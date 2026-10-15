package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/superfly/macaroon"
	"github.com/superfly/macaroon/bundle"
	"github.com/superfly/macaroon/flyio"
	"github.com/superfly/macaroon/tp"
)

// Sealed only in browser-bound continuation state and the one-time authorization code.
// No service-side credential storage is introduced.
type managementGrant struct {
	Token     string             `json:"token"`
	ExpiresAt int64              `json:"exp"`
	Approval  *dischargeApproval `json:"approval,omitempty"`
}

type dischargeApproval struct {
	Issuer  string `json:"issuer"`
	Ticket  []byte `json:"ticket"`
	PollURL string `json:"poll_url"`
	UserURL string `json:"user_url,omitempty"`
}

type managementPending struct{ Grant managementGrant }

func (*managementPending) Error() string { return "Fly management access requires browser approval" }

// This implements the init/poll protocol from macaroon/tp, with one browser
// continuation at a time instead of a CLI callback or background browser.
func (c *flyClient) completeManagement(ctx context.Context, grant *managementGrant) error {
	for attempt := 0; attempt < 32; attempt++ {
		if grant.ExpiresAt <= c.now().Unix() {
			return errors.New("Fly management tokens expired; reconnect your MCP client")
		}
		if len(grant.Token) > maxFlyCredentialBytes {
			return errors.New("Fly management credential bundle is too large")
		}
		parsed, err := flyio.ParseBundle(grant.Token)
		if err != nil || parsed.Count(flyio.IsPermissionToken) == 0 {
			return errors.New("Fly returned an invalid management bundle")
		}
		// Unverified expiry can only shorten our deadline, never establish
		// authorization. Leave a minute for requests still in flight.
		bundle.ForEach(parsed, func(m bundle.Macaroon) {
			grant.ExpiresAt = min(grant.ExpiresAt, m.UnsafeMacaroon().Expiration().Unix()-60)
		})
		if grant.ExpiresAt <= c.now().Unix() {
			return errors.New("Fly management credentials expire too soon; reconnect your MCP client")
		}
		missing := parsed.UndischargedThirdPartyTickets()
		if len(missing) == 0 {
			grant.Approval = nil
			var data struct {
				Apps *struct{ Nodes []struct{ ID string } }
			}
			if err := c.graphql(ctx, "management_verification", grant.Token,
				`query FlyMCPManagementCheck { apps(first: 1) { nodes { id } } }`, nil, &data); err != nil {
				return err
			}
			if data.Apps == nil {
				return errors.New("Fly did not verify management access")
			}
			if grant.ExpiresAt <= c.now().Unix() {
				return errors.New("Fly management credentials expired during verification")
			}
			logManagementStructure(grant.Token)
			return nil
		}
		approval := grant.Approval
		if approval == nil {
			for issuer, tickets := range missing {
				approval = &dischargeApproval{Issuer: issuer, Ticket: tickets[0]}
				break
			}
		}
		if approval.Issuer != flyio.LocationNewAuthentication && approval.Issuer != flyio.LocationAuthentication {
			slog.Info("fly_auth", "stage", "management_discharge", "accepted", false, "reason", "unsupported_issuer")
			return errors.New("Fly requires an unsupported management discharge issuer")
		}
		_, _, oauth, err := flyHeaders(grant.Token)
		if err != nil {
			return err
		}
		method, endpoint := http.MethodGet, approval.PollURL
		var body io.Reader
		if endpoint == "" {
			method, endpoint = http.MethodPost, approval.Issuer+tp.InitPath
			encoded, _ := json.Marshal(struct {
				Ticket []byte `json:"ticket"`
			}{approval.Ticket})
			body = bytes.NewReader(encoded)
		} else if !validDischargePoll(approval.Issuer, endpoint) {
			return errors.New("Fly returned an invalid discharge poll URL")
		}
		req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
		if err != nil {
			return errors.New("Could not create Fly discharge request")
		}
		req.Header.Set("Authorization", oauth)
		req.Header.Set("Content-Type", "application/json")
		resp, err := c.httpClient.Do(req)
		if err != nil {
			return errors.New("Fly management discharge request failed")
		}
		responseBody, readErr := io.ReadAll(io.LimitReader(resp.Body, (64<<10)+1))
		resp.Body.Close()
		slog.Info("fly_auth", "stage", "management_discharge", "method", method, "status", resp.StatusCode)
		if readErr != nil || len(responseBody) > 64<<10 {
			return errors.New("Invalid Fly management discharge response")
		}
		if resp.StatusCode == http.StatusAccepted && method == http.MethodGet {
			grant.Approval = approval
			return &managementPending{Grant: *grant}
		}
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
			return fmt.Errorf("Fly management discharge request failed (HTTP %d)", resp.StatusCode)
		}
		var result struct {
			Error           string `json:"error"`
			Discharge       string `json:"discharge"`
			PollURL         string `json:"poll_url"`
			UserInteractive *struct {
				PollURL string `json:"poll_url"`
				UserURL string `json:"user_url"`
			} `json:"user_interactive"`
		}
		if json.Unmarshal(responseBody, &result) != nil || result.Error != "" {
			return errors.New("Fly rejected management discharge acquisition")
		}
		if result.Discharge != "" {
			// Preserve the minted permissions and fo1 byte-for-byte. A discharge
			// endpoint must not add a permission token or another user identity.
			raw, err := macaroon.Parse(result.Discharge)
			if err != nil || len(raw) != 1 || strings.Contains(result.Discharge, "fo1_") {
				return errors.New("Fly returned an invalid management discharge")
			}
			discharge, err := macaroon.Decode(raw[0])
			if err != nil || discharge.Location != approval.Issuer || !bytes.Equal(discharge.Nonce.KID, approval.Ticket) {
				return errors.New("Fly returned a discharge for a different ticket")
			}
			grant.Token += "," + strings.TrimPrefix(macaroon.ToAuthorizationHeader(raw...), "FlyV1 ")
			grant.Approval = nil
			continue
		}
		approval.PollURL = result.PollURL
		if result.UserInteractive != nil {
			approval.PollURL = result.UserInteractive.PollURL
			approval.UserURL = result.UserInteractive.UserURL
			if !validDischargeBrowserURL(approval.UserURL) {
				return errors.New("Fly returned an invalid management approval URL")
			}
		}
		if !validDischargePoll(approval.Issuer, approval.PollURL) {
			return errors.New("Fly returned an invalid discharge poll URL")
		}
		grant.Approval = approval
		return &managementPending{Grant: *grant}
	}
	return errors.New("Fly management discharge acquisition exceeded its limit")
}

func validDischargePoll(issuer, raw string) bool {
	u, err := url.Parse(raw)
	base, _ := url.Parse(issuer)
	return err == nil && u.Scheme == "https" && u.Host == base.Host && u.User == nil && u.Fragment == "" && u.RawPath == "" && path.Clean(u.Path) == u.Path && strings.HasPrefix(u.Path, base.Path+tp.PollPathPrefix)
}

func validDischargeBrowserURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.User == nil && u.Fragment == "" && (u.Host == "auth.fly.io" || u.Host == "api.fly.io" || u.Host == "fly.io")
}
