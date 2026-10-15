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
	"strings"
	"time"

	"github.com/superfly/macaroon/bundle"
	"github.com/superfly/macaroon/flyio"
)

const maxFlyCredentialBytes = 16 * 1024

type flyClient struct {
	graphqlURL    string
	machinesURL   string
	credentialTTL time.Duration
	httpClient    *http.Client
	now           func() time.Time
}

type preparedCredential struct {
	Token     string
	Subject   string
	ExpiresAt time.Time
}

func (c *flyClient) prepareCredential(ctx context.Context, credential string) (preparedCredential, error) {
	credential = strings.TrimSpace(credential)
	if credential == "" || len(credential) > maxFlyCredentialBytes {
		return preparedCredential{}, errors.New("Fly returned an invalid login credential")
	}
	for _, scheme := range []string{"FlyV1 ", "Bearer "} {
		if strings.HasPrefix(credential, scheme) {
			credential = strings.TrimPrefix(credential, scheme)
			break
		}
	}
	// Keep only the explicitly approved broad login credential, never the
	// returned permission/discharge bundle or multiple OAuth identities.
	token, count := "", 0
	for _, part := range strings.Split(credential, ",") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "fo1_") {
			token = part
			count++
		}
	}
	slog.Info("fly_auth", "stage", "credential_parse", "oauth_count", count)
	if count != 1 || len(token) <= len("fo1_") || strings.ContainsAny(token, " \t\r\n") {
		return preparedCredential{}, errors.New("Fly login must return exactly one valid fo1 credential")
	}
	if err := c.verifyCredential(ctx, token); err != nil {
		return preparedCredential{}, err
	}
	// This is our connection cap, not the opaque fo1 credential's expiry.
	// Refreshing the OAuth wrapper never renews the credential at Fly.
	expiresAt := c.now().UTC().Add(c.credentialTTL)
	return preparedCredential{Token: token, Subject: "fly:" + hashClientID(token), ExpiresAt: expiresAt}, nil
}

func (c *flyClient) verifyCredential(ctx context.Context, credential string) error {
	var data struct {
		Viewer *struct{ ID string }
	}
	if err := c.graphql(ctx, "login_verification", "Bearer "+credential, `query FlyMCPAuthorize { viewer { id } }`, nil, &data); err != nil {
		return err
	}
	if data.Viewer == nil || data.Viewer.ID == "" {
		return errors.New("Fly did not verify the login identity")
	}
	return nil
}

// Prepare management access during browser authorization and refresh, never
// during tool calls. Missing discharges must be completed before issuing access.
func (c *flyClient) managementCredential(ctx context.Context, oauth string) (string, time.Time, error) {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	var orgs []string
	seen := make(map[string]bool)
	var after *string
	for {
		var data struct {
			Organizations *struct {
				Nodes    []struct{ ID string }
				PageInfo struct {
					HasNextPage bool
					EndCursor   string
				}
			}
		}
		err := c.graphql(ctx, "management_organizations", "Bearer "+oauth,
			`query FlyMCPOrganizations($after: String) { organizations(first: 100, after: $after) { nodes { id } pageInfo { hasNextPage endCursor } } }`,
			map[string]any{"after": after}, &data)
		if err != nil {
			return "", time.Time{}, err
		}
		if data.Organizations == nil {
			return "", time.Time{}, errors.New("Fly did not return organizations")
		}
		for _, org := range data.Organizations.Nodes {
			if org.ID == "" {
				return "", time.Time{}, errors.New("Fly returned an invalid organization")
			}
			if !seen[org.ID] {
				orgs = append(orgs, org.ID)
				seen[org.ID] = true
			}
		}
		page := data.Organizations.PageInfo
		if !page.HasNextPage {
			break
		}
		if page.EndCursor == "" || (after != nil && page.EndCursor == *after) {
			return "", time.Time{}, errors.New("Fly returned invalid organization pagination")
		}
		after = &page.EndCursor
	}
	if len(orgs) == 0 {
		return "", time.Time{}, errors.New("Fly account has no organizations for management access")
	}
	// Start the deadline before minting, and leave time for in-flight requests.
	expires := c.now().Add(9 * time.Minute)
	var parts []string
	for _, id := range orgs {
		var data struct {
			CreateLimitedAccessToken *struct {
				LimitedAccessToken *struct{ TokenHeader string }
			}
		}
		err := c.graphql(ctx, "management_mint", "Bearer "+oauth,
			`mutation FlyMCPManagement($organizationId: ID!) { createLimitedAccessToken(input: { name: "Fly MCP gateway", organizationId: $organizationId, profile: "deploy_organization", profileParams: {}, expiry: "10m" }) { limitedAccessToken { tokenHeader } } }`,
			map[string]string{"organizationId": id}, &data)
		if err != nil {
			return "", time.Time{}, err
		}
		if data.CreateLimitedAccessToken == nil || data.CreateLimitedAccessToken.LimitedAccessToken == nil {
			return "", time.Time{}, errors.New("Fly did not return a management token")
		}
		header := strings.TrimSpace(data.CreateLimitedAccessToken.LimitedAccessToken.TokenHeader)
		header = strings.TrimPrefix(header, "FlyV1 ")
		for _, part := range strings.Split(header, ",") {
			part = strings.TrimSpace(part)
			if !strings.HasPrefix(part, "fm2_") || len(part) <= 4 || strings.ContainsAny(part, " \t\r\n") {
				return "", time.Time{}, errors.New("Fly returned an invalid management token")
			}
			parts = append(parts, part)
		}
	}
	// Include OAuth for user-level GraphQL queries. The native Machines client
	// selects only the management macaroons from this bundle.
	bundle := "FlyV1 " + strings.Join(append(parts, oauth), ",")
	if len(bundle) > maxFlyCredentialBytes {
		return "", time.Time{}, errors.New("Fly management credential bundle is too large")
	}
	logManagementStructure(bundle)
	grant := managementGrant{Token: bundle, ExpiresAt: expires.Unix()}
	if err := c.completeManagement(ctx, &grant); err != nil {
		return "", time.Time{}, err
	}
	if !expires.After(c.now()) {
		return "", time.Time{}, errors.New("Fly management tokens expired during acquisition")
	}
	return grant.Token, time.Unix(grant.ExpiresAt, 0), nil
}

// Inspect structure only, without verifying signatures or fetching discharges.
// Never log parser errors: they may contain token material. Keep orphan
// discharges in the count so they cannot look like matching credentials.
func logManagementStructure(header string) {
	parsed, err := flyio.ParseBundleWithFilter(header, bundle.KeepAll)
	if err != nil {
		slog.Info("fly_auth", "stage", "management_structure", "parsed", false)
		return
	}
	missing := 0
	for _, tickets := range parsed.UndischargedThirdPartyTickets() {
		missing += len(tickets)
	}
	slog.Info("fly_auth", "stage", "management_structure", "parsed", true,
		"permission_count", parsed.Count(flyio.IsPermissionToken),
		"discharge_count", parsed.Count(bundle.And(bundle.IsWellFormedMacaroon, bundle.Not(flyio.IsPermissionToken))),
		"missing_ticket_count", missing)
}

func (c *flyClient) graphql(ctx context.Context, stage, authorization, query string, variables any, out any) (resultErr error) {
	status, decoded := 0, false
	defer func() {
		slog.Info("fly_auth", "stage", stage, "status", status, "decoded", decoded, "accepted", resultErr == nil)
	}()
	body, err := json.Marshal(map[string]any{"query": query, "variables": variables})
	if err != nil {
		return errors.New("could not encode Fly request")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.graphqlURL, bytes.NewReader(body))
	if err != nil {
		return errors.New("could not create Fly credential check")
	}
	req.Header.Set("Authorization", authorization)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "fly-mcp-gateway")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return errors.New("credential could not be verified by Fly; try again")
	}
	defer resp.Body.Close()
	status = resp.StatusCode
	if status != http.StatusOK {
		return fmt.Errorf("Fly credential verification failed (HTTP %d)", status)
	}
	responseBody, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if err != nil || len(responseBody) > 1<<20 {
		return errors.New("invalid Fly credential verification response")
	}
	var result struct {
		Data   json.RawMessage   `json:"data"`
		Errors []json.RawMessage `json:"errors"`
	}
	if json.Unmarshal(responseBody, &result) != nil {
		return errors.New("Fly credential verification returned an invalid response")
	}
	decoded = true
	logGraphQLDiagnostics(stage, result.Errors)
	if len(result.Errors) > 0 {
		return errors.New("Fly rejected credential verification (GraphQL error)")
	}
	if len(result.Data) == 0 || string(result.Data) == "null" || json.Unmarshal(result.Data, out) != nil {
		return errors.New("Fly returned invalid response data")
	}
	return nil
}
