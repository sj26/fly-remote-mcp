package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/superfly/macaroon"
	"github.com/superfly/macaroon/flyio"
)

// Wire-valid but unsigned permissions for the local API fixture only. Actual
// signature and third-party ticket checks use signed fixtures in discharge tests.
func managementToken(t *testing.T, id string, generation int64) string {
	t.Helper()
	m := &macaroon.Macaroon{Location: flyio.LocationPermission}
	m.Nonce.KID = []byte(fmt.Sprintf("%s%d", id, generation))
	token, err := m.String()
	if err != nil {
		t.Fatal(err)
	}
	return token
}

// Two pages protect against silently omitting permissions after the first page.
// Distinct generations detect refresh accidentally reusing management tokens.
func managementFixture(t *testing.T, oauth string, fallback http.Handler) http.Handler {
	t.Helper()
	var generation atomic.Int64
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var request struct {
			Query     string
			Variables map[string]any
		}
		if json.Unmarshal(body, &request) != nil {
			t.Error("invalid GraphQL request")
			w.WriteHeader(400)
			return
		}
		if !strings.Contains(request.Query, "FlyMCPOrganizations") && !strings.Contains(request.Query, "FlyMCPManagement") {
			r.Body = io.NopCloser(bytes.NewReader(body))
			fallback.ServeHTTP(w, r)
			return
		}
		if strings.Contains(request.Query, "FlyMCPManagementCheck") {
			n := generation.Load()
			want := "FlyV1 " + managementToken(t, "A", n-1) + "," + managementToken(t, "B", n) + "," + oauth
			if r.Header.Get("Authorization") != want {
				t.Error("management verification used incomplete or stale permissions")
				w.WriteHeader(401)
				return
			}
			_, _ = io.WriteString(w, `{"data":{"apps":{"nodes":[]}}}`)
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+oauth {
			t.Error("discovery/mint did not use only fo1")
			w.WriteHeader(401)
			return
		}
		if strings.Contains(request.Query, "FlyMCPOrganizations") {
			if request.Variables["after"] == nil {
				_, _ = io.WriteString(w, `{"data":{"organizations":{"nodes":[{"id":"A"}],"pageInfo":{"hasNextPage":true,"endCursor":"second"}}}}`)
			} else if request.Variables["after"] == "second" {
				_, _ = io.WriteString(w, `{"data":{"organizations":{"nodes":[{"id":"B"}],"pageInfo":{"hasNextPage":false}}}}`)
			} else {
				t.Error("unexpected page cursor")
				w.WriteHeader(400)
			}
			return
		}
		if !strings.Contains(request.Query, `profile: "deploy_organization"`) || !strings.Contains(request.Query, `expiry: "10m"`) || strings.Contains(request.Query, "optOut") {
			t.Error("wrong management profile, expiry or policy override")
		}
		id := request.Variables["organizationId"]
		if id != "A" && id != "B" {
			t.Error("minted outside discovered memberships")
			w.WriteHeader(400)
			return
		}
		n := generation.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"createLimitedAccessToken": map[string]any{"limitedAccessToken": map[string]string{"tokenHeader": "FlyV1 " + managementToken(t, id.(string), n)}}}})
	})
}

func TestManagementAcquisitionFailsClosed(t *testing.T) {
	const canary = "fo1_private-canary"
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	for _, stage := range []string{"organizations", "second_mint", "verification", "malformed_token", "empty_orgs"} {
		t.Run(stage, func(t *testing.T) {
			fixture := managementFixture(t, canary, http.NotFoundHandler())
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				var request struct {
					Query     string
					Variables map[string]any
				}
				_ = json.Unmarshal(body, &request)
				switch {
				case stage == "organizations" && strings.Contains(request.Query, "FlyMCPOrganizations"),
					stage == "second_mint" && request.Variables["organizationId"] == "B",
					stage == "verification" && strings.Contains(request.Query, "FlyMCPManagementCheck"):
					_, _ = io.WriteString(w, `{"errors":[{"message":"permission denied `+canary+`"}]}`)
				case stage == "malformed_token" && request.Variables["organizationId"] == "A":
					_, _ = io.WriteString(w, `{"data":{"createLimitedAccessToken":{"limitedAccessToken":{"tokenHeader":"`+canary+`"}}}}`)
				case stage == "empty_orgs":
					_, _ = io.WriteString(w, `{"data":{"organizations":{"nodes":[],"pageInfo":{"hasNextPage":false}}}}`)
				default:
					r.Body = io.NopCloser(bytes.NewReader(body))
					fixture.ServeHTTP(w, r)
				}
			}))
			defer api.Close()
			h := testHandler(t, api.URL, api.URL)
			w := httptest.NewRecorder()
			h.oauth.issueTokens(context.Background(), w, "client", "mcp", h.oauth.resourceURL, canary, "subject", time.Now().Add(time.Hour).Unix(), "", nil)
			if w.Code != 400 || strings.Contains(w.Body.String(), "access_token") || strings.Contains(w.Body.String(), canary) || strings.Contains(logs.String(), canary) {
				t.Fatal("failed acquisition issued tokens or leaked upstream details")
			}
		})
	}
}

func TestFailedManagementRefreshRevokesConnection(t *testing.T) {
	const oauth = "fo1_refresh-fixture"
	var rejected atomic.Bool
	fixture := managementFixture(t, oauth, http.NotFoundHandler())
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if rejected.Load() {
			w.WriteHeader(401)
			return
		}
		fixture.ServeHTTP(w, r)
	}))
	defer api.Close()
	h := testHandler(t, api.URL, api.URL)
	w := httptest.NewRecorder()
	h.oauth.issueTokens(context.Background(), w, hashClientID("client"), "mcp", h.oauth.resourceURL, oauth, "subject", time.Now().Add(time.Hour).Unix(), "", nil)
	var tokens struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &tokens) != nil {
		t.Fatal("initial acquisition failed")
	}
	rejected.Store(true)
	response := performRequest(h, "POST", "/token", url.Values{"grant_type": {"refresh_token"}, "client_id": {"client"}, "refresh_token": {tokens.RefreshToken}}.Encode(), "application/x-www-form-urlencoded")
	if response.Code != 400 {
		t.Fatal("failed renewal returned access")
	}
	if _, err := h.oauth.verifyBearer("Bearer " + tokens.AccessToken); err == nil {
		t.Fatal("failed renewal retained old authority")
	}
}

func TestManagementStructureMatchesTicketsWithoutLeakingMaterial(t *testing.T) {
	const issuer = "https://issuer-canary.invalid/private-location"
	key := macaroon.NewEncryptionKey()
	var permissions, discharges []*macaroon.Macaroon
	// Two included parents use different tickets at the same issuer. The third
	// parent is excluded, making its discharge an orphan despite its issuer.
	for range 3 {
		permission, err := macaroon.New([]byte("key-canary"), flyio.LocationPermission, macaroon.NewSigningKey())
		if err != nil {
			t.Fatal(err)
		}
		if err := permission.Add3P(key, issuer); err != nil {
			t.Fatal(err)
		}
		_, discharge, err := macaroon.DischargeTicket(key, issuer, permission.TicketsForThirdParty(issuer)[0])
		if err != nil {
			t.Fatal(err)
		}
		permissions = append(permissions, permission)
		discharges = append(discharges, discharge)
	}
	header := func(ms ...*macaroon.Macaroon) string {
		var parts []string
		for _, m := range append(append([]*macaroon.Macaroon{}, permissions[:2]...), ms...) {
			part, err := m.String()
			if err != nil {
				t.Fatal(err)
			}
			parts = append(parts, part)
		}
		return "FlyV1 " + strings.Join(parts, ",") + ",fo1_private-canary"
	}
	previous := slog.Default()
	t.Cleanup(func() { slog.SetDefault(previous) })
	for _, tc := range []struct {
		name, header        string
		discharges, missing int
	}{
		{"missing", header(), 0, 2},
		{"orphan", header(discharges[2]), 1, 2},
		{"partial", header(discharges[2], discharges[0]), 2, 1},
		{"complete", header(discharges[2], discharges[0], discharges[1]), 3, 0},
		{"malformed", "FlyV1 fm2_private-canary", 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var logs bytes.Buffer
			slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
			logManagementStructure(tc.header)
			var record map[string]any
			if err := json.Unmarshal(logs.Bytes(), &record); err != nil {
				t.Fatal(err)
			}
			if record["stage"] != "management_structure" || record["parsed"] != (tc.name != "malformed") {
				t.Fatalf("incorrect parse outcome: %v", record)
			}
			if tc.name == "malformed" {
				if _, exists := record["missing_ticket_count"]; exists {
					t.Fatal("parse failure reported a misleading ticket count")
				}
			} else if record["permission_count"] != float64(2) || record["discharge_count"] != float64(tc.discharges) || record["missing_ticket_count"] != float64(tc.missing) {
				t.Fatalf("incorrect structural counts: %v", record)
			}
			for _, forbidden := range []string{issuer, "private-canary", "fm2_", "fo1_", tc.header} {
				if strings.Contains(logs.String(), forbidden) {
					t.Fatal("management diagnostics leaked credential material")
				}
			}
		})
	}
}
