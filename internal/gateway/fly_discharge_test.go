package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/superfly/macaroon"
	"github.com/superfly/macaroon/flyio"
	"github.com/superfly/macaroon/tp"
)

type dischargeRoundTrip func(*http.Request) (*http.Response, error)

func (f dischargeRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type dischargeFixture struct {
	oauth, issuer, permission, discharge string
	key                                  macaroon.SigningKey
	ticket                               []byte
	createdAt                            time.Time
	approved                             atomic.Bool
	mints, checks, requests              atomic.Int64
	mode                                 string
}

func newDischargeFixture(t *testing.T, oauth, issuer string) *dischargeFixture {
	t.Helper()
	createdAt := time.Now().Truncate(time.Second)
	key, encryption := macaroon.NewSigningKey(), macaroon.NewEncryptionKey()
	permission, err := macaroon.New([]byte("fixture-key"), flyio.LocationPermission, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := permission.Add3P(encryption, issuer); err != nil {
		t.Fatal(err)
	}
	ticket := permission.TicketsForThirdParty(issuer)[0]
	_, discharge, err := macaroon.DischargeTicket(encryption, issuer, ticket)
	if err != nil {
		t.Fatal(err)
	}
	if err := discharge.Add(&macaroon.ValidityWindow{NotAfter: createdAt.Add(10 * time.Minute).Unix()}); err != nil {
		t.Fatal(err)
	}
	if err := discharge.BindToParentMacaroon(permission); err != nil {
		t.Fatal(err)
	}
	p, err := permission.String()
	if err != nil {
		t.Fatal(err)
	}
	d, err := discharge.String()
	if err != nil {
		t.Fatal(err)
	}
	return &dischargeFixture{oauth: oauth, issuer: issuer, permission: p, discharge: d, key: key, ticket: ticket, createdAt: createdAt, mode: "interactive"}
}

func (f *dischargeFixture) verifies(header string) bool {
	p, ds, err := flyio.ParsePermissionAndDischargeTokens(header)
	if err != nil {
		return false
	}
	m, err := macaroon.Decode(p)
	if err != nil {
		return false
	}
	_, err = m.Verify(f.key, ds, nil)
	return err == nil
}

func (f *dischargeFixture) api(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			if !f.verifies(r.Header.Get("Authorization")) || strings.Contains(r.Header.Get("Authorization"), "fo1_") {
				w.WriteHeader(403)
				return
			}
			_, _ = io.WriteString(w, `[{"id":"approved-machine","name":"fixture","state":"started","region":"iad"}]`)
			return
		}
		var body struct{ Query string }
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			w.WriteHeader(400)
			return
		}
		if strings.Contains(body.Query, "FlyMCPManagementCheck") {
			f.checks.Add(1)
			if !f.verifies(r.Header.Get("Authorization")) {
				_, _ = io.WriteString(w, `{"errors":[{"message":"missing or invalid discharge"}]}`)
				return
			}
			_, _ = io.WriteString(w, `{"data":{"apps":{"nodes":[{"id":"fixture-app"}]}}}`)
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+f.oauth {
			t.Error("identity/discovery/mint did not use the caller's fo1")
			w.WriteHeader(401)
			return
		}
		switch {
		case strings.Contains(body.Query, "FlyMCPOrganizations"):
			_, _ = io.WriteString(w, `{"data":{"organizations":{"nodes":[{"id":"A"}],"pageInfo":{"hasNextPage":false}}}}`)
		case strings.Contains(body.Query, "mutation FlyMCPManagement"):
			f.mints.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"createLimitedAccessToken": map[string]any{"limitedAccessToken": map[string]string{"tokenHeader": "FlyV1 " + f.permission}}}})
		default:
			_, _ = io.WriteString(w, `{"data":{"viewer":{"id":"fixture-user"}}}`)
		}
	})
}

func (f *dischargeFixture) transport(t *testing.T, apiURL string) http.RoundTripper {
	api, _ := url.Parse(apiURL)
	return dischargeRoundTrip(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host == api.Host {
			return http.DefaultTransport.RoundTrip(r)
		}
		f.requests.Add(1)
		if r.URL.Scheme != "https" || r.URL.Host != "auth.fly.io" || r.Header.Get("Authorization") != "Bearer "+f.oauth {
			t.Error("unexpected destination or forwarded credential")
			return nil, errors.New("blocked unexpected destination")
		}
		w := httptest.NewRecorder()
		if f.mode == "redirect" {
			w.Header().Set("Location", "https://credential-canary.invalid/")
			w.WriteHeader(302)
		} else if f.mode == "failure" {
			w.WriteHeader(502)
			_, _ = io.WriteString(w, f.oauth)
		} else if r.Method == http.MethodPost && r.URL.Path == tp.InitPath {
			var request struct{ Ticket []byte }
			if json.NewDecoder(r.Body).Decode(&request) != nil || !bytes.Equal(request.Ticket, f.ticket) {
				t.Error("init did not send the missing ticket")
			}
			if f.mode == "automatic" {
				_ = json.NewEncoder(w).Encode(map[string]string{"discharge": f.discharge})
			} else {
				pollURL, userURL := "https://auth.fly.io"+tp.PollPathPrefix+"fixture", "https://auth.fly.io/approve?fixture=private-canary"
				switch f.mode {
				case "foreign_poll":
					pollURL = "https://credential-canary.invalid" + tp.PollPathPrefix + "fixture"
				case "traversal_poll":
					pollURL = "https://auth.fly.io" + tp.PollPathPrefix + "../other"
				case "foreign_user":
					userURL = "https://credential-canary.invalid/approve"
				}
				w.WriteHeader(201)
				_ = json.NewEncoder(w).Encode(map[string]any{"user_interactive": map[string]string{
					"poll_url": pollURL, "user_url": userURL,
				}})
			}
		} else if r.Method == http.MethodGet && r.URL.Path == tp.PollPathPrefix+"fixture" {
			if !f.approved.Load() {
				w.WriteHeader(202)
			} else {
				_ = json.NewEncoder(w).Encode(map[string]string{"discharge": f.discharge})
			}
		} else {
			t.Error("unexpected discharge protocol operation")
			w.WriteHeader(404)
		}
		return w.Result(), nil
	})
}

func TestManagementDischargeAutomaticAndFailures(t *testing.T) {
	for _, mode := range []string{"automatic", "interactive", "failure", "redirect", "wrong_ticket", "permission_injection", "unsupported", "foreign_poll", "traversal_poll", "foreign_user"} {
		t.Run(mode, func(t *testing.T) {
			issuer := flyio.LocationNewAuthentication
			if mode == "unsupported" {
				issuer = "http://127.0.0.1:4280"
			}
			f := newDischargeFixture(t, "fo1_test-canary", issuer)
			f.mode = mode
			if mode == "wrong_ticket" {
				f.mode = "automatic"
				f.discharge = newDischargeFixture(t, f.oauth, issuer).discharge
			}
			if mode == "permission_injection" {
				f.mode, f.discharge = "automatic", f.permission
			}
			api := httptest.NewServer(f.api(t))
			defer api.Close()
			h := testHandler(t, api.URL, api.URL)
			h.oauth.fly.httpClient.Transport = f.transport(t, api.URL)
			got, _, err := h.oauth.fly.managementCredential(context.Background(), f.oauth)
			if mode == "automatic" {
				if err != nil || !f.verifies(got) || !strings.HasPrefix(got, "FlyV1 "+f.permission+","+f.oauth+",") || f.checks.Load() != 1 {
					t.Fatalf("automatic discharge failed: %v", err)
				}
			} else if err == nil || got != "" || f.checks.Load() != 0 || strings.Contains(err.Error(), f.oauth) {
				t.Fatal("incomplete acquisition returned access, verified prematurely, or leaked a credential")
			}
			var pending *managementPending
			if errors.As(err, &pending) != (mode == "interactive") {
				t.Fatal("unsafe response offered browser continuation, or valid approval was lost")
			}
			if mode == "unsupported" && f.requests.Load() != 0 {
				t.Fatal("unsupported issuer was contacted")
			}
			if mode == "redirect" && f.requests.Load() != 1 {
				t.Fatal("followed a discharge redirect")
			}
		})
	}
}

func TestManagementApprovalBeforeAuthorizationCodeAndRefreshFailure(t *testing.T) {
	f := newDischargeFixture(t, "fo1_approval-fixture", flyio.LocationNewAuthentication)
	resources := f.api(t)
	loginAPI := flyLoginFixture(t, f.oauth, resources)
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v1/apps/") {
			resources.ServeHTTP(w, r)
		} else {
			loginAPI.ServeHTTP(w, r)
		}
	}))
	defer api.Close()
	h := testHandler(t, api.URL, api.URL)
	h.oauth.fly.httpClient.Transport = f.transport(t, api.URL)
	now := f.createdAt
	h.oauth.now = func() time.Time { return now }
	h.oauth.fly.now = h.oauth.now
	clientID := registerClient(t, h, "https://client.example/oauth/callback")
	verifier := strings.Repeat("v", 64)
	digest := sha256.Sum256([]byte(verifier))
	start := performRequest(h, "GET", "/authorize?"+url.Values{
		"client_id": {clientID}, "redirect_uri": {"https://client.example/oauth/callback"}, "response_type": {"code"},
		"code_challenge_method": {"S256"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(digest[:])},
	}.Encode(), "", "")
	cookie := start.Result().Cookies()[0]
	pending := postLogin(h, cookie, url.Values{"request": {authorizationForm(t, start)}, "completion_code": {"fixture-completion"}})
	if pending.Code != 200 || !strings.Contains(pending.Body.String(), "Check approval") || pending.Header().Get("Location") != "" || f.checks.Load() != 0 {
		t.Fatal("redirected to the client or verified before required approval")
	}
	form := url.Values{"request": {authorizationForm(t, pending)}}
	if postLogin(h, nil, form).Code != 400 {
		t.Fatal("approval continuation accepted without browser binding")
	}
	stillPending := postLogin(h, cookie, form)
	if stillPending.Code != 200 || postLogin(h, cookie, form).Code != 400 {
		t.Fatal("pending approval did not rotate one-time browser state")
	}
	if strings.Contains(stillPending.Body.String(), f.oauth) || strings.Contains(stillPending.Body.String(), f.permission) {
		t.Fatal("pending page leaked credential material")
	}
	// Expiry rejects before contacting the issuer or consuming the continuation.
	mintedAt := now
	now = mintedAt.Add(9 * time.Minute)
	requests := f.requests.Load()
	expired := postLogin(h, cookie, url.Values{"request": {authorizationForm(t, stillPending)}})
	if expired.Code != 400 || !strings.Contains(expired.Body.String(), "expired") || f.requests.Load() != requests {
		t.Fatal("expired approval continuation contacted Fly or stayed usable")
	}
	now = mintedAt
	now = now.Add(2 * time.Minute)
	f.approved.Store(true)
	finish := postLogin(h, cookie, url.Values{"request": {authorizationForm(t, stillPending)}})
	if finish.Code != 302 {
		t.Fatalf("approved continuation failed: HTTP %d", finish.Code)
	}
	redirect, _ := url.Parse(finish.Header().Get("Location"))
	exchange := exchangeCode(h, clientID, redirect.Query().Get("code"), verifier)
	var tokens struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
	}
	if json.Unmarshal(exchange.Body.Bytes(), &tokens) != nil || exchange.Code != 200 || tokens.ExpiresIn != 420 || f.mints.Load() != 1 {
		t.Fatal("exchange reminted an unapproved bundle or reset its original deadline")
	}
	endpoint := httptest.NewServer(h)
	defer endpoint.Close()
	result := mcpRPC(t, endpoint.URL, tokens.AccessToken, "tools/call", map[string]any{"name": "fly-machine-list", "arguments": map[string]string{"app": "fixture"}})
	if result.Error != nil || result.Result.IsError || len(result.Result.Content) != 1 || !strings.Contains(result.Result.Content[0].Text, "approved-machine") {
		t.Fatal("approved bundle did not authorize an actual MCP call")
	}
	refresh := performRequest(h, "POST", "/token", url.Values{"grant_type": {"refresh_token"}, "client_id": {clientID}, "refresh_token": {tokens.RefreshToken}}.Encode(), "application/x-www-form-urlencoded")
	if refresh.Code != 400 || strings.Contains(refresh.Body.String(), "access_token") {
		t.Fatal("interactive refresh requirement issued unusable tokens")
	}
	if _, err := h.oauth.verifyBearer("Bearer " + tokens.AccessToken); err == nil {
		t.Fatal("failed interactive refresh did not revoke old access")
	}
}

func TestManagementDischargeShortensAccessDeadline(t *testing.T) {
	f := newDischargeFixture(t, "fo1_expiry-fixture", flyio.LocationNewAuthentication)
	f.mode = "automatic"
	api := httptest.NewServer(f.api(t))
	defer api.Close()
	h := testHandler(t, api.URL, api.URL)
	h.oauth.fly.httpClient.Transport = f.transport(t, api.URL)
	now := f.createdAt.Add(8 * time.Minute)
	h.oauth.fly.now = func() time.Time { return now }
	token, expires, err := h.oauth.fly.managementCredential(context.Background(), f.oauth)
	// The discharge has two minutes left, not the requested ten. Reserve one
	// minute for in-flight calls rather than issuing another nine-minute wrapper.
	if err != nil || token == "" || expires.Unix() != f.createdAt.Add(9*time.Minute).Unix() {
		t.Fatalf("ignored shorter discharge lifetime: %v", err)
	}
	now = expires
	checks := f.checks.Load()
	if err := h.oauth.fly.completeManagement(context.Background(), &managementGrant{Token: token, ExpiresAt: expires.Unix()}); err == nil || f.checks.Load() != checks {
		t.Fatal("accepted access at the shortened deadline")
	}
}
