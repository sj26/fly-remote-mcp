package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"
)

func flyLoginFixture(t *testing.T, credential string, verify http.Handler) http.Handler {
	t.Helper()
	var challenge string
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/graphql" {
			verify.ServeHTTP(w, r)
			return
		}
		if r.Header.Get("Authorization") != "" {
			t.Error("login creation/redemption carried an ambient credential")
		}
		var raw map[string]json.RawMessage
		if json.NewDecoder(r.Body).Decode(&raw) != nil {
			t.Error("invalid request body")
			w.WriteHeader(400)
			return
		}
		switch r.URL.Path {
		case "/api/v1/cli_sessions":
			if _, exists := raw["metadata"]; exists {
				t.Error("login unexpectedly requested an organization lock")
			}
			if _, exists := raw["redirect_port"]; exists {
				t.Error("manual login supplied a callback port")
			}
			if _, exists := raw["code_verifier"]; exists {
				t.Error("creation leaked verifier")
			}
			_ = json.Unmarshal(raw["code_challenge"], &challenge)
			var method string
			_ = json.Unmarshal(raw["code_challenge_method"], &method)
			if !validCodeChallenge(challenge) || method != "S256" {
				t.Error("missing Fly PKCE")
			}
			w.WriteHeader(201)
			_, _ = io.WriteString(w, `{"id":"fixture-session","pkce":true,"auth_url":"https://fly.io/fixture-approval"}`)
		case "/api/v1/cli_sessions/fixture-session/redeem":
			var code, verifier string
			_ = json.Unmarshal(raw["code"], &code)
			_ = json.Unmarshal(raw["code_verifier"], &verifier)
			if code != "fixture-completion" || !pkceMatches(verifier, challenge) {
				w.WriteHeader(400)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "FlyV1 fm2_discarded, \t" + credential + ",fm2_also-discarded"})
		default:
			t.Error("unexpected Fly request: no mint or discharge requests are allowed")
			w.WriteHeader(404)
		}
	})
}

func authorizationForm(t *testing.T, response *httptest.ResponseRecorder) string {
	t.Helper()
	match := regexp.MustCompile(`name="request" value="([^"]+)"`).FindStringSubmatch(response.Body.String())
	if len(match) != 2 {
		t.Fatalf("missing authorization form: %s", response.Body.String())
	}
	return match[1]
}

func postLogin(handler *Handler, cookie *http.Cookie, form url.Values) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/authorize", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", handler.oauth.baseURL)
	if cookie != nil {
		r.AddCookie(cookie)
	}
	return performRecorderRequest(handler, r)
}

func TestFlyLoginRejectsUnsafeCreation(t *testing.T) {
	for _, response := range []string{
		`{"id":"test","pkce":false,"auth_url":"https://fly.io/approve"}`,
		`{"id":"test","pkce":true,"auth_url":"https://fly.io.attacker.example/approve"}`,
	} {
		t.Run(response, func(t *testing.T) {
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(201); _, _ = io.WriteString(w, response) }))
			defer api.Close()
			h := testHandler(t, api.URL, api.URL)
			if _, _, _, err := h.oauth.fly.startLogin(context.Background()); err == nil {
				t.Fatal("accepted unsafe Fly session")
			}
		})
	}
}

func TestLoginSelectsOnlyOneOAuthCredential(t *testing.T) {
	const token = "fo1_SENSITIVE-canary"
	now := time.Unix(1800000000, 0)
	for _, tc := range []struct {
		name, bundle string
		accepted     bool
	}{
		{"oauth", token, true},
		{"bearer", "Bearer " + token, true},
		{"first", "FlyV1 " + token + ",fm2_ignored", true},
		{"last", "FlyV1 fm2_ignored, \t" + token, true},
		{"missing", "FlyV1 fm2_ignored", false},
		{"duplicate", token + "," + token, false},
		{"multiple", token + ",fo1_other", false},
		{"empty", "fo1_", false},
		{"header_injection", token + "\r\nX-Test: bad", false},
		{"oversize", "fo1_" + strings.Repeat("x", maxFlyCredentialBytes), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.URL.Path != "/graphql" || r.Header.Get("Authorization") != "Bearer "+token {
					t.Error("wrong credential or unexpected acquisition request")
				}
				_, _ = io.WriteString(w, `{"data":{"viewer":{"id":"user-outside-org"}}}`)
			}))
			defer api.Close()
			h := testHandler(t, api.URL, api.URL)
			h.oauth.fly.now = func() time.Time { return now }
			got, err := h.oauth.fly.prepareCredential(context.Background(), tc.bundle)
			if tc.accepted {
				if err != nil || got.Token != token || calls != 1 || !got.ExpiresAt.Equal(now.Add(30*24*time.Hour)) {
					t.Fatal("did not select, verify and cap only the fo1 credential")
				}
			} else if err == nil || got.Token != "" || calls != 0 || strings.Contains(err.Error(), token) {
				t.Fatal("invalid/ambiguous bundle accepted, transmitted, or exposed")
			}
		})
	}
}

func TestFlyVerificationFailsClosedWithoutLeakingSecrets(t *testing.T) {
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	const secret = "fo1_SENSITIVE-response-canary"
	for _, tc := range []struct {
		name, body string
		status     int
		accepted   bool
	}{
		{"success", `{"data":{"viewer":{"id":"` + secret + `"}}}`, 200, true},
		{"graphql", `{"data":{"viewer":{"id":"user"}},"errors":[{"message":"authentication ` + secret + `"}]}`, 200, false},
		{"missing_viewer", `{"data":{"viewer":null}}`, 200, false},
		{"empty_identity", `{"data":{"viewer":{"id":""}}}`, 200, false},
		{"http", secret, 401, false},
		{"invalid_json", secret, 200, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logs.Reset()
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			}))
			defer api.Close()
			h := testHandler(t, api.URL, api.URL)
			got, err := h.oauth.fly.prepareCredential(context.Background(), secret)
			if (err == nil) != tc.accepted || (!tc.accepted && got.Token != "") {
				t.Fatal("verification did not fail closed")
			}
			var out any
			_ = h.oauth.fly.loginJSON(context.Background(), "login_redeem", "/"+secret, "Bearer "+secret, map[string]string{"code": secret}, 200, &out)
			if strings.Contains(logs.String(), secret) || (err != nil && strings.Contains(err.Error(), secret)) {
				t.Fatal("request, response or identity leaked into diagnostics")
			}
		})
	}
}

func TestOAuthCannotExtendConnectionDeadline(t *testing.T) {
	api := httptest.NewServer(managementFixture(t, "fo1_fixture", http.NotFoundHandler()))
	defer api.Close()
	h := testHandler(t, api.URL, api.URL)
	now := time.Unix(1800000000, 0)
	h.oauth.now = func() time.Time { return now }
	h.oauth.fly.now = h.oauth.now
	clientID := "fixture-client"
	expires := now.Add(2 * time.Minute).Unix()
	w := httptest.NewRecorder()
	h.oauth.issueTokens(context.Background(), w, hashClientID(clientID), "mcp offline_access", h.oauth.resourceURL, "fo1_fixture", "fixture-subject", expires, "", nil)
	var tokens struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
	}
	if json.Unmarshal(w.Body.Bytes(), &tokens) != nil || tokens.ExpiresIn != 120 {
		t.Fatal("access token outlives connection deadline")
	}
	now = now.Add(119 * time.Second)
	if _, err := h.oauth.verifyBearer("Bearer " + tokens.AccessToken); err != nil {
		t.Fatal("rejected before deadline")
	}
	now = now.Add(time.Second)
	if _, err := h.oauth.verifyBearer("Bearer " + tokens.AccessToken); err == nil {
		t.Fatal("accepted at deadline")
	}
	refresh := performRequest(h, http.MethodPost, "/token", url.Values{"grant_type": {"refresh_token"}, "client_id": {clientID}, "refresh_token": {tokens.RefreshToken}}.Encode(), "application/x-www-form-urlencoded")
	if refresh.Code != http.StatusBadRequest {
		t.Fatal("refresh extended connection deadline")
	}
	code, err := h.oauth.sealer.seal("authorization_code", authorizationCode{ExpiresAt: now.Add(time.Minute).Unix(), CredentialExp: expires, RedirectURI: h.oauth.redirectURIs[0], Management: &managementGrant{ExpiresAt: now.Add(time.Minute).Unix()}})
	if err != nil {
		t.Fatal(err)
	}
	h.oauth.rememberGrant("code:"+hashClientID("fixture-code"), pendingGrant{expiresAt: now.Add(time.Minute).Unix(), sealedCode: code})
	response := exchangeCode(h, clientID, "fixture-code", strings.Repeat("v", 64))
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "expired authorization code") {
		t.Fatal("exchange accepted expired connection")
	}
}
