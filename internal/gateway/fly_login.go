package gateway

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
)

// Only the short-lived PKCE verifier is carried in encrypted browser state.
// Login credentials exist only during redemption.
func (c *flyClient) startLogin(ctx context.Context) (id, verifier, approvalURL string, err error) {
	material := make([]byte, 32)
	if _, err = rand.Read(material); err != nil {
		return
	}
	verifier = base64.RawURLEncoding.EncodeToString(material)
	challenge := sha256.Sum256([]byte(verifier))
	state, err := randomID()
	if err != nil {
		return "", "", "", err
	}
	var response struct {
		ID      string `json:"id"`
		AuthURL string `json:"auth_url"`
		PKCE    bool   `json:"pkce"`
	}
	err = c.loginJSON(ctx, "login_start", "/api/v1/cli_sessions", "", map[string]any{
		"name": "Fly MCP gateway", "signup": false, "target": "auth",
		"code_challenge":        base64.RawURLEncoding.EncodeToString(challenge[:]),
		"code_challenge_method": "S256", "state": state,
		// No redirect_port: the user returns the completion code manually.
	}, http.StatusCreated, &response)
	if err != nil {
		return "", "", "", err
	}
	link, parseErr := url.Parse(response.AuthURL)
	if !response.PKCE || response.ID == "" || parseErr != nil || link.Scheme != "https" || link.User != nil || (link.Host != "fly.io" && link.Host != "api.fly.io" && link.Host != "auth.fly.io") {
		return "", "", "", fmt.Errorf("Fly did not return a supported PKCE login; no fallback was attempted")
	}
	return response.ID, verifier, response.AuthURL, nil
}

func (c *flyClient) completeLogin(ctx context.Context, id, verifier, code string) (preparedCredential, error) {
	var login struct {
		Token string `json:"access_token"`
	}
	if err := c.loginJSON(ctx, "login_redeem", "/api/v1/cli_sessions/"+url.PathEscape(id)+"/redeem", "", map[string]string{
		"code": code, "code_verifier": verifier,
	}, http.StatusOK, &login); err != nil {
		return preparedCredential{}, err
	}
	return c.prepareCredential(ctx, login.Token)
}

func (c *flyClient) loginJSON(ctx context.Context, stage, path, authorization string, body any, expectedStatus int, out any) error {
	status, outcome := 0, "request_error"
	defer func() { slog.Info("fly_auth_http", "stage", stage, "status", status, "outcome", outcome) }()
	encoded, err := json.Marshal(body)
	if err != nil {
		return err
	}
	endpoint := strings.TrimSuffix(c.graphqlURL, "/graphql") + path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(encoded))
	if err != nil {
		return fmt.Errorf("could not create Fly login request")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "fly-mcp-gateway")
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		outcome = "transport_error"
		return fmt.Errorf("Fly request failed")
	}
	defer resp.Body.Close()
	status = resp.StatusCode
	if resp.StatusCode != expectedStatus {
		outcome = "http_error"
		return fmt.Errorf("Fly rejected the request (HTTP %d)", resp.StatusCode)
	}
	if json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out) != nil {
		outcome = "invalid_json"
		return fmt.Errorf("Fly returned an invalid response")
	}
	outcome = "decoded"
	return nil
}

// Never log upstream messages, paths, extensions, or bodies. Even error fields
// can echo credentials. Only fixed categories and counts leave request memory.
func logGraphQLDiagnostics(stage string, rawErrors []json.RawMessage) {
	slog.Info("fly_auth_graphql", "stage", stage, "error_count", len(rawErrors))
	for _, raw := range rawErrors {
		var entry struct{ Message string }
		category := "other"
		if json.Unmarshal(raw, &entry) == nil {
			message := strings.ToLower(entry.Message)
			switch {
			case strings.Contains(message, "discharge"):
				category = "discharge"
			case strings.Contains(message, "expired"):
				category = "expired"
			case strings.Contains(message, "caveat"):
				category = "caveat"
			case strings.Contains(message, "signature"):
				category = "signature"
			case strings.Contains(message, "macaroon"):
				category = "macaroon"
			case strings.Contains(message, "authenticate"), strings.Contains(message, "authentication"), strings.Contains(message, "invalid token"):
				category = "authentication"
			case strings.Contains(message, "unauthorized"), strings.Contains(message, "not authorized"), strings.Contains(message, "forbidden"), strings.Contains(message, "permission"), strings.Contains(message, "access denied"), strings.Contains(message, "not allowed"):
				category = "authorization"
			case strings.Contains(message, "not found"), strings.Contains(message, "could not find"):
				category = "not_found"
			}
		}
		slog.Info("fly_auth_graphql_error", "stage", stage, "category", category)
	}
}
