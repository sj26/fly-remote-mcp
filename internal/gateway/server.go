package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type flyCredentialContextKey struct{}

type Handler struct {
	oauth           *oauthHandlers
	mcpHandler      http.Handler
	resourceMetaURL string
}

func NewHandler(config Config) (*Handler, error) {
	sealer, err := newSealer(config.TokenEncryptionKey)
	if err != nil {
		return nil, err
	}
	now := time.Now
	httpClient := &http.Client{Timeout: 12 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	oauth := &oauthHandlers{
		baseURL:      config.PublicBaseURL,
		resourceURL:  config.PublicBaseURL + "/mcp",
		redirectURIs: append([]string(nil), config.OAuthRedirectURIs...),
		sealer:       sealer,
		fly: &flyClient{
			graphqlURL:    config.FlyGraphQLURL,
			machinesURL:   config.FlyMachinesURL,
			credentialTTL: config.CredentialTTL,
			httpClient:    httpClient,
			now:           now,
		},
		now:           now,
		accessTTL:     config.AccessTokenTTL,
		clientTTL:     config.ClientTTL,
		pendingGrants: make(map[string]pendingGrant),
	}

	return &Handler{
		oauth:           oauth,
		mcpHandler:      newMCPHandler(oauth.fly),
		resourceMetaURL: config.PublicBaseURL + "/.well-known/oauth-protected-resource/mcp",
	}, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/":
		h.root(w, r)
	case "/healthz":
		h.health(w, r)
	case "/mcp":
		h.mcp(w, r)
	case "/.well-known/oauth-authorization-server":
		h.oauth.metadata(w, r)
	case "/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp":
		h.oauth.protectedResourceMetadata(w, r)
	case "/register":
		h.oauth.register(w, r)
	case "/authorize":
		h.oauth.authorize(w, r)
	case "/token":
		h.oauth.token(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (h *Handler) root(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = fmt.Fprintln(w, "Fly.io MCP gateway\n\nConnect an MCP client to /mcp. OAuth discovery is enabled.")
}

func (h *Handler) health(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = fmt.Fprintln(w, "ok")
	}
}

func (h *Handler) mcp(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		setMCPResponseCORS(w.Header())
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Accept, Mcp-Protocol-Version, Mcp-Session-Id, Last-Event-ID")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	claims, err := h.oauth.verifyBearer(r.Header.Get("Authorization"))
	if err != nil {
		setMCPResponseCORS(w.Header())
		challenge := fmt.Sprintf(`Bearer resource_metadata=%q, scope=%q`, h.resourceMetaURL, mcpScope)
		if r.Header.Get("Authorization") != "" {
			challenge = fmt.Sprintf(`Bearer error="invalid_token", resource_metadata=%q, scope=%q`, h.resourceMetaURL, mcpScope)
		}
		w.Header().Set("WWW-Authenticate", challenge)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	r.Header.Del("Authorization")
	r.Header.Del("Mcp-Session-Id")
	r.Header.Del("Last-Event-ID")
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	setMCPResponseCORS(w.Header())
	w.Header().Set("Cache-Control", "no-store")
	h.mcpHandler.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), flyCredentialContextKey{}, claims.FlyToken)))
}

func setMCPResponseCORS(header http.Header) {
	header.Set("Access-Control-Allow-Origin", "*")
	header.Set("Access-Control-Expose-Headers", "Mcp-Session-Id, WWW-Authenticate")
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeCORSPreflight(w http.ResponseWriter, methods string) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", methods)
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
	w.WriteHeader(http.StatusNoContent)
}

func methodNotAllowed(w http.ResponseWriter, method string) {
	w.Header().Set("Allow", method)
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}

func contextWithTimeout(r *http.Request, duration time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(r.Context(), duration)
}
