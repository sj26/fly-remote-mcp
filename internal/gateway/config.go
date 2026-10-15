package gateway

import (
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"
)

type Config struct {
	ListenAddress      string
	PublicBaseURL      string
	FlyGraphQLURL      string
	FlyMachinesURL     string
	TokenEncryptionKey string
	CredentialTTL      time.Duration
	AccessTokenTTL     time.Duration
	ClientTTL          time.Duration
	OAuthRedirectURIs  []string
}

func ConfigFromEnv() (Config, error) {
	port := envOr("PORT", "8080")
	config := Config{
		ListenAddress:      ":" + port,
		PublicBaseURL:      strings.TrimSuffix(envOr("PUBLIC_BASE_URL", "http://localhost:"+port), "/"),
		FlyGraphQLURL:      envOr("FLY_GRAPHQL_URL", "https://api.fly.io/graphql"),
		FlyMachinesURL:     "https://api.machines.dev",
		TokenEncryptionKey: os.Getenv("TOKEN_ENCRYPTION_KEY"),
		CredentialTTL:      30 * 24 * time.Hour,
		AccessTokenTTL:     15 * time.Minute,
		ClientTTL:          5 * 365 * 24 * time.Hour,
		OAuthRedirectURIs:  strings.Fields(os.Getenv("OAUTH_REDIRECT_URIS")),
	}

	if len(config.OAuthRedirectURIs) == 0 {
		return Config{}, fmt.Errorf("OAUTH_REDIRECT_URIS must list the exact approved OAuth client callback URLs")
	}
	for _, redirectURI := range config.OAuthRedirectURIs {
		if !validRedirectURI(redirectURI) {
			return Config{}, fmt.Errorf("OAUTH_REDIRECT_URIS contains an invalid callback URL")
		}
	}

	if config.TokenEncryptionKey == "" {
		return Config{}, fmt.Errorf("TOKEN_ENCRYPTION_KEY is required; generate one with: openssl rand -base64 32")
	}
	if _, err := newSealer(config.TokenEncryptionKey); err != nil {
		return Config{}, err
	}

	baseURL, err := url.Parse(config.PublicBaseURL)
	if err != nil || baseURL.Host == "" || (baseURL.Scheme != "https" && !(baseURL.Scheme == "http" && isLoopbackHost(baseURL.Hostname()))) {
		return Config{}, fmt.Errorf("PUBLIC_BASE_URL must be HTTPS (HTTP is allowed only for localhost)")
	}
	return config, nil
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func isLoopbackHost(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}
