package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

type toolArguments map[string]any

func (a toolArguments) text(key string) string { s, _ := a[key].(string); return s }
func (a toolArguments) flag(key string) bool   { b, _ := a[key].(bool); return b }
func (a toolArguments) number(key string) int  { n, _ := a[key].(float64); return int(n) }
func (a toolArguments) has(key string) bool    { _, ok := a[key]; return ok }
func (a toolArguments) list(key string) []string {
	items, _ := a[key].([]any)
	out := make([]string, 0, len(items))
	for _, item := range items {
		out = append(out, item.(string))
	}
	return out
}

type nativeToolHandler func(context.Context, string, toolArguments) (any, error)

type nativeHTTPError struct{ StatusCode int }

func (e *nativeHTTPError) Error() string {
	return fmt.Sprintf("Fly rejected the request (HTTP %d); inspect resource state before retrying a write", e.StatusCode)
}

func httpStatus(err error) int {
	var response *nativeHTTPError
	if errors.As(err, &response) {
		return response.StatusCode
	}
	return 0
}

// Paths are built only by handlers from validated arguments, never supplied URLs.
func appAPIPath(app string) string { return "/v1/apps/" + url.PathEscape(app) }

func (c *flyClient) machinesRequest(ctx context.Context, credential, method, path string, body, out any) error {
	return c.machinesRequestHeaders(ctx, credential, method, path, body, out, nil)
}

func (c *flyClient) machinesRequestHeaders(ctx context.Context, credential, method, path string, body, out any, headers http.Header) error {
	_, authorization, _, err := flyHeaders(credential)
	if err != nil {
		return err
	}
	return c.nativeJSON(ctx, authorization, method, c.machinesURL+path, body, out, headers)
}

// No retry, token refresh, redirects, ambient credential, or upstream-body errors.
// A failed write may already have taken effect; callers must inspect before retry.
func (c *flyClient) nativeJSON(ctx context.Context, authorization, method, endpoint string, body, out any, headers http.Header) error {
	var data []byte
	var err error
	if body != nil {
		data, err = json.Marshal(body)
		if err != nil {
			return errors.New("Could not encode Fly request")
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(data))
	if err != nil {
		return errors.New("Could not create Fly request")
	}
	for key, values := range headers {
		req.Header[key] = append([]string(nil), values...)
	}
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	req.Header.Set("User-Agent", "fly-mcp-gateway")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return errors.New("Fly request failed; a write may have taken effect. Inspect the resource before retrying")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &nativeHTTPError{StatusCode: resp.StatusCode}
	}
	data, err = io.ReadAll(io.LimitReader(resp.Body, (4<<20)+1))
	if err != nil || len(data) > 4<<20 {
		return errors.New("Invalid or oversized Fly response; inspect resource state before retrying a write")
	}
	if out == nil {
		return nil
	}
	if len(data) == 0 {
		return errors.New("Fly returned an empty response")
	}
	if json.Unmarshal(data, out) != nil {
		return errors.New("Fly returned an invalid JSON response")
	}
	return nil
}
