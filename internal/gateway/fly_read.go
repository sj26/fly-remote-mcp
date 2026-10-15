package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
)

// API shapes and header selection follow flyctl 11e4d398 and fly-go v0.9.14:
// resource_organizations.go, command/apps/list.go and flaps/flaps_machines.go.
// We do not run CLI token monitoring or mutate credentials during a tool call.
type flyOrganization struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Slug string `json:"slug"`
}

type flyApp struct {
	ID           string          `json:"id"`
	Name         string          `json:"name"`
	Status       string          `json:"status"`
	Organization flyOrganization `json:"organization"`
}

type flyMachine struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	State  string `json:"state"`
	Region string `json:"region"`
}

type flyConnection[T any] struct {
	Nodes    []T
	PageInfo struct {
		HasNextPage bool
		EndCursor   string
	}
}

// GraphQL accepts mixed credentials; Machines accepts only the macaroons.
// User-level organization discovery uses fo1, just as management acquisition.
func flyHeaders(bundle string) (graphql, machines, oauth string, err error) {
	var macaroons []string
	for _, part := range strings.Split(strings.TrimPrefix(bundle, "FlyV1 "), ",") {
		switch {
		case strings.HasPrefix(part, "fm2_") && len(part) > 4:
			macaroons = append(macaroons, part)
		case strings.HasPrefix(part, "fo1_") && len(part) > 4 && oauth == "":
			oauth = "Bearer " + part
		default:
			return "", "", "", errors.New("Invalid Fly credential bundle; reconnect your MCP client.")
		}
	}
	if len(macaroons) == 0 || oauth == "" {
		return "", "", "", errors.New("Incomplete Fly credential bundle; reconnect your MCP client.")
	}
	return bundle, "FlyV1 " + strings.Join(macaroons, ","), oauth, nil
}

func (c *flyClient) listOrganizations(ctx context.Context, credential, _ string) (any, error) {
	_, _, authorization, err := flyHeaders(credential)
	if err != nil {
		return nil, err
	}
	result := []flyOrganization{}
	var after *string
	for page := 0; page < 100; page++ {
		var data struct {
			Organizations *flyConnection[flyOrganization]
		}
		if err := c.graphql(ctx, "mcp_organizations", authorization,
			`query FlyMCPListOrganizations($after: String) { organizations(first: 100, after: $after) { nodes { id name slug } pageInfo { hasNextPage endCursor } } }`,
			map[string]any{"after": after}, &data); err != nil {
			return nil, fmt.Errorf("Organization listing failed: %w", err)
		}
		if data.Organizations == nil {
			return nil, errors.New("Fly returned no organization connection")
		}
		result = append(result, data.Organizations.Nodes...)
		info := data.Organizations.PageInfo
		if !info.HasNextPage {
			return result, nil
		}
		if info.EndCursor == "" || (after != nil && info.EndCursor == *after) {
			return nil, errors.New("Fly returned invalid organization pagination")
		}
		after = &info.EndCursor
	}
	return nil, errors.New("Fly organization listing exceeded 100 pages")
}

func (c *flyClient) listApps(ctx context.Context, credential, org string) (any, error) {
	authorization, _, _, err := flyHeaders(credential)
	if err != nil {
		return nil, err
	}
	var orgID *string
	if org != "" {
		var data struct{ Organization *struct{ ID string } }
		if err := c.graphql(ctx, "mcp_app_organization", authorization,
			`query FlyMCPAppOrganization($slug: String!) { organization(slug: $slug) { id } }`, map[string]string{"slug": org}, &data); err != nil {
			return nil, fmt.Errorf("Organization lookup failed: %w", err)
		}
		if data.Organization == nil || data.Organization.ID == "" {
			return nil, errors.New("Fly did not return the requested organization")
		}
		orgID = &data.Organization.ID
	}
	result := []flyApp{}
	var after *string
	for page := 0; page < 100; page++ {
		var data struct{ Apps *flyConnection[flyApp] }
		if err := c.graphql(ctx, "mcp_apps", authorization,
			`query FlyMCPListApps($org: ID, $after: String) { apps(type: "container", first: 100, after: $after, organizationId: $org) { nodes { id name status organization { id name slug } } pageInfo { hasNextPage endCursor } } }`,
			map[string]any{"org": orgID, "after": after}, &data); err != nil {
			return nil, fmt.Errorf("App listing failed: %w", err)
		}
		if data.Apps == nil {
			return nil, errors.New("Fly returned no app connection")
		}
		result = append(result, data.Apps.Nodes...)
		info := data.Apps.PageInfo
		if !info.HasNextPage {
			return result, nil
		}
		if info.EndCursor == "" || (after != nil && info.EndCursor == *after) {
			return nil, errors.New("Fly returned invalid app pagination")
		}
		after = &info.EndCursor
	}
	return nil, errors.New("Fly app listing exceeded 100 pages")
}

func (c *flyClient) listMachines(ctx context.Context, credential, app string) (result any, resultErr error) {
	status := 0
	defer func() { slog.Info("fly_mcp", "stage", "mcp_machines", "status", status, "accepted", resultErr == nil) }()
	_, authorization, _, err := flyHeaders(credential)
	if err != nil {
		return nil, err
	}
	endpoint := c.machinesURL + "/v1/apps/" + url.PathEscape(app) + "/machines"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, errors.New("Could not create Machines request")
	}
	req.Header.Set("Authorization", authorization)
	req.Header.Set("User-Agent", "fly-mcp-gateway")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, errors.New("Fly Machines request failed")
	}
	defer resp.Body.Close()
	status = resp.StatusCode
	if status != http.StatusOK {
		return nil, fmt.Errorf("Fly Machines rejected the request (HTTP %d)", status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if err != nil || len(body) > 1<<20 {
		return nil, errors.New("Invalid Fly Machines response")
	}
	machines := []flyMachine{}
	if json.Unmarshal(body, &machines) != nil || machines == nil {
		return nil, errors.New("Invalid Fly Machines response")
	}
	return machines, nil
}
