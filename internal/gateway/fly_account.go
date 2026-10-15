package gateway

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// accountToolHandlers implements the account/app portion of flyctl's MCP
// catalogue directly against Fly's public APIs. Mutations are deliberately
// single-attempt: their errors must be treated as having an unknown outcome.
func (c *flyClient) accountToolHandlers() map[string]nativeToolHandler {
	return map[string]nativeToolHandler{
		"fly-apps-create": c.createApp, "fly-apps-destroy": c.destroyApp,
		"fly-apps-list": func(ctx context.Context, cred string, a toolArguments) (any, error) {
			return c.listApps(ctx, cred, a.text("org"))
		},
		"fly-apps-move": c.moveApp, "fly-apps-releases": c.appReleases, "fly-apps-restart": c.restartApp,
		"fly-orgs-create": c.createOrg, "fly-orgs-delete": c.deleteOrg, "fly-orgs-invite": c.inviteOrg,
		"fly-orgs-list": func(ctx context.Context, cred string, _ toolArguments) (any, error) {
			return c.listOrganizations(ctx, cred, "")
		},
		"fly-orgs-remove": c.removeOrgMember, "fly-orgs-show": c.showOrg,
		"fly-secrets-deploy": c.deploySecrets, "fly-secrets-list": c.listSecrets,
		"fly-secrets-set": c.setSecrets, "fly-secrets-unset": c.unsetSecrets,
		"fly-logs": c.logs, "fly-status": c.appStatus,
	}
}

func (c *flyClient) createApp(ctx context.Context, cred string, a toolArguments) (any, error) {
	_, machines, _, err := flyHeaders(cred)
	if err != nil {
		return nil, err
	}
	in := map[string]any{"org_slug": a.text("org")}
	if a.has("name") {
		// The Machines app-create endpoint uses the flaps CreateAppRequest
		// shape (name), not GraphQL's app_name/organizationId shape.
		in["name"] = a.text("name")
	}
	if a.has("network") {
		in["network"] = a.text("network")
	}
	var out map[string]any
	err = c.nativeJSON(ctx, machines, http.MethodPost, c.machinesURL+"/v1/apps?wait=true", in, &out, nil)
	return out, err
}

func (c *flyClient) destroyApp(ctx context.Context, cred string, a toolArguments) (any, error) {
	err := c.machinesRequest(ctx, cred, http.MethodDelete, appAPIPath(a.text("name")), nil, nil)
	if err != nil {
		return nil, err
	}
	return map[string]any{"destroyed": a.text("name")}, nil
}

func (c *flyClient) appReleases(ctx context.Context, cred string, a toolArguments) (any, error) {
	auth, _, _, err := flyHeaders(cred)
	if err != nil {
		return nil, err
	}
	var d struct {
		App *struct {
			Releases *struct{ Nodes []map[string]any }
		}
	}
	err = c.graphql(ctx, "mcp_app_releases", auth, `query FlyMCPReleases($appName:String!,$limit:Int!){app(name:$appName){releases:releasesUnprocessed(first:$limit){nodes{id version description reason status imageRef stable user{id email name} createdAt}}}}`, map[string]any{"appName": a.text("name"), "limit": 25}, &d)
	if err != nil {
		return nil, err
	}
	if d.App == nil || d.App.Releases == nil {
		return nil, errors.New("Fly returned no release connection")
	}
	return map[string]any{"releases": d.App.Releases.Nodes, "limit": 25, "truncated": len(d.App.Releases.Nodes) == 25}, nil
}

func (c *flyClient) orgBySlug(ctx context.Context, auth, slug string, members bool) (map[string]any, error) {
	var d struct{ Organization map[string]any }
	err := c.graphql(ctx, "mcp_organization", auth, "query FlyMCPOrganization($slug:String!){organization(slug:$slug){id name slug type viewerRole}}", map[string]string{"slug": slug}, &d)
	if err != nil {
		return nil, err
	}
	if d.Organization == nil {
		return nil, errors.New("Fly did not return the requested organization")
	}
	if !members {
		return d.Organization, nil
	}
	for _, connection := range []string{"memberships", "invitations"} {
		var after *string
		all := []map[string]any{}
		for page := 0; page < 1000; page++ {
			var p struct {
				Organization *struct {
					Memberships, Invitations *flyConnection[map[string]any]
				}
			}
			// Fly exposes members, with roles on edges and users in edge.node.
			// Aliases retain the normalized membership shape used by tool callers.
			fields := "memberships:members(first:100,after:$after){nodes:edges{role user:node{id name email}} pageInfo{hasNextPage endCursor}}"
			if connection == "invitations" {
				fields = "invitations(first:100,after:$after){nodes{id email createdAt redeemed} pageInfo{hasNextPage endCursor}}"
			}
			err = c.graphql(ctx, "mcp_organization_"+connection, auth, "query($slug:String!,$after:String){organization(slug:$slug){"+fields+"}}", map[string]any{"slug": slug, "after": after}, &p)
			if err != nil {
				return nil, err
			}
			if p.Organization == nil {
				return nil, errors.New("Fly omitted organization while paginating " + connection)
			}
			conn := p.Organization.Memberships
			if connection == "invitations" {
				conn = p.Organization.Invitations
			}
			if conn == nil {
				return nil, errors.New("Fly omitted required " + connection + " data")
			}
			all = append(all, conn.Nodes...)
			if !conn.PageInfo.HasNextPage {
				break
			}
			if conn.PageInfo.EndCursor == "" || after != nil && *after == conn.PageInfo.EndCursor {
				return nil, errors.New("Fly returned invalid " + connection + " pagination")
			}
			after = &conn.PageInfo.EndCursor
			if page == 999 {
				return nil, errors.New("Organization pagination exceeded safety bound")
			}
		}
		d.Organization[connection] = map[string]any{"nodes": all, "pageInfo": map[string]any{"hasNextPage": false}}
	}
	return d.Organization, nil
}

func (c *flyClient) createOrg(ctx context.Context, cred string, a toolArguments) (any, error) {
	_, _, auth, e := flyHeaders(cred)
	if e != nil {
		return nil, e
	}
	var d struct {
		CreateOrganization struct{ Organization map[string]any }
	}
	e = c.graphql(ctx, "mcp_org_create", auth, `mutation($input:CreateOrganizationInput!){createOrganization(input:$input){organization{id name slug type viewerRole}}}`, map[string]any{"input": map[string]string{"name": a.text("name")}}, &d)
	if e != nil {
		return nil, e
	}
	if d.CreateOrganization.Organization == nil {
		return nil, errors.New("Fly returned no created organization")
	}
	d.CreateOrganization.Organization["credentialRefreshRequired"] = true
	d.CreateOrganization.Organization["credentialRefreshReason"] = "The current organization-scoped credential bundle predates this organization"
	return d.CreateOrganization.Organization, nil
}

func (c *flyClient) deleteOrg(ctx context.Context, cred string, a toolArguments) (any, error) {
	_, _, auth, e := flyHeaders(cred)
	if e != nil {
		return nil, e
	}
	org, e := c.orgBySlug(ctx, auth, a.text("slug"), false)
	if e != nil {
		return nil, e
	}
	id, _ := org["id"].(string)
	if id == "" {
		return nil, errors.New("Fly returned an organization without an ID")
	}
	var d struct {
		DeleteOrganization struct{ DeletedOrganizationID string }
	}
	e = c.graphql(ctx, "mcp_org_delete", auth, `mutation($input:DeleteOrganizationInput!){deleteOrganization(input:$input){deletedOrganizationId}}`, map[string]any{"input": map[string]string{"organizationId": id}}, &d)
	if e != nil {
		return nil, e
	}
	if d.DeleteOrganization.DeletedOrganizationID == "" {
		return nil, errors.New("Fly returned no deleted organization ID")
	}
	return map[string]any{"deletedOrganizationId": d.DeleteOrganization.DeletedOrganizationID}, nil
}

func (c *flyClient) inviteOrg(ctx context.Context, cred string, a toolArguments) (any, error) {
	_, _, auth, e := flyHeaders(cred)
	if e != nil {
		return nil, e
	}
	org, e := c.orgBySlug(ctx, auth, a.text("slug"), false)
	if e != nil {
		return nil, e
	}
	id, _ := org["id"].(string)
	if id == "" {
		return nil, errors.New("Fly returned an organization without an ID")
	}
	var d struct {
		CreateOrganizationInvitation struct{ Invitation map[string]any }
	}
	e = c.graphql(ctx, "mcp_org_invite", auth, `mutation($input:CreateOrganizationInvitationInput!){createOrganizationInvitation(input:$input){invitation{id email createdAt redeemed organization{slug}}}}`, map[string]any{"input": map[string]string{"organizationId": id, "email": a.text("email")}}, &d)
	if e != nil {
		return nil, e
	}
	if d.CreateOrganizationInvitation.Invitation == nil {
		return nil, errors.New("Fly returned no organization invitation")
	}
	return d.CreateOrganizationInvitation.Invitation, nil
}

func (c *flyClient) showOrg(ctx context.Context, cred string, a toolArguments) (any, error) {
	_, _, auth, e := flyHeaders(cred)
	if e != nil {
		return nil, e
	}
	return c.orgBySlug(ctx, auth, a.text("slug"), true)
}

func (c *flyClient) removeOrgMember(ctx context.Context, cred string, a toolArguments) (any, error) {
	_, _, auth, e := flyHeaders(cred)
	if e != nil {
		return nil, e
	}
	org, e := c.orgBySlug(ctx, auth, a.text("slug"), true)
	if e != nil {
		return nil, e
	}
	oid, _ := org["id"].(string)
	// Resolve email to the immutable user ID. Never pass an email as userId.
	members, _ := org["memberships"].(map[string]any)
	var uid string
	nodes, _ := members["nodes"].([]map[string]any)
	for _, n := range nodes {
		u, _ := n["user"].(map[string]any)
		if strings.EqualFold(fmt.Sprint(u["email"]), a.text("email")) {
			if uid != "" {
				return nil, errors.New("Multiple memberships matched that email")
			}
			uid, _ = u["id"].(string)
		}
	}
	if uid == "" {
		return nil, errors.New("No organization member has that email")
	}
	var d struct {
		DeleteOrganizationMembership struct {
			Organization map[string]any
			User         map[string]any
		}
	}
	e = c.graphql(ctx, "mcp_org_remove", auth, `mutation($input:DeleteOrganizationMembershipInput!){deleteOrganizationMembership(input:$input){organization{slug} user{id name email}}}`, map[string]any{"input": map[string]string{"organizationId": oid, "userId": uid}}, &d)
	if e != nil {
		return nil, e
	}
	if d.DeleteOrganizationMembership.Organization == nil || d.DeleteOrganizationMembership.User == nil {
		return nil, errors.New("Fly returned no deleted organization membership")
	}
	return d.DeleteOrganizationMembership, nil
}

type accountMachine struct {
	ID         string         `json:"id"`
	InstanceID string         `json:"instance_id"`
	State      string         `json:"state"`
	Config     map[string]any `json:"config"`
	Name       string         `json:"name"`
	Region     string         `json:"region"`
	Checks     []struct {
		Status string `json:"status"`
	} `json:"checks"`
}

func managedAccountMachine(m accountMachine) bool {
	if m.State == "destroyed" || m.State == "destroying" {
		return false
	}
	meta, _ := m.Config["metadata"].(map[string]any)
	if fmt.Sprint(meta["fly_platform_version"]) != "v2" {
		return false
	}
	pg, _ := meta["fly_process_group"].(string)
	if pg == "" {
		pg, _ = meta["process_group"].(string)
	}
	return pg != "fly_app_console" && pg != "fly_app_release_command" && pg != "release_command"
}

func (c *flyClient) machines(ctx context.Context, cred, app string) ([]accountMachine, error) {
	var m []accountMachine
	e := c.machinesRequest(ctx, cred, http.MethodGet, appAPIPath(app)+"/machines", nil, &m)
	return m, e
}

func (c *flyClient) restartApp(ctx context.Context, cred string, a toolArguments) (any, error) {
	app := a.text("name")
	ms, e := c.machines(ctx, cred, app)
	if e != nil {
		return nil, e
	}
	done := []string{}
	for _, m := range ms {
		if !managedAccountMachine(m) || m.State != "started" {
			continue
		}
		e = c.withMachineLease(ctx, cred, app, m.ID, func(x context.Context, nonce string) error {
			h := http.Header{"fly-machine-lease-nonce": []string{nonce}}
			endpoint := appAPIPath(app) + "/machines/" + url.PathEscape(m.ID) + "/restart?force_stop=" + fmt.Sprint(a.flag("force-stop"))
			if e := c.machinesRequestHeaders(x, cred, http.MethodPost, endpoint, nil, nil, h); e != nil {
				return e
			}
			if e := c.waitMachineState(x, cred, app, m.ID, "started", 3*time.Minute); e != nil {
				return e
			}
			if !a.flag("skip-health-checks") {
				return c.waitMachineHealthy(x, cred, app, m.ID, 3*time.Minute)
			}
			return nil
		})
		if e != nil {
			return map[string]any{"restarted": done, "failed": m.ID}, fmt.Errorf("rolling restart partially completed: %w", e)
		}
		done = append(done, m.ID)
	}
	return map[string]any{"restarted": done, "healthChecksSkipped": a.flag("skip-health-checks")}, nil
}

func (c *flyClient) moveApp(ctx context.Context, cred string, a toolArguments) (any, error) {
	auth, _, _, e := flyHeaders(cred)
	if e != nil {
		return nil, e
	}
	org, e := c.orgBySlug(ctx, auth, a.text("org"), false)
	if e != nil {
		return nil, e
	}
	oid, _ := org["id"].(string)
	if oid == "" {
		return nil, errors.New("Fly returned an organization without an ID")
	}
	ms, e := c.machines(ctx, cred, a.text("name"))
	if e != nil {
		return nil, e
	}
	managed := make([]accountMachine, 0, len(ms))
	for _, m := range ms {
		if statics, exists := m.Config["statics"]; exists && statics != nil && fmt.Sprint(statics) != "[]" {
			return nil, errors.New("Cannot move this app: its Tigris statics bucket requires tokenized S3 authority that is not present in the supplied Fly API credential; no changes were made")
		}
		if m.State != "destroyed" && m.State != "destroying" {
			if m.ID == "" || m.InstanceID == "" || m.Config == nil {
				return nil, errors.New("Cannot move this app: Fly returned an incomplete machine; no changes were made")
			}
			managed = append(managed, m)
		}
	}
	var moved map[string]any
	done := []string{}
	nonces := make([]string, len(managed))
	var acquire func(context.Context, int) error
	acquire = func(ctx context.Context, i int) error {
		if i < len(managed) {
			m := managed[i]
			return c.withMachineLease(ctx, cred, a.text("name"), m.ID, func(x context.Context, nonce string) error {
				nonces[i] = nonce
				return acquire(x, i+1)
			})
		}
		var d struct{ MoveApp struct{ App map[string]any } }
		if err := c.graphql(ctx, "mcp_app_move", auth, `mutation($input:MoveAppInput!){moveApp(input:$input){app{id name networkId organization{slug}}}}`, map[string]any{"input": map[string]string{"appId": a.text("name"), "organizationId": oid}}, &d); err != nil {
			return err
		}
		if d.MoveApp.App == nil {
			return errors.New("Fly returned no moved app")
		}
		moved = d.MoveApp.App
		for i, m := range managed {
			if err := c.updateMachineForSecretsWithNonce(ctx, cred, a.text("name"), m, nil, !a.flag("skip-health-checks"), nonces[i]); err != nil {
				return fmt.Errorf("app moved but machine refresh partially completed after %v: %w", done, err)
			}
			done = append(done, m.ID)
		}
		return nil
	}
	if e = acquire(ctx, 0); e != nil {
		if moved != nil {
			return map[string]any{"app": moved, "moved": true, "updatedMachines": done}, e
		}
		return nil, e
	}
	return map[string]any{"app": moved, "moved": true, "updatedMachines": done}, nil
}

type appSecret struct {
	Name      string  `json:"name"`
	Digest    string  `json:"digest,omitempty"`
	UpdatedAt *string `json:"updated_at,omitempty"`
	CreatedAt *string `json:"created_at,omitempty"`
}

func (c *flyClient) listSecrets(ctx context.Context, cred string, a toolArguments) (any, error) {
	var d struct {
		Secrets []appSecret `json:"secrets"`
	}
	e := c.machinesRequest(ctx, cred, http.MethodGet, appAPIPath(a.text("app"))+"/secrets", nil, &d)
	return d.Secrets, e
}
func (c *flyClient) updateSecrets(ctx context.Context, cred, app string, v map[string]*string) (any, error) {
	var d struct {
		Secrets []appSecret `json:"secrets"`
		Version uint64      `json:"version"`
	}
	e := c.machinesRequest(ctx, cred, http.MethodPost, appAPIPath(app)+"/secrets", map[string]any{"values": v}, &d)
	if e != nil {
		return nil, e
	}
	return map[string]any{"staged": len(v), "version": d.Version, "secrets": d.Secrets}, nil
}
func (c *flyClient) setSecrets(ctx context.Context, cred string, a toolArguments) (any, error) {
	v := map[string]*string{}
	for _, kv := range a.list("keyvalues") {
		k, x, ok := strings.Cut(kv, "=")
		if !ok || k == "" {
			return nil, errors.New("Each secret must use KEY=VALUE format")
		}
		value := x
		v[k] = &value
	}
	if len(v) == 0 {
		return nil, errors.New("At least one secret is required")
	}
	return c.updateSecrets(ctx, cred, a.text("app"), v)
}
func (c *flyClient) unsetSecrets(ctx context.Context, cred string, a toolArguments) (any, error) {
	v := map[string]*string{}
	for _, k := range a.list("names") {
		v[k] = nil
	}
	return c.updateSecrets(ctx, cred, a.text("app"), v)
}

func (c *flyClient) deploySecrets(ctx context.Context, cred string, a toolArguments) (any, error) {
	app := a.text("app")
	ms, e := c.machines(ctx, cred, app)
	if e != nil {
		return nil, e
	}
	// GET /secrets has no version. Re-submitting the deployed configuration
	// installs current staged secrets, as flyctl's restart-only deployment does.
	done := []string{}
	for _, m := range ms {
		if !managedAccountMachine(m) {
			continue
		}
		e = c.updateMachineForSecrets(ctx, cred, app, m, nil, true)
		if e != nil {
			return map[string]any{"deployed": done, "failed": m.ID}, fmt.Errorf("secret deployment partially completed: %w", e)
		}
		done = append(done, m.ID)
	}
	if len(done) == 0 {
		return nil, errors.New("No managed Machines available to deploy staged secrets")
	}
	return map[string]any{"deployed": done}, nil
}

func (c *flyClient) updateMachineForSecrets(ctx context.Context, cred, app string, m accountMachine, minVersion *uint64, health bool) error {
	if m.ID == "" || m.InstanceID == "" || m.Config == nil {
		return errors.New("Fly returned an incomplete machine; refusing to update it")
	}
	return c.withMachineLease(ctx, cred, app, m.ID, func(x context.Context, nonce string) error {
		return c.updateMachineForSecretsWithNonce(x, cred, app, m, minVersion, health, nonce)
	})
}

func (c *flyClient) updateMachineForSecretsWithNonce(ctx context.Context, cred, app string, m accountMachine, minVersion *uint64, health bool, nonce string) error {
	wasStarted := m.State == "started"
	body := map[string]any{"config": m.Config, "current_version": m.InstanceID}
	if !wasStarted {
		body["skip_launch"] = true
	}
	if minVersion != nil {
		body["min_secrets_version"] = *minVersion
	}
	h := http.Header{"fly-machine-lease-nonce": []string{nonce}}
	var updated accountMachine
	if e := c.machinesRequestHeaders(ctx, cred, http.MethodPost, appAPIPath(app)+"/machines/"+url.PathEscape(m.ID), body, &updated, h); e != nil {
		return e
	}
	if !wasStarted {
		return c.waitMachineState(ctx, cred, app, m.ID, "stopped", 3*time.Minute)
	}
	if e := c.waitMachineState(ctx, cred, app, m.ID, "started", 3*time.Minute); e != nil {
		return e
	}
	if health {
		return c.waitMachineHealthy(ctx, cred, app, m.ID, 3*time.Minute)
	}
	return nil
}

func (c *flyClient) logs(ctx context.Context, cred string, a toolArguments) (any, error) {
	auth, _, _, e := flyHeaders(cred)
	if e != nil {
		return nil, e
	}
	q := url.Values{}
	q.Set("next_token", "")
	if a.has("machine") {
		q.Set("instance", a.text("machine"))
	}
	if a.has("region") {
		q.Set("region", a.text("region"))
	}
	type logsPage struct {
		Data []struct {
			ID         string         `json:"id"`
			Attributes map[string]any `json:"attributes"`
		} `json:"data"`
		Meta struct {
			NextToken string `json:"next_token"`
		} `json:"meta"`
	}
	endpoint := strings.TrimSuffix(c.graphqlURL, "/graphql") + "/api/v1/apps/" + url.PathEscape(a.text("app")) + "/logs?" + q.Encode()
	out := make([]map[string]any, 0, 200)
	truncated := false
	previousToken := ""
	for page := 0; page < 5; page++ {
		var d logsPage
		e = c.nativeJSON(ctx, auth, http.MethodGet, endpoint, nil, &d, nil)
		if e != nil {
			return nil, e
		}
		for _, x := range d.Data {
			entry := x.Attributes
			if entry == nil {
				entry = map[string]any{}
			}
			entry["id"] = x.ID
			out = append(out, entry)
			if len(out) == 500 {
				truncated = true
				break
			}
		}
		if truncated || d.Meta.NextToken == "" || len(d.Data) == 0 {
			break
		}
		if d.Meta.NextToken == previousToken {
			return nil, errors.New("Fly returned the same logs cursor again")
		}
		previousToken = d.Meta.NextToken
		q.Set("next_token", d.Meta.NextToken)
		endpoint = strings.TrimSuffix(c.graphqlURL, "/graphql") + "/api/v1/apps/" + url.PathEscape(a.text("app")) + "/logs?" + q.Encode()
		if page == 4 {
			truncated = true
		}
	}
	return map[string]any{"entries": out, "truncated": truncated, "maxPages": 5, "maxEntries": 500}, nil
}
func (c *flyClient) appStatus(ctx context.Context, cred string, a toolArguments) (any, error) {
	var app map[string]any
	if e := c.machinesRequest(ctx, cred, http.MethodGet, appAPIPath(a.text("app")), nil, &app); e != nil {
		return nil, e
	}
	ms, e := c.machines(ctx, cred, a.text("app"))
	if e != nil {
		return nil, e
	}
	redacted := make([]map[string]any, 0, len(ms))
	for _, m := range ms {
		checks := make([]string, 0, len(m.Checks))
		for _, check := range m.Checks {
			checks = append(checks, check.Status)
		}
		redacted = append(redacted, map[string]any{"id": m.ID, "name": m.Name, "region": m.Region, "state": m.State, "instance_id": m.InstanceID, "checkStatuses": checks})
	}
	return map[string]any{"app": app, "machines": redacted}, nil
}
