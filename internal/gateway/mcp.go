package gateway

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

var flyResourceName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)

// Declarative metadata extracted from flyctl, without its CLI argv builders.
// Source and license: third_party/README.md.
//
//go:embed tool_catalog.json
var toolCatalogJSON []byte

type toolArgumentSpec struct {
	Description string
	Type        string
	Required    bool
	Default     string
	Enum        []string
}
type toolSpec struct {
	ToolName        string
	ToolDescription string
	ToolArgs        map[string]toolArgumentSpec
}

func toolCatalog() []toolSpec {
	var catalog []toolSpec
	if err := json.Unmarshal(toolCatalogJSON, &catalog); err != nil {
		panic(err)
	}
	for i := range catalog {
		// There is no local fly.toml, working directory, or ambient app in a
		// hosted multi-user service. Every Machine operation must name its app.
		if arg, ok := catalog[i].ToolArgs["app"]; ok {
			arg.Required = true
			catalog[i].ToolArgs["app"] = arg
		}
	}
	return catalog
}

func readOnlyTool(name string) bool {
	return slices.Contains(strings.Fields(`fly-apps-list fly-apps-releases
		fly-certs-list fly-certs-show fly-ips-list fly-ips-private fly-logs
		fly-machine-egress-ip-list fly-machine-leases-view fly-machine-list fly-machine-status
		fly-orgs-list fly-orgs-show fly-platform-regions fly-platform-status fly-platform-vm-sizes
		fly-secrets-list fly-status fly-volumes-list fly-volumes-show fly-volumes-snapshots-list`), name)
}

func (s toolSpec) tool() mcp.Tool {
	readOnly := readOnlyTool(s.ToolName)
	description := s.ToolDescription
	if !readOnly {
		description += " Changes Fly resources or account state; may incur charges or cause downtime/data loss."
	}
	t := mcp.NewTool(s.ToolName, mcp.WithDescription(description), mcp.WithReadOnlyHintAnnotation(readOnly), mcp.WithDestructiveHintAnnotation(!readOnly), mcp.WithIdempotentHintAnnotation(readOnly))
	t.InputSchema.AdditionalProperties = false
	for name, arg := range s.ToolArgs {
		kind := arg.Type
		if kind == "enum" {
			kind = "string"
		}
		if kind == "hash" {
			kind = "array"
		}
		if kind == "number" {
			kind = "integer"
		}
		p := map[string]any{"type": kind, "description": arg.Description}
		if kind == "array" {
			p["items"] = map[string]any{"type": "string"}
			p["maxItems"] = 100
		}
		if kind == "string" {
			p["maxLength"] = 16384
		}
		if len(arg.Enum) > 0 {
			p["enum"] = arg.Enum
		}
		if kind == "integer" {
			p["minimum"] = 0
			p["maximum"] = 1 << 30
		}
		t.InputSchema.Properties[name] = p
		if arg.Required {
			t.InputSchema.Required = append(t.InputSchema.Required, name)
		}
	}
	slices.Sort(t.InputSchema.Required)
	return t
}

// Errors name the field, never its supplied value (which may be a secret).
func (s toolSpec) validate(args map[string]any) (toolArguments, error) {
	for name, value := range args {
		arg, ok := s.ToolArgs[name]
		if !ok {
			return nil, errors.New("Unknown argument; use only this tool's documented arguments")
		}
		valid := false
		switch arg.Type {
		case "string", "enum":
			v, ok := value.(string)
			valid = ok && len(v) <= 16384 && !strings.ContainsRune(v, '\x00') && (len(arg.Enum) == 0 || slices.Contains(arg.Enum, v))
			if arg.Required && v == "" {
				valid = false
			}
			if name == "app" || name == "org" || name == "slug" || name == "id" || name == "region" || (name == "name" && s.ToolName != "fly-orgs-create") {
				valid = valid && flyResourceName.MatchString(v)
			}
		case "boolean":
			_, valid = value.(bool)
		case "number":
			v, ok := value.(float64)
			valid = ok && !math.IsNaN(v) && !math.IsInf(v, 0) && math.Trunc(v) == v && v >= 0 && v <= 1<<30
			if name == "size" || name == "vm-cpus" || name == "vm-memory" {
				valid = valid && v > 0
			}
			if name == "wait-timeout" || name == "time" || name == "timeout" {
				valid = valid && v <= 240
			}
		case "array", "hash":
			v, ok := value.([]any)
			valid = ok && len(v) <= 100 && (!arg.Required || len(v) > 0)
			for _, item := range v {
				text, ok := item.(string)
				valid = valid && ok && len(text) <= 16384 && !strings.ContainsRune(text, '\x00')
			}
		}
		if !valid {
			return nil, fmt.Errorf("Invalid %s argument", name)
		}
	}
	for name, arg := range s.ToolArgs {
		if _, ok := args[name]; arg.Required && !ok {
			return nil, fmt.Errorf("Missing required %s argument", name)
		}
	}
	return toolArguments(args), nil
}

func newMCPHandler(fly *flyClient) http.Handler {
	srv := server.NewMCPServer("Fly MCP", "in-process-2", server.WithToolCapabilities(false))
	handlers := fly.accountToolHandlers()
	for _, group := range []map[string]nativeToolHandler{fly.machineToolHandlers(), fly.resourceToolHandlers()} {
		for name, handler := range group {
			if handlers[name] != nil {
				panic("duplicate native tool: " + name)
			}
			handlers[name] = handler
		}
	}
	catalog := toolCatalog()
	if len(catalog) != len(handlers) {
		panic("native tool/catalog mismatch")
	}
	for _, spec := range catalog {
		call := handlers[spec.ToolName]
		if call == nil {
			panic("missing native tool: " + spec.ToolName)
		}
		srv.AddTool(spec.tool(), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args, err := spec.validate(request.GetArguments())
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			credential, _ := ctx.Value(flyCredentialContextKey{}).(string)
			if credential == "" {
				return mcp.NewToolResultError("Missing Fly credential; reconnect your MCP client."), nil
			}
			ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
			defer cancel()
			value, callErr := call(ctx, credential, args)
			if callErr != nil {
				result := mcp.NewToolResultError(callErr.Error())
				// Multi-resource writes return safe progress so callers can inspect
				// partial completion instead of blindly replaying the entire call.
				if value != nil {
					if encoded, err := json.Marshal(value); err == nil {
						result.Content = append(result.Content, mcp.NewTextContent(string(encoded)))
					}
				}
				return result, nil
			}
			encoded, err := json.Marshal(value)
			if err != nil {
				return nil, errors.New("could not encode Fly result")
			}
			return mcp.NewToolResultText(string(encoded)), nil
		})
	}
	return server.NewStreamableHTTPServer(srv, server.WithStateLess(true), server.WithDisableStreaming(true))
}
