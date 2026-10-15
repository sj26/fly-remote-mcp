//go:build ignore

// Extract only declarative MCP tool metadata, never flyctl's argv builders.
// Usage: go run scripts/generate-tool-catalog.go /path/to/flyctl/internal/command/mcp/server
package main

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
)

func literal(expr ast.Expr) any {
	switch v := expr.(type) {
	case *ast.BasicLit:
		s, err := strconv.Unquote(v.Value)
		if err != nil {
			panic(err)
		}
		return s
	case *ast.Ident:
		return v.Name == "true"
	case *ast.SelectorExpr:
		if id, ok := v.X.(*ast.Ident); ok && id.Name == "platform" && v.Sel.Name == "RegionsCommandDesc" {
			return "View a list of regions where Fly has datacenters."
		}
		panic("unknown metadata constant")
	case *ast.CompositeLit:
		if _, ok := v.Type.(*ast.ArrayType); ok {
			values := []any{}
			for _, e := range v.Elts {
				values = append(values, literal(e))
			}
			return values
		}
		values := map[string]any{}
		for _, e := range v.Elts {
			kv := e.(*ast.KeyValueExpr)
			var key string
			if id, ok := kv.Key.(*ast.Ident); ok {
				key = id.Name
			} else {
				key = literal(kv.Key).(string)
			}
			if key != "Builder" {
				values[key] = literal(kv.Value)
			}
		}
		return values
	default:
		panic(fmt.Sprintf("unsupported metadata expression %T", expr))
	}
}

func main() {
	if len(os.Args) != 2 {
		panic("expected flyctl MCP source directory")
	}
	paths, err := filepath.Glob(filepath.Join(os.Args[1], "*.go"))
	if err != nil {
		panic(err)
	}
	var tools []map[string]any
	for _, path := range paths {
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			panic(err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			v, ok := n.(*ast.ValueSpec)
			if !ok {
				return true
			}
			for _, e := range v.Values {
				list, ok := e.(*ast.CompositeLit)
				if !ok {
					continue
				}
				array, ok := list.Type.(*ast.ArrayType)
				if !ok {
					continue
				}
				element, ok := array.Elt.(*ast.Ident)
				if !ok || element.Name != "FlyCommand" {
					continue
				}
				for _, row := range list.Elts {
					metadata := literal(row).(map[string]any)
					if metadata["ToolName"] != nil {
						tools = append(tools, metadata)
					}
				}
			}
			return false
		})
	}
	sort.Slice(tools, func(i, j int) bool { return tools[i]["ToolName"].(string) < tools[j]["ToolName"].(string) })
	if len(tools) != 60 {
		panic(fmt.Sprintf("expected 60 tools, got %d; review upstream catalog changes", len(tools)))
	}
	encoded, err := json.MarshalIndent(tools, "", "  ")
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile("internal/gateway/tool_catalog.json", append(encoded, '\n'), 0644); err != nil {
		panic(err)
	}
}
