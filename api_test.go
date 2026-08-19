package credbound_test

import (
	"bytes"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// updateAPI rewrites the golden surface instead of comparing against it:
//
//	go test -run TestPublicAPISurface -update-api
var updateAPI = flag.Bool("update-api", false, "rewrite testdata/api.txt from the current sources")

// apiGolden is the recorded public surface of every package a host can
// import.
const apiGolden = "testdata/api.txt"

// TestPublicAPISurface pins everything outside this module can depend on.
// While the module is v0 breaking changes are allowed, but they must be
// deliberate and land in the CHANGELOG: this test turns any change to an
// exported declaration — a removed method, a renamed field, a widened
// signature, a new port method custom stores must implement — into a failure
// that has to be acknowledged by regenerating the golden file.
func TestPublicAPISurface(t *testing.T) {
	surface := publicSurface(t)
	rendered := strings.Join(surface, "\n") + "\n"

	if *updateAPI {
		if err := os.WriteFile(apiGolden, []byte(rendered), 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
		t.Logf("wrote %d declarations to %s", len(surface), apiGolden)
		return
	}

	expected, err := os.ReadFile(apiGolden)
	if err != nil {
		t.Fatalf("read golden (regenerate with -update-api): %v", err)
	}
	if string(expected) == rendered {
		return
	}
	recorded := strings.Split(strings.TrimSuffix(string(expected), "\n"), "\n")
	added, removed := difference(surface, recorded), difference(recorded, surface)
	var report strings.Builder
	report.WriteString("the public API surface changed; if the change is intended, note it in CHANGELOG.md and regenerate with:\n")
	report.WriteString("\tgo test -run TestPublicAPISurface -update-api\n")
	for _, declaration := range removed {
		fmt.Fprintf(&report, "\n- %s", declaration)
	}
	for _, declaration := range added {
		fmt.Fprintf(&report, "\n+ %s", declaration)
	}
	t.Fatal(report.String())
}

func difference(from, other []string) []string {
	present := make(map[string]struct{}, len(other))
	for _, value := range other {
		present[value] = struct{}{}
	}
	var only []string
	for _, value := range from {
		if _, ok := present[value]; !ok {
			only = append(only, value)
		}
	}
	return only
}

// publicSurface renders every exported declaration of every importable
// package of the module, sorted for a stable diff.
func publicSurface(t *testing.T) []string {
	t.Helper()
	fileSet := token.NewFileSet()
	var declarations []string
	err := filepath.WalkDir(".", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			// internal packages are not importable, examples are programs,
			// and the rest holds no Go source.
			switch entry.Name() {
			case ".git", ".github", "internal", "examples", "testdata", "migrations", "sql", "scripts", "specs":
				if path != "." {
					return fs.SkipDir
				}
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(fileSet, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}
		pkg := strings.ReplaceAll(filepath.Dir(path), string(filepath.Separator), "/")
		if pkg == "." {
			pkg = "credbound"
		}
		declarations = append(declarations, packageDeclarations(fileSet, pkg, file)...)
		return nil
	})
	if err != nil {
		t.Fatalf("walk sources: %v", err)
	}
	slices.Sort(declarations)
	return slices.Compact(declarations)
}

func packageDeclarations(fileSet *token.FileSet, pkg string, file *ast.File) []string {
	var declarations []string
	emit := func(format string, arguments ...any) {
		declarations = append(declarations, pkg+" "+fmt.Sprintf(format, arguments...))
	}
	for _, declaration := range file.Decls {
		switch typed := declaration.(type) {
		case *ast.FuncDecl:
			if !typed.Name.IsExported() {
				continue
			}
			signature := render(fileSet, typed.Type)
			if typed.Recv == nil {
				emit("func %s%s", typed.Name.Name, strings.TrimPrefix(signature, "func"))
				continue
			}
			receiver := render(fileSet, typed.Recv.List[0].Type)
			if !ast.IsExported(strings.TrimLeft(receiver, "*")) {
				continue
			}
			emit("method (%s) %s%s", receiver, typed.Name.Name, strings.TrimPrefix(signature, "func"))
		case *ast.GenDecl:
			for _, spec := range typed.Specs {
				switch specified := spec.(type) {
				case *ast.TypeSpec:
					if !specified.Name.IsExported() {
						continue
					}
					declarations = append(declarations, typeDeclarations(fileSet, pkg, specified)...)
				case *ast.ValueSpec:
					for _, name := range specified.Names {
						if !name.IsExported() {
							continue
						}
						kind := "var"
						if typed.Tok == token.CONST {
							kind = "const"
						}
						if specified.Type != nil {
							emit("%s %s %s", kind, name.Name, render(fileSet, specified.Type))
							continue
						}
						emit("%s %s", kind, name.Name)
					}
				}
			}
		}
	}
	return declarations
}

// typeDeclarations renders a type and, for structs and interfaces, each of its
// exported members: a renamed field or a new interface method is as breaking
// as a changed function signature.
func typeDeclarations(fileSet *token.FileSet, pkg string, spec *ast.TypeSpec) []string {
	name := spec.Name.Name
	declarations := []string{fmt.Sprintf("%s type %s %s", pkg, name, typeKind(spec.Type))}
	switch underlying := spec.Type.(type) {
	case *ast.StructType:
		for _, field := range underlying.Fields.List {
			rendered := render(fileSet, field.Type)
			if len(field.Names) == 0 {
				declarations = append(declarations, fmt.Sprintf("%s field %s.%s %s", pkg, name, strings.TrimLeft(rendered, "*"), rendered))
				continue
			}
			for _, fieldName := range field.Names {
				if !fieldName.IsExported() {
					continue
				}
				declarations = append(declarations, fmt.Sprintf("%s field %s.%s %s", pkg, name, fieldName.Name, rendered))
			}
		}
	case *ast.InterfaceType:
		for _, method := range underlying.Methods.List {
			rendered := render(fileSet, method.Type)
			if len(method.Names) == 0 {
				declarations = append(declarations, fmt.Sprintf("%s embeds %s.%s", pkg, name, rendered))
				continue
			}
			for _, methodName := range method.Names {
				if !methodName.IsExported() {
					continue
				}
				declarations = append(declarations, fmt.Sprintf("%s interface %s.%s%s", pkg, name, methodName.Name, strings.TrimPrefix(rendered, "func")))
			}
		}
	}
	return declarations
}

func typeKind(expression ast.Expr) string {
	switch expression.(type) {
	case *ast.StructType:
		return "struct"
	case *ast.InterfaceType:
		return "interface"
	case *ast.FuncType:
		return "func"
	default:
		return "="
	}
}

// render prints a syntax node in its canonical single-line form.
func render(fileSet *token.FileSet, node ast.Node) string {
	var buffer bytes.Buffer
	if err := printer.Fprint(&buffer, fileSet, node); err != nil {
		return "<unprintable>"
	}
	return strings.Join(strings.Fields(buffer.String()), " ")
}
