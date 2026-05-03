package callgraph

import (
	"context"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kaeawc/policyguard/internal/scanner"
)

func loadPythonDir(t *testing.T, root string) []*scanner.File {
	t.Helper()
	var files []*scanner.File
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".py") {
			return nil
		}
		f, perr := scanner.ParseFile(context.Background(), path, scanner.LangPython)
		if perr != nil {
			return perr
		}
		files = append(files, f)
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	return files
}

func TestBuildPython_BasicReachability(t *testing.T) {
	root := "../../tests/fixtures/python/callgraph_basic"
	files := loadPythonDir(t, root)
	if len(files) == 0 {
		t.Fatalf("no fixture files found under %s", root)
	}

	g := BuildPython(files, root)

	wantFuncs := []FQN{
		"app.handlers.fetch_user_summary",
		"app.handlers.load_user",
		"app.redactor.redact",
	}
	for _, w := range wantFuncs {
		if _, ok := g.Funcs[w]; !ok {
			t.Errorf("missing function %q in graph; have %v", w, keys(g.Funcs))
		}
	}

	calls := g.Calls["app.handlers.fetch_user_summary"]
	if len(calls) == 0 {
		t.Fatalf("expected calls under fetch_user_summary, got none")
	}
	wantCallees := map[FQN]bool{
		"app.handlers.load_user":    false,
		"app.redactor.redact":       false,
		"anthropic.messages.create": false,
	}
	for _, c := range calls {
		if _, ok := wantCallees[c.Callee]; ok {
			wantCallees[c.Callee] = true
		}
	}
	for callee, seen := range wantCallees {
		if !seen {
			t.Errorf("expected callee %q under fetch_user_summary; calls=%v", callee, calls)
		}
	}
}

func TestPythonModuleFQN(t *testing.T) {
	tests := []struct {
		path, root string
		want       FQN
	}{
		{"app/handlers.py", "", "app.handlers"},
		{"/repo/app/handlers.py", "/repo", "app.handlers"},
		{"/repo/app/__init__.py", "/repo", "app"},
		{"/repo/single.py", "/repo", "single"},
	}
	for _, tc := range tests {
		got := pythonModuleFQN(tc.path, tc.root)
		if got != tc.want {
			t.Errorf("pythonModuleFQN(%q, %q) = %q, want %q", tc.path, tc.root, got, tc.want)
		}
	}
}

func keys(m map[FQN]*FuncNode) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, string(k))
	}
	return out
}
