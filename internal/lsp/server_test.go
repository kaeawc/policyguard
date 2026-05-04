package lsp

import (
	"bytes"
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/kaeawc/policyguard/internal/callgraph"
	"github.com/kaeawc/policyguard/internal/engine"
	"github.com/kaeawc/policyguard/internal/policy"
)

// fakeAnalyzer feeds predetermined findings to the server, so tests
// don't need to set up a real workspace.
type fakeAnalyzer struct {
	findings []engine.Finding
	err      error
}

func (a *fakeAnalyzer) Run(ctx context.Context, root string) ([]engine.Finding, error) {
	return a.findings, a.err
}

func encodeRPC(t *testing.T, msg map[string]any) []byte {
	t.Helper()
	body, err := json.Marshal(msg)
	if err != nil {
		t.Fatal(err)
	}
	return []byte("Content-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + string(body))
}

func parseAllRPC(t *testing.T, raw []byte) []map[string]any {
	t.Helper()
	var out []map[string]any
	src := raw
	for len(src) > 0 {
		// Find header end.
		idx := bytes.Index(src, []byte("\r\n\r\n"))
		if idx < 0 {
			break
		}
		header := string(src[:idx])
		src = src[idx+4:]
		var length int
		for _, line := range strings.Split(header, "\r\n") {
			if strings.HasPrefix(line, "Content-Length:") {
				n, _ := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "Content-Length:")))
				length = n
			}
		}
		if length == 0 || length > len(src) {
			break
		}
		var msg map[string]any
		if err := json.Unmarshal(src[:length], &msg); err != nil {
			t.Fatalf("decode: %v\nbody=%s", err, src[:length])
		}
		out = append(out, msg)
		src = src[length:]
	}
	return out
}

func TestServer_InitializeAdvertisesCapabilities(t *testing.T) {
	in := &bytes.Buffer{}
	in.Write(encodeRPC(t, map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params": map[string]any{
			"rootUri": "file:///tmp/proj",
		},
	}))
	in.Write(encodeRPC(t, map[string]any{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  "shutdown",
	}))
	in.Write(encodeRPC(t, map[string]any{
		"jsonrpc": "2.0",
		"method":  "exit",
	}))

	out := &bytes.Buffer{}
	srv := NewServer(Config{}, in, out, nil)
	srv.SetAnalyzer(&fakeAnalyzer{})
	if err := srv.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	msgs := parseAllRPC(t, out.Bytes())
	if len(msgs) < 2 {
		t.Fatalf("got %d responses, want >=2: %+v", len(msgs), msgs)
	}
	caps := msgs[0]["result"].(map[string]any)["capabilities"].(map[string]any)
	if int(caps["textDocumentSync"].(float64)) != 1 {
		t.Errorf("textDocumentSync = %v", caps["textDocumentSync"])
	}
	if caps["diagnosticProvider"] != true {
		t.Errorf("diagnosticProvider missing/false")
	}
}

func TestServer_PublishesDiagnosticsOnDidSave(t *testing.T) {
	in := &bytes.Buffer{}
	in.Write(encodeRPC(t, map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "initialize",
		"params": map[string]any{"rootUri": "file:///tmp/proj"},
	}))
	in.Write(encodeRPC(t, map[string]any{
		"jsonrpc": "2.0", "method": "textDocument/didSave",
		"params": map[string]any{
			"textDocument": map[string]any{"uri": "file:///tmp/proj/app.py"},
		},
	}))
	in.Write(encodeRPC(t, map[string]any{
		"jsonrpc": "2.0", "id": 99, "method": "shutdown",
	}))
	in.Write(encodeRPC(t, map[string]any{"jsonrpc": "2.0", "method": "exit"}))

	out := &bytes.Buffer{}
	srv := NewServer(Config{}, in, out, nil)
	srv.SetAnalyzer(&fakeAnalyzer{
		findings: []engine.Finding{{
			PolicyID: "pii-redaction-before-llm",
			Severity: policy.SeverityError,
			Message:  "User PII reaches LLM call.",
			Function: callgraph.FQN("app.handler.fetch"),
			Source:   engine.FindingSite{Path: "/tmp/proj/app.py", Line: 7},
			Sink:     engine.FindingSite{Path: "/tmp/proj/app.py", Line: 9},
		}},
	})
	if err := srv.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	msgs := parseAllRPC(t, out.Bytes())

	var publish map[string]any
	for _, m := range msgs {
		if m["method"] == "textDocument/publishDiagnostics" {
			publish = m
			break
		}
	}
	if publish == nil {
		t.Fatalf("no publishDiagnostics in output: %+v", msgs)
	}
	params := publish["params"].(map[string]any)
	if params["uri"].(string) != "file:///tmp/proj/app.py" {
		t.Errorf("uri = %v", params["uri"])
	}
	diags := params["diagnostics"].([]any)
	if len(diags) != 1 {
		t.Fatalf("diagnostics = %d", len(diags))
	}
	d := diags[0].(map[string]any)
	if int(d["severity"].(float64)) != 1 {
		t.Errorf("severity = %v, want 1 (error)", d["severity"])
	}
	if d["code"].(string) != "pii-redaction-before-llm" {
		t.Errorf("code = %v", d["code"])
	}
	rng := d["range"].(map[string]any)
	startLine := int(rng["start"].(map[string]any)["line"].(float64))
	if startLine != 6 { // 0-based for line 7
		t.Errorf("start.line = %d, want 6", startLine)
	}
}

func TestPathToURI(t *testing.T) {
	tests := []struct {
		path, root, want string
	}{
		{"/abs/file.py", "", "file:///abs/file.py"},
		{"rel/file.py", "/root", "file:///root/rel/file.py"},
		{"file:///already.py", "", "file:///already.py"},
	}
	for _, tc := range tests {
		got := pathToURI(tc.path, tc.root)
		if got != tc.want {
			t.Errorf("pathToURI(%q, %q) = %q, want %q", tc.path, tc.root, got, tc.want)
		}
	}
}

func TestSeverityFor(t *testing.T) {
	cases := map[policy.Severity]int{
		policy.SeverityError:   1,
		policy.SeverityWarning: 2,
		policy.SeverityInfo:    3,
	}
	for sev, want := range cases {
		if got := severityFor(sev); got != want {
			t.Errorf("severityFor(%q) = %d, want %d", sev, got, want)
		}
	}
}
