package lsp

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"

	"github.com/kaeawc/policyguard/internal/callgraph"
	"github.com/kaeawc/policyguard/internal/engine"
	"github.com/kaeawc/policyguard/internal/policy"
	"github.com/kaeawc/policyguard/internal/scanner"
)

// Config carries the policyguard knobs the LSP server needs to run an
// analysis. Mirrors the `check` subcommand's flags.
type Config struct {
	PoliciesDir string
	Lang        scanner.Language
	Version     string
}

// Analyzer is the analysis pipeline the server invokes on each
// didOpen/didSave. Tests inject a fake; production wires this to
// runAnalysis below.
type Analyzer interface {
	Run(ctx context.Context, workspaceRoot string) ([]engine.Finding, error)
}

// Server speaks LSP over r/w. Use Run to start the message loop.
type Server struct {
	cfg      Config
	r        *bufio.Reader
	w        io.Writer
	logf     func(format string, a ...any)
	analyze  Analyzer
	wmu      sync.Mutex
	root     string
	shutdown bool
}

// NewServer wires a Server with the given config and a default
// analyzer. r/w are typically os.Stdin/os.Stdout; logf is a stderr
// logger (use a no-op in tests).
func NewServer(cfg Config, r io.Reader, w io.Writer, logf func(string, ...any)) *Server {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	s := &Server{
		cfg:  cfg,
		r:    bufio.NewReader(r),
		w:    w,
		logf: logf,
	}
	s.analyze = &defaultAnalyzer{cfg: cfg}
	return s
}

// SetAnalyzer overrides the analyzer (test hook).
func (s *Server) SetAnalyzer(a Analyzer) { s.analyze = a }

// Run pumps messages until shutdown/EOF. Returns nil on clean exit.
func (s *Server) Run(ctx context.Context) error {
	for {
		msg, err := readMessage(s.r)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if err := s.dispatch(ctx, msg); err != nil {
			s.logf("dispatch %s: %v", msg.Method, err)
		}
		if s.shutdown && msg.Method == "exit" {
			return nil
		}
	}
}

func (s *Server) dispatch(ctx context.Context, msg *rpcMessage) error {
	switch msg.Method {
	case "initialize":
		return s.onInitialize(msg)
	case "initialized":
		return nil
	case "shutdown":
		s.shutdown = true
		return s.reply(msg, nil)
	case "exit":
		return nil
	case "textDocument/didOpen", "textDocument/didSave":
		return s.onDidOpenOrSave(ctx, msg)
	case "textDocument/didChange":
		// Accepted; no in-memory analysis yet — wait for save.
		return nil
	default:
		return s.replyMethodNotFound(msg)
	}
}

func (s *Server) onInitialize(msg *rpcMessage) error {
	var p initializeParams
	if len(msg.Params) > 0 {
		_ = json.Unmarshal(msg.Params, &p)
	}
	root := pickRoot(p)
	if root != "" {
		s.root = uriToPath(root)
	}
	return s.reply(msg, initializeResult{
		Capabilities: serverCapabilities{
			TextDocumentSync:   1, // full
			DiagnosticProvider: true,
		},
		ServerInfo: &serverInfo{Name: "policyguard-lsp", Version: s.cfg.Version},
	})
}

func pickRoot(p initializeParams) string {
	if len(p.WorkspaceFolders) > 0 {
		return p.WorkspaceFolders[0].URI
	}
	return p.RootURI
}

func (s *Server) onDidOpenOrSave(ctx context.Context, msg *rpcMessage) error {
	if s.root == "" {
		return nil
	}
	findings, err := s.analyze.Run(ctx, s.root)
	if err != nil {
		s.logf("analysis: %v", err)
		return nil
	}
	groups := FindingsToDiagnostics(findings, s.root)
	for uri, diags := range groups {
		if err := s.publishDiagnostics(uri, diags); err != nil {
			return err
		}
	}
	// Also clear diagnostics on the focused file when it has none.
	uri := focusedURI(msg)
	if uri != "" {
		if _, ok := groups[uri]; !ok {
			if err := s.publishDiagnostics(uri, nil); err != nil {
				return err
			}
		}
	}
	return nil
}

func focusedURI(msg *rpcMessage) string {
	switch msg.Method {
	case "textDocument/didOpen":
		var p didOpenParams
		if err := json.Unmarshal(msg.Params, &p); err == nil {
			return p.TextDocument.URI
		}
	case "textDocument/didSave":
		var p didSaveParams
		if err := json.Unmarshal(msg.Params, &p); err == nil {
			return p.TextDocument.URI
		}
	}
	return ""
}

func (s *Server) publishDiagnostics(uri string, diags []Diagnostic) error {
	if diags == nil {
		diags = []Diagnostic{}
	}
	return s.notify("textDocument/publishDiagnostics", publishDiagnosticsParams{
		URI:         uri,
		Diagnostics: diags,
	})
}

func (s *Server) reply(msg *rpcMessage, result any) error {
	return s.send(rpcMessage{JSONRPC: "2.0", ID: msg.ID, Result: result})
}

func (s *Server) replyMethodNotFound(msg *rpcMessage) error {
	if len(msg.ID) == 0 {
		// Unknown notification — nothing to reply to.
		return nil
	}
	return s.send(rpcMessage{
		JSONRPC: "2.0",
		ID:      msg.ID,
		Error:   &rpcError{Code: -32601, Message: "method not found: " + msg.Method},
	})
}

func (s *Server) notify(method string, params any) error {
	body, err := json.Marshal(params)
	if err != nil {
		return err
	}
	return s.send(rpcMessage{JSONRPC: "2.0", Method: method, Params: body})
}

func (s *Server) send(msg rpcMessage) error {
	body, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	header := "Content-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n"
	s.wmu.Lock()
	defer s.wmu.Unlock()
	if _, err := io.WriteString(s.w, header); err != nil {
		return err
	}
	_, err = s.w.Write(body)
	return err
}

// readMessage parses one LSP message from r. Returns io.EOF when the
// stream cleanly ends.
func readMessage(r *bufio.Reader) (*rpcMessage, error) {
	contentLength := -1
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return nil, err
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		if strings.HasPrefix(line, "Content-Length:") {
			n, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "Content-Length:")))
			if err != nil {
				return nil, fmt.Errorf("bad Content-Length: %w", err)
			}
			contentLength = n
		}
	}
	if contentLength < 0 {
		return nil, errors.New("missing Content-Length header")
	}
	body := make([]byte, contentLength)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	var msg rpcMessage
	if err := json.Unmarshal(body, &msg); err != nil {
		return nil, fmt.Errorf("bad JSON-RPC body: %w", err)
	}
	return &msg, nil
}

// defaultAnalyzer wires the LSP server to the existing analysis
// pipeline: it loads policies from cfg.PoliciesDir, walks the
// workspace, builds the call graph, and runs every applicable policy
// through the engine. Identical to the `check` subcommand minus the
// renderer.
type defaultAnalyzer struct {
	cfg Config
}

func (a *defaultAnalyzer) Run(ctx context.Context, root string) ([]engine.Finding, error) {
	if a.cfg.PoliciesDir == "" {
		return nil, errors.New("lsp: policies dir not configured")
	}
	policies, err := policy.LoadDir(a.cfg.PoliciesDir)
	if err != nil {
		return nil, err
	}
	files, err := loadSourceTree(ctx, root, a.cfg.Lang)
	if err != nil {
		return nil, err
	}
	g := buildGraph(files, root, a.cfg.Lang)
	if g == nil {
		return nil, fmt.Errorf("lsp: language %q not supported", a.cfg.Lang)
	}
	var out []engine.Finding
	for _, p := range policies {
		if !applies(p, a.cfg.Lang) {
			continue
		}
		out = append(out, engine.Analyze(g, p)...)
	}
	return out, nil
}

func buildGraph(files []*scanner.File, root string, lang scanner.Language) *callgraph.Graph {
	switch lang {
	case scanner.LangPython:
		return callgraph.BuildPython(files, root)
	case scanner.LangTypeScript:
		return callgraph.BuildTypeScript(files, root)
	case scanner.LangGo:
		return callgraph.BuildGo(files, root)
	case scanner.LangJava:
		return callgraph.BuildJava(files, root)
	default:
		return nil
	}
}

func applies(p *policy.Policy, lang scanner.Language) bool {
	for _, l := range p.Languages {
		if string(l) == string(lang) {
			return true
		}
	}
	return false
}
