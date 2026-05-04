// Package lsp implements a minimal Language Server Protocol server
// for policyguard. It speaks JSON-RPC 2.0 over stdio with the small
// subset of LSP methods needed to publish diagnostics:
//
//	initialize, initialized, shutdown, exit
//	textDocument/didOpen, textDocument/didSave, textDocument/didChange
//	textDocument/publishDiagnostics  (server -> client)
//
// On didOpen and didSave the server re-analyses the workspace and
// publishes diagnostics for every file with findings. didChange is
// accepted but ignored (no in-memory analysis yet) — the user must
// save to refresh.
package lsp

import "encoding/json"

// Request / response envelopes ---------------------------------------

type rpcMessage struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Initialize ----------------------------------------------------------

type initializeParams struct {
	RootURI          string            `json:"rootUri"`
	WorkspaceFolders []workspaceFolder `json:"workspaceFolders"`
}

type workspaceFolder struct {
	URI  string `json:"uri"`
	Name string `json:"name"`
}

type initializeResult struct {
	Capabilities serverCapabilities `json:"capabilities"`
	ServerInfo   *serverInfo        `json:"serverInfo,omitempty"`
}

type serverCapabilities struct {
	TextDocumentSync   int  `json:"textDocumentSync"` // 1 = full
	DiagnosticProvider bool `json:"diagnosticProvider,omitempty"`
}

type serverInfo struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

// Document notifications ----------------------------------------------

type didOpenParams struct {
	TextDocument textDocumentItem `json:"textDocument"`
}

type didSaveParams struct {
	TextDocument textDocumentIdentifier `json:"textDocument"`
}

type textDocumentItem struct {
	URI        string `json:"uri"`
	LanguageID string `json:"languageId"`
	Version    int    `json:"version"`
}

type textDocumentIdentifier struct {
	URI string `json:"uri"`
}

// Diagnostic publishing -----------------------------------------------

type publishDiagnosticsParams struct {
	URI         string       `json:"uri"`
	Diagnostics []Diagnostic `json:"diagnostics"`
}

// Diagnostic mirrors the LSP Diagnostic structure. Severity values
// are: 1=error, 2=warning, 3=info, 4=hint.
type Diagnostic struct {
	Range    Range  `json:"range"`
	Severity int    `json:"severity"`
	Code     string `json:"code,omitempty"`
	Source   string `json:"source,omitempty"`
	Message  string `json:"message"`
}

// Range identifies a contiguous span in a text document. Both endpoints
// are zero-based.
type Range struct {
	Start Position `json:"start"`
	End   Position `json:"end"`
}

// Position is a zero-based (line, character) coordinate.
type Position struct {
	Line      int `json:"line"`
	Character int `json:"character"`
}
