package lsp

import (
	"net/url"
	"path/filepath"
	"strings"

	"github.com/kaeawc/policyguard/internal/engine"
	"github.com/kaeawc/policyguard/internal/policy"
)

// FindingsToDiagnostics groups engine findings by URI and converts
// them to LSP Diagnostic objects. The source location of each finding
// is the diagnostic anchor; the sink and message are folded into the
// rendered text. workspaceRoot is used to resolve relative source
// paths into absolute file:// URIs.
func FindingsToDiagnostics(findings []engine.Finding, workspaceRoot string) map[string][]Diagnostic {
	out := make(map[string][]Diagnostic)
	for _, f := range findings {
		uri := pathToURI(f.Source.Path, workspaceRoot)
		out[uri] = append(out[uri], findingDiagnostic(f))
	}
	return out
}

func findingDiagnostic(f engine.Finding) Diagnostic {
	line := zeroBasedLine(f.Source.Line)
	msg := f.Message
	if msg == "" {
		msg = "policy violation"
	}
	if f.Sink.Path != "" {
		// Append sink hint so the diagnostic is self-contained when
		// the editor doesn't surface relatedInformation.
		msg = msg + "\n  → sink at " + f.Sink.Path + ":" + itoa(f.Sink.Line)
	}
	if f.Fix != nil && f.Fix.Suggestion != "" {
		msg = msg + "\n  fix: " + f.Fix.Suggestion
	}
	return Diagnostic{
		Range: Range{
			Start: Position{Line: line, Character: 0},
			End:   Position{Line: line, Character: 9999},
		},
		Severity: severityFor(f.Severity),
		Code:     f.PolicyID,
		Source:   "policyguard",
		Message:  msg,
	}
}

// zeroBasedLine converts policyguard's 1-based line numbers to LSP's
// zero-based line numbers, clamping at zero.
func zeroBasedLine(line int) int {
	if line <= 0 {
		return 0
	}
	return line - 1
}

func severityFor(s policy.Severity) int {
	switch s {
	case policy.SeverityError:
		return 1
	case policy.SeverityWarning:
		return 2
	case policy.SeverityInfo:
		return 3
	default:
		return 2
	}
}

// pathToURI produces a file:// URI from a finding's stored path.
// Absolute paths are encoded directly; relative paths are anchored to
// workspaceRoot. Paths that already look like a URI pass through.
func pathToURI(path, workspaceRoot string) string {
	if strings.HasPrefix(path, "file://") || strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return path
	}
	abs := path
	if !filepath.IsAbs(abs) && workspaceRoot != "" {
		abs = filepath.Join(workspaceRoot, abs)
	}
	abs = filepath.ToSlash(abs)
	if !strings.HasPrefix(abs, "/") {
		abs = "/" + abs
	}
	u := url.URL{Scheme: "file", Path: abs}
	return u.String()
}

// uriToPath turns a file:// URI back into a filesystem path. Returns
// the input unchanged for non-file schemes.
func uriToPath(uri string) string {
	if !strings.HasPrefix(uri, "file://") {
		return uri
	}
	u, err := url.Parse(uri)
	if err != nil {
		return strings.TrimPrefix(uri, "file://")
	}
	return u.Path
}

// itoa is a tiny stdlib-free integer formatter to avoid pulling fmt
// into the diagnostic hot path.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
