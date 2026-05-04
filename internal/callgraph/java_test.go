package callgraph

import (
	"context"
	"testing"

	"github.com/kaeawc/policyguard/internal/scanner"
)

func parseJava(t *testing.T, src string) *scanner.File {
	t.Helper()
	f, err := scanner.ParseBytes(context.Background(), "X.java", scanner.LangJava, []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestBuildJava_PackageQualifiedFQN(t *testing.T) {
	src := `package com.example.app;
public class Handler {
    public String summarize(String id) { return loadUser(id); }
    private String loadUser(String id) { return id; }
}
`
	g := BuildJava([]*scanner.File{parseJava(t, src)}, "")
	for _, want := range []FQN{
		"com.example.app.Handler.summarize",
		"com.example.app.Handler.loadUser",
	} {
		if _, ok := g.Funcs[want]; !ok {
			t.Errorf("missing %q; have %v", want, funcKeys(g))
		}
	}
}

func TestBuildJava_BareCallResolvesToEnclosingClass(t *testing.T) {
	src := `package com.example.app;
public class Handler {
    public String summarize(String id) { return loadUser(id); }
    private String loadUser(String id) { return id; }
}
`
	g := BuildJava([]*scanner.File{parseJava(t, src)}, "")
	calls := g.Calls["com.example.app.Handler.summarize"]
	if len(calls) != 1 {
		t.Fatalf("calls = %+v", calls)
	}
	if string(calls[0].Callee) != "com.example.app.Handler.loadUser" {
		t.Errorf("Callee = %q", calls[0].Callee)
	}
}

func TestBuildJava_ImportResolution(t *testing.T) {
	src := `package com.example.app;
import com.example.redactor.Redactor;

public class Handler {
    public String f() { return Redactor.redact("x"); }
}
`
	g := BuildJava([]*scanner.File{parseJava(t, src)}, "")
	calls := g.Calls["com.example.app.Handler.f"]
	if len(calls) != 1 {
		t.Fatalf("calls = %+v", calls)
	}
	if string(calls[0].Callee) != "com.example.redactor.Redactor.redact" {
		t.Errorf("Callee = %q", calls[0].Callee)
	}
}

func TestBuildJava_OnDemandImportSkipped(t *testing.T) {
	src := `package com.example.app;
import com.example.redactor.*;

public class Handler {
    public String f() { return Redactor.redact("x"); }
}
`
	g := BuildJava([]*scanner.File{parseJava(t, src)}, "")
	calls := g.Calls["com.example.app.Handler.f"]
	// On-demand imports are skipped, so the Redactor call falls back
	// to module-local resolution.
	if len(calls) != 1 {
		t.Fatalf("calls = %+v", calls)
	}
	if string(calls[0].Callee) != "com.example.app.Redactor.redact" {
		t.Errorf("Callee = %q (on-demand imports unsupported, want module-local)", calls[0].Callee)
	}
}

func TestBuildJava_VariableInvocationFallsBackToRaw(t *testing.T) {
	src := `package com.example.app;
public class Handler {
    private final Anthropic client = null;
    public String f() { return client.messagesCreate("x"); }
}
`
	g := BuildJava([]*scanner.File{parseJava(t, src)}, "")
	calls := g.Calls["com.example.app.Handler.f"]
	if len(calls) == 0 {
		t.Fatal("no calls")
	}
	if calls[0].Raw != "client.messagesCreate" {
		t.Errorf("Raw = %q, want 'client.messagesCreate' (raw fallback so policies can match without receiver-type tracking)", calls[0].Raw)
	}
}

func TestBuildJava_ConstructorRegistered(t *testing.T) {
	src := `package com.example.app;
public class Handler {
    public Handler(String x) {}
}
`
	g := BuildJava([]*scanner.File{parseJava(t, src)}, "")
	if _, ok := g.Funcs["com.example.app.Handler.Handler"]; !ok {
		t.Errorf("missing constructor FQN; have %v", funcKeys(g))
	}
}
