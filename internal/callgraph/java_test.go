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

func TestBuildJava_ReceiverTypedField(t *testing.T) {
	src := `package com.example.app;
import com.example.redactor.Redactor;

public class Handler {
    private final Redactor redactor;
    public Handler(Redactor r) { this.redactor = r; }
    public String f() { return redactor.redact("x"); }
}
`
	g := BuildJava([]*scanner.File{parseJava(t, src)}, "")
	calls := g.Calls["com.example.app.Handler.f"]
	if len(calls) != 1 {
		t.Fatalf("calls = %+v", calls)
	}
	if string(calls[0].Callee) != "com.example.redactor.Redactor.redact" {
		t.Errorf("Callee = %q, want canonical FQN", calls[0].Callee)
	}
	if calls[0].Raw != "redactor.redact" {
		t.Errorf("Raw = %q, want 'redactor.redact' (raw fallback preserved)", calls[0].Raw)
	}
}

func TestBuildJava_ReceiverTypedParameter(t *testing.T) {
	src := `package com.example.app;
import com.example.redactor.Redactor;

public class Handler {
    public String f(Redactor r) { return r.redact("x"); }
}
`
	g := BuildJava([]*scanner.File{parseJava(t, src)}, "")
	calls := g.Calls["com.example.app.Handler.f"]
	if len(calls) != 1 || string(calls[0].Callee) != "com.example.redactor.Redactor.redact" {
		t.Errorf("calls = %+v", calls)
	}
}

func TestBuildJava_ReceiverTypedLocal(t *testing.T) {
	src := `package com.example.app;
import com.example.redactor.Redactor;

public class Handler {
    public String f() {
        Redactor r = makeRedactor();
        return r.redact("x");
    }
    private Redactor makeRedactor() { return null; }
}
`
	g := BuildJava([]*scanner.File{parseJava(t, src)}, "")
	calls := g.Calls["com.example.app.Handler.f"]
	// Two calls: makeRedactor() and r.redact(). Find r.redact().
	var rRedact *CallSite
	for _, c := range calls {
		if c.Raw == "r.redact" {
			rRedact = c
		}
	}
	if rRedact == nil {
		t.Fatalf("missing r.redact call; got %+v", calls)
	}
	if string(rRedact.Callee) != "com.example.redactor.Redactor.redact" {
		t.Errorf("Callee = %q", rRedact.Callee)
	}
}

func TestBuildJava_ReceiverTypedSamePackage(t *testing.T) {
	// Field type isn't imported because it's in the same package — the
	// resolver should fall back to <pkg>.<TypeName>.<method>.
	src := `package com.example.app;
public class Handler {
    private final Local local;
    public Handler(Local l) { this.local = l; }
    public String f() { return local.run(); }
}
`
	g := BuildJava([]*scanner.File{parseJava(t, src)}, "")
	calls := g.Calls["com.example.app.Handler.f"]
	if len(calls) != 1 || string(calls[0].Callee) != "com.example.app.Local.run" {
		t.Errorf("calls = %+v", calls)
	}
}

func TestBuildJava_RawAlwaysPreserved(t *testing.T) {
	// Even when receiver-type tracking is active, the original
	// expression text stays in Raw so policies that match by raw
	// (e.g. `calls: client.messagesCreate`) keep working.
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
		t.Errorf("Raw = %q, want 'client.messagesCreate'", calls[0].Raw)
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
