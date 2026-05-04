package callgraph

import (
	"reflect"
	"testing"
)

func TestParseSuppression(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []string
	}{
		{"py inline", "# policyguard: ignore foo", []string{"foo"}},
		{"py csv", "#policyguard: ignore foo, bar, baz", []string{"foo", "bar", "baz"}},
		{"slash inline", "// policyguard: ignore one", []string{"one"}},
		{"block", "/* policyguard: ignore-all */", []string{"*"}},
		{"explicit star", "// policyguard: ignore *", []string{"*"}},
		{"not a directive", "// just a regular comment", nil},
		{"empty ids", "// policyguard: ignore  ", nil},
		{"spaces inside", "//  policyguard:   ignore    foo  ", []string{"foo"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseSuppression(tc.in)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("parseSuppression(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}
