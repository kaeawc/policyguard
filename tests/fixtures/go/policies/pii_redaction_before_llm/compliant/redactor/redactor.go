//go:build policyguard_fixture

package redactor

func Redact(user map[string]string) map[string]string {
	out := make(map[string]string, len(user))
	for k := range user {
		out[k] = "***"
	}
	return out
}
