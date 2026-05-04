//go:build policyguard_fixture

package handler

import (
	"redactor"

	llm "github.com/anthropic/anthropic-sdk-go"
)

func SummarizeUser(userID string) string {
	user := loadUser(userID)
	safe := redactor.Redact(user)
	return llm.Messages.Create(safe)
}

func loadUser(userID string) map[string]string {
	return map[string]string{"id": userID, "email": "x@example.com"}
}
