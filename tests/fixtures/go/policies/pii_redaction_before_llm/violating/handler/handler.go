//go:build policyguard_fixture

package handler

import (
	llm "github.com/anthropic/anthropic-sdk-go"
)

func SummarizeUser(userID string) string {
	user := loadUser(userID)
	return llm.Messages.Create(user)
}

func loadUser(userID string) map[string]string {
	return map[string]string{"id": userID, "email": "x@example.com"}
}
