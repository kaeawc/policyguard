package com.example.app;

import com.example.redactor.Redactor;
import com.example.anthropic.Anthropic;

public class Handler {
    private final Redactor redactor;
    private final Anthropic client;

    public Handler(Redactor redactor, Anthropic client) {
        this.redactor = redactor;
        this.client = client;
    }

    public String summarize(String userId) {
        var user = loadUser(userId);
        var safe = redactor.redact(user);
        return client.messagesCreate(safe);
    }

    private java.util.Map<String, String> loadUser(String userId) {
        return java.util.Map.of("id", userId, "email", "x@example.com");
    }
}
