package com.example.app;

import com.example.anthropic.Anthropic;

public class Handler {
    private final Anthropic client;

    public Handler(Anthropic client) {
        this.client = client;
    }

    public String summarize(String userId) {
        var user = loadUser(userId);
        return client.messagesCreate(user);
    }

    private java.util.Map<String, String> loadUser(String userId) {
        return java.util.Map.of("id", userId, "email", "x@example.com");
    }
}
