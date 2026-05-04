"""Sink uses positional args, so the autofix patch is generated."""
import anthropic


def summarize_user(user_id: str) -> str:
    user = load_user(user_id)
    return anthropic.messages.create(user)


def load_user(user_id: str) -> dict:
    return {"id": user_id, "email": "x@example.com"}
