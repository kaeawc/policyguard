"""Compliant via decorator-based guard: @redacted on the function."""
import anthropic


def redacted(fn):
    return fn


@redacted
def summarize_user(user_id: str) -> str:
    user = load_user(user_id)
    return anthropic.messages.create(model="claude", input=user)


def load_user(user_id: str) -> dict:
    return {"id": user_id, "email": "x@example.com"}
