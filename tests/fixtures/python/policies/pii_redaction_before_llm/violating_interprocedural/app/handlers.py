"""Interprocedural violation: source in get_user, sink in call_llm,
no guard anywhere on the path. fetch_summary is the common ancestor."""
import anthropic


def get_user(user_id: str) -> dict:
    return load_user(user_id)


def load_user(user_id: str) -> dict:
    return {"id": user_id, "email": "x@example.com"}


def call_llm(payload: dict) -> str:
    return anthropic.messages.create(model="claude", input=payload)


def fetch_summary(user_id: str) -> str:
    user = get_user(user_id)
    return call_llm(user)
