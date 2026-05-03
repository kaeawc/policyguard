from app import redactor
import anthropic


def summarize_user(user_id: str) -> str:
    user = load_user(user_id)
    safe = redactor.redact(user)
    return anthropic.messages.create(model="claude", input=safe)


def load_user(user_id: str) -> dict:
    return {"id": user_id, "email": "x@example.com"}
