"""Source via field-access: reads user.email then sends to LLM."""
import anthropic


class User:
    email: str


def summarize(user: User) -> str:
    return anthropic.messages.create(model="claude", input=user.email)
