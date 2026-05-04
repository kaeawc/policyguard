"""Service B: receives the request and forwards directly to the LLM."""
import anthropic


def handle_llm(payload: dict) -> str:
    return anthropic.messages.create(model="claude", input=payload)
