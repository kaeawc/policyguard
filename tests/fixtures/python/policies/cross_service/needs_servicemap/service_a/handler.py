"""Service A: loads PII and posts it to service B over the rpc client."""
import rpc


def fetch_user(user_id: str) -> dict:
    user = load_user(user_id)
    rpc.post("/llm", body=user)
    return user


def load_user(user_id: str) -> dict:
    return {"id": user_id, "email": "x@example.com"}
