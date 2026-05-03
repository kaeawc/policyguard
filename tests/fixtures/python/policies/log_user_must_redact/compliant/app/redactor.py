def redact(user: dict) -> dict:
    return {k: "***" for k in user}
