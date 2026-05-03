import logging

from app import redactor, users


def report(user_id: str) -> None:
    user = users.load_user(user_id)
    safe = redactor.redact(user)
    logging.info(safe)
