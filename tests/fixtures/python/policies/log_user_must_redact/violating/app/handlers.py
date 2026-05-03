import logging

from app import users


def report(user_id: str) -> None:
    user = users.load_user(user_id)
    logging.info(user)
