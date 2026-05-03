from app import input as user_input
from app import paths


def write_report(name: str) -> None:
    path = user_input.user_path(name)
    safe = paths.confine_to_workspace(path)
    with open(safe, "w") as f:
        f.write("ok")
