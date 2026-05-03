from app import input as user_input


def write_report(name: str) -> None:
    path = user_input.user_path(name)
    with open(path, "w") as f:
        f.write("ok")
