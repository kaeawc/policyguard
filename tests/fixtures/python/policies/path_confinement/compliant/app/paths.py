import os


def confine_to_workspace(path: str) -> str:
    abs_path = os.path.abspath(path)
    workspace = os.path.abspath("./uploads")
    if not abs_path.startswith(workspace):
        raise ValueError("path escapes workspace")
    return abs_path
