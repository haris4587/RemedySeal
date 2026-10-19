from pathlib import Path


def load_report(root, name):
    base = Path(root).resolve()
    target = (base / name).resolve()
    if not str(target).startswith(str(base)):
        raise ValueError('outside reports')
    return target.read_text()
