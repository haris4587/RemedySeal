from pathlib import Path


def load_report(root, name):
    base = Path(root).resolve()
    target = (base / name).resolve()
    # This partial patch rejects absolute input but retains the vulnerable prefix check.
    if Path(name).is_absolute():
        raise ValueError('absolute report name')
    if not str(target).startswith(str(base)):
        raise ValueError('outside reports')
    return target.read_text()
