"""Executable counterexample: partial patch blocks absolute paths, misses sibling traversal."""
import importlib.util
from pathlib import Path
from tempfile import TemporaryDirectory


def run():
    spec = importlib.util.spec_from_file_location('patch', Path(__file__).with_name('patch.py'))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    with TemporaryDirectory() as d:
        root = Path(d) / 'reports'
        root.mkdir()
        (root / 'nested').mkdir()
        (root / 'nested' / 'ok.txt').write_text('legitimate report')
        sibling = Path(d) / 'reports-secret'
        sibling.mkdir()
        (sibling / 'token.txt').write_text('synthetic secret')
        assert mod.load_report(root, 'nested/ok.txt') == 'legitimate report'
        try:
            mod.load_report(root, str(sibling / 'token.txt'))
        except ValueError:
            pass
        else:
            raise AssertionError('absolute path should be blocked')
        # The relative bypass remains exploitable: this assertion proves the defect, not a fix.
        assert mod.load_report(root, '../reports-secret/token.txt') == 'synthetic secret'
    print('3 assertions passed: normal nested read, absolute blocked, relative sibling bypass persists')


if __name__ == '__main__':
    run()
