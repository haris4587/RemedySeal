"""Verify an exported get_review JSON receipt, hashes and optional fixture files."""
import hashlib
import json
from pathlib import Path
import sys


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def verify(receipt, evidence_dir=None):
    package = receipt['package']
    assert sha(canonical(package).encode()) == receipt['package_hash'], 'package hash mismatch'
    previous = ''
    for index, record in enumerate(receipt['history'], 1):
        data = dict(record)
        decision_hash = data.pop('decision_hash')
        assert decision_hash == sha(canonical(data).encode()), 'decision hash mismatch'
        assert data['package_hash'] == receipt['package_hash'], 'record package mismatch'
        assert data['previous_hash'] == previous and data['attempt'] == index, 'chain mismatch'
        assert data['owner'] == receipt['owner'], 'owner mismatch'
        previous = decision_hash
    if evidence_dir:
        for s in package['sources']:
            path = Path(evidence_dir) / s['url'].rsplit('/', 1)[-1]
            body = path.read_bytes()
            assert len(body) == s['bytes'] and sha(body) == s['sha256'], 'source mismatch: ' + str(path)
    return previous


if __name__ == '__main__':
    result = verify(json.loads(Path(sys.argv[1]).read_text()), sys.argv[2] if len(sys.argv) > 2 else None)
    print('Verified package and decision chain:', result)
