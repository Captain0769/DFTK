import hashlib
from pathlib import Path


ALGORITHMS = ("md5", "sha1", "sha256", "sha512")


def hash_file(path, chunk_size=1024 * 1024):
    """Hash a file in chunks so large evidence files are not loaded in memory."""
    digesters = {algorithm: hashlib.new(algorithm) for algorithm in ALGORITHMS}
    with Path(path).open("rb") as evidence_file:
        while chunk := evidence_file.read(chunk_size):
            for digester in digesters.values():
                digester.update(chunk)
    return {algorithm: digester.hexdigest() for algorithm, digester in digesters.items()}


def compare_hashes(recorded, current):
    """Return per-algorithm comparisons and an overall integrity status."""
    results = {}
    for algorithm in ALGORITHMS:
        try:
            expected = recorded[algorithm]
        except (KeyError, IndexError):
            expected = ""
        try:
            actual = current[algorithm]
        except (KeyError, IndexError):
            actual = ""
        results[algorithm] = (
            "Match" if expected and actual and expected.casefold() == actual.casefold()
            else "Mismatch"
        )
    status = "Verified" if all(value == "Match" for value in results.values()) else "Mismatch"
    return status, results
