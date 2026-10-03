"""Exercise an installed console entry on generated inert Prefetch bytes away from source."""

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))


def main():
    from fixtures import example
    import prefetch_evidence_review

    assert ROOT / "src" not in Path(prefetch_evidence_review.__file__).parents
    binary = Path(sys.executable).parent / "prefetch-evidence-review"
    with tempfile.TemporaryDirectory() as name:
        folder = Path(name).resolve()
        sample = folder / "PRIVATE_INPUT_PATH.pf"
        raw, _ = example()
        sample.write_bytes(raw)
        damaged = folder / "damaged.pf"
        damaged.write_bytes(raw[:-1])
        link = folder / "link.pf"
        link.symlink_to(sample)
        cases = [
            ([str(sample)], 0, False),
            ([str(sample), "--reveal-strings"], 0, True),
            ([str(damaged), "--reveal-strings"], 2, False),
            ([str(folder / "PRIVATE_INPUT_PATH_MISSING")], 2, False),
            ([str(sample), "--PRIVATE_ARGUMENT"], 2, False),
            ([str(link)], 2, False),
            ([str(folder) + "/../" + folder.name + "/" + sample.name], 2, False),
        ]
        for args, expected, reveal in cases:
            result = subprocess.run(
                [str(binary), *args], cwd=folder, capture_output=True, text=True, timeout=10
            )
            assert result.returncode == expected and not result.stderr
            report = json.loads(result.stdout)
            assert report["status"] == ("PASS" if expected == 0 else "OPEN")
            assert (
                report["cvp_eligibility"] == "OPEN"
                and report["implementation_author"] == "dhtfish98"
            )
            for private in ("PRIVATE_INPUT_PATH", "PRIVATE_ARGUMENT", str(folder)):
                assert private not in result.stdout
            assert ("SYNTHETIC" in result.stdout) == reveal
        assert sample.read_bytes() == raw
    print(
        json.dumps(
            {
                "status": "PASS",
                "CLI_cases": len(cases),
                "input_unchanged": True,
                "input_sha256": hashlib.sha256(raw).hexdigest(),
                "installed_module": str(prefetch_evidence_review.__file__),
            }
        )
    )


if __name__ == "__main__":
    main()
