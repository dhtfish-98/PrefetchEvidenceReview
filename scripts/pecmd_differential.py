"""Actual fixed PECmd JSON field comparison on complete harmless synthetic records only."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
from fixtures import STAMP, example  # noqa: E402
from prefetch_evidence_review import review  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dotnet", default="dotnet")
    parser.add_argument("--identity", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    identity = json.loads(args.identity.read_text())
    assert identity["commit"] == "acdf082f1c2e946b0c358cdf6ef71607e00cfea0"
    assert identity["telemetry_startup_removed"] is True and identity["changed_files"] == [
        "PECmd/Program.cs"
    ]
    assert (
        identity["dependency_manifest_sha256"]
        == hashlib.sha256((ROOT / "ORACLE_DEPENDENCIES.json").read_bytes()).hexdigest()
    )
    executable = Path(identity["executable"])
    assert hashlib.sha256(executable.read_bytes()).hexdigest() == identity["executable_sha256"]
    assert (
        identity["lock_sha256"]
        == hashlib.sha256((ROOT / "oracle-packages.lock.json").read_bytes()).hexdigest()
    )
    expected_files = {row["path"] for row in identity["runtime_files"]}
    assert expected_files == {
        p.relative_to(executable.parent).as_posix()
        for p in executable.parent.rglob("*")
        if p.is_file()
    }
    for row in identity["runtime_files"]:
        assert (
            hashlib.sha256((executable.parent / row["path"]).read_bytes()).hexdigest()
            == row["sha256"]
        )
    args.output.mkdir(parents=True, exist_ok=False)
    environment = dict(
        os.environ,
        DOTNET_CLI_TELEMETRY_OPTOUT="1",
        DOTNET_CLI_HOME=str(args.output / "dotnet-home"),
    )
    versions = {
        17: "Windows XP or Windows Server 2003",
        23: "Windows Vista or Windows 7",
        26: "Windows 8.0, Windows 8.1, or Windows Server 2012(R2)",
    }
    rows = []
    for version in (17, 23, 26):
        profiles = (
            [None, [0], [STAMP + 1]]
            if version != 26
            else [
                None,
                [0] * 8,
                [0, STAMP + 9, 0, STAMP, 0, STAMP + 1, 0, 0],
                [STAMP + i for i in range(8)],
            ]
        )
        for volume_count in (1, 2):
            for number, times in enumerate(profiles):
                raw, facts = example(version, volume_count, times)
                folder = args.output / f"v{version}-vol{volume_count}-time{number}"
                folder.mkdir()
                input_path = folder / "SYNTHETIC-ABCDEF12.pf"
                input_path.write_bytes(raw)
                digest = hashlib.sha256(raw).hexdigest()
                reviewed = review(raw, True)
                assert reviewed["status"] == "PASS", reviewed
                result = subprocess.run(
                    [
                        args.dotnet,
                        str(executable),
                        "-f",
                        str(input_path.resolve()),
                        "-q",
                        "--json",
                        str(folder.resolve()),
                        "--jsonf",
                        "oracle.json",
                        "--dt",
                        "yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'",
                    ],
                    env=environment,
                    capture_output=True,
                    timeout=60,
                )
                (folder / "stdout.txt").write_bytes(result.stdout)
                (folder / "stderr.txt").write_bytes(result.stderr)
                assert result.returncode == 0 and result.stderr == b""
                official = json.loads((folder / "oracle.json").read_text())
                e = reviewed["evidence"]
                expected = {
                    "ExecutableName": e["header"]["executable"]["text"],
                    "Hash": f"{e['header']['recorded_prefetch_hash']:08X}",
                    "Size": str(len(raw)),
                    "Version": versions[version],
                    "RunCount": str(e["run_count"]["value"]),
                    "ParsingError": False,
                    "FilesLoaded": ", ".join(row["text"] for row in e["filenames"]),
                    "Directories": "".join(
                        ", ".join(row["text"] for row in volume["directories"])
                        for volume in e["volumes"]
                    ),
                }
                # PECmd's CSV/JSON export omits zero v26 times; v17/v23 serialize zero as the epoch.
                active = [row["utc_100ns"] for row in e["recorded_run_times"] if row["ticks_100ns"]]
                if version != 26 and not active:
                    active = ["1601-01-01T00:00:00.0000000Z"]
                expected["LastRun"] = active[0] if active else ""
                for index in range(7):
                    key = "PreviousRun" + str(index)
                    expected[key] = active[index + 1] if len(active) > index + 1 else None
                for index, volume in enumerate(e["volumes"]):
                    prefix = "Volume" + str(index)
                    expected[prefix + "Name"] = volume["device"]["text"]
                    expected[prefix + "Serial"] = f"{volume['serial_uint32']:08X}"
                    expected[prefix + "Created"] = volume["creation_time"]["utc_100ns"]
                for key, value in expected.items():
                    assert official.get(key) == value, (
                        version,
                        volume_count,
                        number,
                        key,
                        official.get(key),
                        value,
                    )
                assert input_path.read_bytes() == raw
                assert [row["ticks_100ns"] for row in e["recorded_run_times"]] == facts["times"]
                rows.append(
                    {
                        "version": version,
                        "volumes": volume_count,
                        "time_profile": number,
                        "input_bytes": len(raw),
                        "input_sha256": digest,
                        "official_json_sha256": hashlib.sha256(
                            (folder / "oracle.json").read_bytes()
                        ).hexdigest(),
                        "compared_fields": len(expected),
                        "exit": result.returncode,
                        "input_unchanged": True,
                        "status": "PASS",
                    }
                )
    report = {
        "scope": "actual test-only PECmd entry adaptation and exported field parsing comparison",
        "oracle_identity_sha256": hashlib.sha256(args.identity.read_bytes()).hexdigest(),
        "cases": len(rows),
        "field_comparisons": sum(row["compared_fields"] for row in rows),
        "zero_time_normalization": "v26 zero slots omitted in PECmd; v17/v23 zero serialized as epoch; new API preserves every raw slot",
        "directory_export_normalization": "PECmd concatenates per-volume comma-joined strings without a separator between volumes",
        "outside_oracle_export": [
            "trace graph",
            "metric arrays",
            "v23/v26 documented 16-byte file-reference header",
            "full 48-bit NTFS interpretation",
            "source positions",
            "malformed data",
            "current Windows execution",
        ],
        "windows_native_runtime": "OPEN",
        "cvp_eligibility": "OPEN",
        "rows": rows,
    }
    (args.output / "comparison.json").write_text(json.dumps(report, indent=2) + "\n")
    print(
        json.dumps(
            {"cases": len(rows), "field_comparisons": report["field_comparisons"], "status": "PASS"}
        )
    )


if __name__ == "__main__":
    main()
