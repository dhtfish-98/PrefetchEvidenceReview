"""Build a fixed, telemetry-disabled PECmd test entry; no evidence file is loaded here."""

import argparse
import difflib
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess
import urllib.request
from urllib.parse import unquote
import zipfile

ROOT = Path(__file__).resolve().parents[1]
COMMIT = "acdf082f1c2e946b0c358cdf6ef71607e00cfea0"
ARCHIVE_SHA = "0e6143351769e75b3eed60fd6d23fa271c7fee009d40eff477d6f12937a37b3f"
PROGRAM_SHA = "85f1f062db182b80381e000c07133c994b81811e692c876b21403a41fde84016"
ADAPTED_NONWINDOWS_SHA = "c04d0e959635776ab31b77c2caed701a7850f8fdc044f8a52e6b91a8f10370ad"
SDK = "9.0.318"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def check_dependencies(source, cache):
    assets = json.loads((source / "PECmd/obj/project.assets.json").read_text())
    expected = json.loads((ROOT / "ORACLE_DEPENDENCIES.json").read_text())["resolved_packages"]
    packages = {key: row for key, row in assets["libraries"].items() if row["type"] == "package"}
    assert set(packages) == {row["id"] + "/" + row["version"] for row in expected}
    licenses = []
    for row in expected:
        name, version = row["id"].lower(), row["version"].lower()
        package = cache / name / version / (name + "." + version + ".nupkg")
        assert digest(package.read_bytes()) == row["nupkg_sha256"]
        assert packages[row["id"] + "/" + row["version"]]["sha512"] == row["sha512"]
        with zipfile.ZipFile(package) as zipped:
            for member in zipped.infolist():
                if not member.is_dir():
                    if member.filename in (
                        "_rels/.rels",
                        "[Content_Types].xml",
                    ) or member.filename.startswith("package/services/metadata/core-properties/"):
                        continue  # NuGet deliberately omits package-container metadata from its cache.
                    extracted = cache / name / version / unquote(member.filename)
                    if member.filename.endswith(".nuspec"):
                        extracted = cache / name / version / (name + ".nuspec")
                    assert extracted.read_bytes() == zipped.read(member), (
                        row["id"],
                        member.filename,
                    )
            for license_row in row["license_files"]:
                raw = zipped.read(license_row["member"])
                assert digest(raw) == license_row["sha256"]
                licenses.append(
                    {"package": row["id"], "member": license_row["member"], "sha256": digest(raw)}
                )
    return {"packages": len(expected), "embedded_license_texts_verified": len(licenses)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dotnet", default="dotnet")
    parser.add_argument("--workspace", type=Path, default=ROOT / "validation-local/oracle-repro")
    parser.add_argument("--archive", type=Path)
    args = parser.parse_args()
    workspace = args.workspace.resolve()
    workspace.mkdir(parents=True, exist_ok=False)
    environment = dict(
        os.environ,
        DOTNET_CLI_TELEMETRY_OPTOUT="1",
        DOTNET_SKIP_FIRST_TIME_EXPERIENCE="1",
        DOTNET_CLI_HOME=str(workspace / "dotnet-home"),
        NUGET_PACKAGES=str(workspace / "nuget"),
    )
    sdk = subprocess.run(
        [args.dotnet, "--version"],
        cwd=ROOT,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
    ).stdout.strip()
    assert sdk == SDK, "Unexpected SDK; use pinned version"
    if args.archive:
        archive = args.archive.read_bytes()
    else:
        with urllib.request.urlopen(
            "https://codeload.github.com/EricZimmerman/PECmd/zip/" + COMMIT, timeout=60
        ) as response:
            archive = response.read(2_000_001)
    assert len(archive) == 149172 and digest(archive) == ARCHIVE_SHA
    zip_path = workspace / "upstream.zip"
    zip_path.write_bytes(archive)
    upstream = workspace / "upstream"
    upstream.mkdir()
    with zipfile.ZipFile(zip_path) as zipped:
        for row in zipped.infolist():
            path = PurePosixPath(row.filename)
            assert (
                not path.is_absolute()
                and ".." not in path.parts
                and not stat.S_ISLNK(row.external_attr >> 16)
            )
            zipped.extract(row, upstream)
    original = upstream / ("PECmd-" + COMMIT)
    source = workspace / "adapted"
    shutil.copytree(original, source)
    program = original / "PECmd/Program.cs"
    raw = program.read_bytes()
    assert digest(raw) == PROGRAM_SHA
    text = raw.decode("utf-8")
    lines = text.splitlines(keepends=True)
    telemetry = [
        i for i, line in enumerate(lines) if "ExceptionlessClient.Default.Startup(" in line
    ]
    assert len(telemetry) == 1
    del lines[telemetry[0]]
    adapted = "".join(lines)
    windows_adapted_sha = digest(adapted.encode())
    if os.name != "nt":
        block = (
            "        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))\n"
            "        {\n"
            "            Console.WriteLine();\n"
            '            Log.Fatal("Non-Windows platforms not supported due to the need to load decompression specific Windows libraries! Exiting...");\n'
            "            Console.WriteLine();\n"
            "            Environment.Exit(0);\n"
            "            return;\n"
            "        }\n"
        )
        assert adapted.count(block) == 1
        adapted = adapted.replace(block, "", 1)
        assert digest(adapted.encode()) == ADAPTED_NONWINDOWS_SHA
    target = source / "PECmd/Program.cs"
    target.write_bytes(adapted.encode())
    difference = "".join(
        difflib.unified_diff(
            text.splitlines(keepends=True),
            adapted.splitlines(keepends=True),
            fromfile="upstream/PECmd/Program.cs",
            tofile="adapted/PECmd/Program.cs",
        )
    )
    (workspace / "entry-adaptation.diff").write_bytes(difference.encode())
    # Verify every source member. Only the explicitly reviewed entry changes are allowed.
    changed = []
    for path in original.rglob("*"):
        if (
            path.is_file()
            and path.read_bytes() != (source / path.relative_to(original)).read_bytes()
        ):
            changed.append(path.relative_to(original).as_posix())
    assert changed == ["PECmd/Program.cs"] and digest(program.read_bytes()) == PROGRAM_SHA
    shutil.copyfile(ROOT / "oracle-packages.lock.json", source / "PECmd/packages.lock.json")
    restore = subprocess.run(
        [
            args.dotnet,
            "restore",
            str(source / "PECmd/PECmd.csproj"),
            "--locked-mode",
            "-p:TargetFrameworks=net9.0",
        ],
        env=environment,
        capture_output=True,
        timeout=1200,
    )
    (workspace / "restore.stdout").write_bytes(restore.stdout)
    (workspace / "restore.stderr").write_bytes(restore.stderr)
    assert restore.returncode == 0, "Locked restore failed; inspect private log"
    checked = check_dependencies(source, workspace / "nuget")
    command = [
        args.dotnet,
        "build",
        str(source / "PECmd/PECmd.csproj"),
        "-f",
        "net9.0",
        "-c",
        "Release",
        "-p:TargetFrameworks=net9.0",
        "--no-restore",
    ]
    result = subprocess.run(command, env=environment, capture_output=True, timeout=1200)
    (workspace / "build.stdout").write_bytes(result.stdout)
    (workspace / "build.stderr").write_bytes(result.stderr)
    assert result.returncode == 0, "Oracle build failed; inspect private build log"
    executable = source / "PECmd/bin/Release/net9.0/PECmd.dll"
    runtime_files = [
        {
            "path": p.relative_to(executable.parent).as_posix(),
            "bytes": p.stat().st_size,
            "sha256": digest(p.read_bytes()),
        }
        for p in sorted(executable.parent.rglob("*"))
        if p.is_file()
    ]
    identity = {
        "runtime_files": runtime_files,
        "lock_sha256": digest((ROOT / "oracle-packages.lock.json").read_bytes()),
        "scope": "test-only PECmd entry adaptation; parser/JSON source unchanged; not native whole-tool equivalence",
        "commit": COMMIT,
        "archive_sha256": ARCHIVE_SHA,
        "original_program_sha256": PROGRAM_SHA,
        "adapted_program_sha256": digest(target.read_bytes()),
        "diff_sha256": digest(difference.encode()),
        "changed_files": changed,
        "platform_guard_removed": os.name != "nt",
        "windows_telemetry_only_program_sha256": windows_adapted_sha,
        "telemetry_startup_removed": True,
        "sdk": sdk,
        "executable": str(executable),
        "executable_sha256": digest(executable.read_bytes()),
        "dependency_manifest_sha256": digest((ROOT / "ORACLE_DEPENDENCIES.json").read_bytes()),
        "build_exit": result.returncode,
        "locked_restore_exit": restore.returncode,
        **checked,
    }
    (workspace / "identity.json").write_text(json.dumps(identity, indent=2) + "\n")
    print(
        json.dumps(
            {key: value for key, value in identity.items() if key != "executable"}, sort_keys=True
        )
    )


if __name__ == "__main__":
    main()
