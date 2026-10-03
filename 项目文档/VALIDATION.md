# Current licensing validation — 0.1.2

This patch removes only 15 confirmed unused complete reference-license/notice copies. New implementation author remains dhtfish98. Runtime parsing and evidence interpretation are unchanged; runtime changes are package version constants and any existing version display. The new source suite ran **50 unittest methods with nonzero PASS**. Current source identities are in SOURCE_MANIFEST.json, and LICENSE_CLEANUP.json describes the exact licensing boundary. Wheel and sdist reconstruction, fresh isolated consumer tests, CLI contracts, runtime/notice byte identity and package metadata are independently bound to the new assets in the batch release records; source tests alone do not prove those outcomes. New hosted CI and publication remain separate observations.

The actual 344-byte PECmd platform-guard fragment in the test-build helper remains attributed and covered by its unchanged MIT file. Externally resolved oracle/SDK/NuGet implementations are not bundled. This licensing patch does not claim a newly reacquired native oracle comparison.

## Historical validation evidence

All following earlier version/count/native observations are historical evidence, not validation of this new patch. Statements below about then-retained reference copies describe the earlier artifacts. Current licensing membership is LICENSE_CLEANUP.json.

# Current validation — 0.1.1

The 2026-10-03 attribution update identifies the new implementation author and maintainer as dhtfish98. The final wheel and sdist were rebuilt, and a fresh isolated consumer ran **50 existing and targeted unittest methods successfully**, imported the installed package from site-packages, exercised the declared CLI contract and matched every shipped runtime/notice byte to current source. Wheel metadata records author dhtfish98 and version 0.1.1; RECORD and source-distribution contents were checked. Current runtime identities are in SOURCE_MANIFEST.json; ATTRIBUTION_UPDATE.json records the exact selected validation scope. The matching private build/install/test logs and artifact hashes are retained in the batch validation records, outside this public project.

One functional change in this update rejects missing, non-positive or non-integer safe-file flags before opening input. API/CLI regressions cover missing, None, invalid, zero and boolean flags, plus regular files and symbolic links.

The existing pinned PECmd oracle workflow and all original dependency notices remain available. This attribution update did not reacquire native oracle data or claim a new Windows-native comparison.

The current safe-file capability gate also requires set/frozenset directory-relative support declarations containing each actually used operation before opening input. Missing, None, empty, malformed or operation-incomplete collections yield the existing controlled unsupported result. Normal set/frozenset declarations and API/CLI rejection-before-open are regression tested.

## Historical validation evidence

The following earlier records retain their original versions, counts and fixed source identities. They are historical observations, not evidence that an old artifact is the current package.

# Validation

The first public run, 37025105975 at commit b71ad0b73b4fb0da6af35f188faa2fda27830fd1, passed all four product jobs. Both external-oracle jobs stopped at the exact SDK-version assertion before restore/build or data comparison. Installing 9.0.318 alone did not select it among the runner's installed SDKs. The project now pins that exact version with `global.json`, disables roll-forward/prereleases, and checks the version from the project directory. Build and comparison are separate dependent CI steps, so a failed build does not attempt a missing identity. The strict SDK and data checks remain required. A new actual exact-commit result is still pending. See the [Microsoft SDK selection reference](https://learn.microsoft.com/en-us/dotnet/core/tools/global-json).

Local source verification: 45 unittest methods PASS, including complete v17/v23/v26 records with one and two volumes, empty arrays, both filename/metric rows, complete trace graphs, full volume reference/directory lists, exact 48-bit NTFS fields, eight time slots, zero/gap/submicrosecond times, BMP/astral UTF-16, opaque-region privacy, precise error positions, endian/reference/truncation/overlap/cycle/ownership boundaries and every reduced budget. The same suite includes 1,000 fixed-seed malformed mutations; this is bounded smoke coverage, not a fuzzing proof. Thirteen input/CLI methods include leaf/parent links, all missing safety flags, short reads and changed identity, directories/FIFO/socket/device files, sparse oversized input, invalid arguments, default privacy and network/subprocess prohibition.

The required independent gate is actual **test-only PECmd entry adaptation and exported-field parsing comparison**. A pinned .NET SDK 9.0.318 / runtime 9.0.20 built the fixed entry on macOS arm64. Locked restore verifies all 82 package archives and their actual extracted payloads before build; package-container metadata that NuGet omits is explicitly excluded. All 129 embedded license/notice members are hash checked. Only the reviewed entry changes and an external dependency lock are added; parser and JSON source bytes remain unchanged. The SDK download matched the official release SHA-512, and its local identity is retained privately.

Twenty complete synthetic PF records and 410 actual JSON field comparisons PASS. Versions 17/23 test ordinary, zero and 100 ns times; v26 tests all eight slots, all zeros, gaps, and consecutive 100 ns values; each runs with one/two volumes. Comparisons include executable, version, recorded hash, size, run count, active recorded times, both volume identities/times, file strings and directory strings. PECmd exports zero v17/v23 time as 1601 and omits zero v26 slots; the comparison explicitly normalizes that export while the new API preserves every slot. PECmd's exported directories concatenate each volume's comma-joined list without an inter-volume separator, also explicitly accounted for. No malformed-file equivalence, modern reference-array equivalence or complete tool equivalence is inferred.

Reproduce source tests and packaging:

```sh
python -m venv validation-local/builder
validation-local/builder/bin/python -m pip install -r requirements-dev.txt
PYTHONPATH=src validation-local/builder/bin/python -m unittest discover -s tests -v
validation-local/builder/bin/ruff check src tests scripts
validation-local/builder/bin/ruff format --check src tests scripts
validation-local/builder/bin/python -m build --no-isolation
python -m venv validation-local/consumer
validation-local/consumer/bin/python -m pip install --no-index --no-deps dist/prefetch_evidence_review-0.1.0-py3-none-any.whl
validation-local/consumer/bin/python -m pip check
validation-local/consumer/bin/python -I -m unittest discover -s tests -v
validation-local/consumer/bin/python -I scripts/installed_cli_check.py
validation-local/consumer/bin/python -I scripts/verify_package.py .
```

For the optional oracle, read the package-specific license references first, install exactly .NET SDK 9.0.318 from its official distribution, then run:

```sh
python scripts/build_pecmd_oracle.py --dotnet /absolute/path/to/dotnet
PYTHONPATH=src python scripts/pecmd_differential.py --dotnet /absolute/path/to/dotnet --identity validation-local/oracle-repro/identity.json --output validation-local/comparison
```

The builder deliberately requires a fresh workspace and verifies a fixed archive hash, fixed original Program hash, exact adaptation, dependency lock, package hashes and generated runtime identity. Reproduction needs network access for fixed tool sources/packages; product analysis does not. Actual input files, tool JSON/stdout, full adaptation diff and binaries remain in ignored `validation-local/`. All executed fixtures are generated harmless records, not downloaded real host Prefetch records. The selected source's real binary test fixtures are excluded.

CI defines four source/build/fresh-consumer/CLI jobs on Linux/macOS with Python 3.11/3.14, plus actual oracle comparisons on Linux/Windows using the fixed SDK and entry adaptation. The Windows test oracle retains the platform guard and only removes telemetry Startup. Merely defining CI does not establish its success; exact-commit remote outcomes remain OPEN until observed. The product file reader's Windows capabilities remain unsupported regardless of the oracle job.

All product runtime, tests, package configuration, CLI and validation scripts were reviewed fully. Final local wheel/sdist metadata, license bytes, RECORD hashes, complete sdist source inclusion, seven installed-console cases and fresh installed-suite results are recorded in the accompanying engineering evidence. Publication, exact-commit CI, native Windows runtime, record authenticity, real execution attribution, security assessment, legal qualification and CVP acceptance remain OPEN until separately supported.
