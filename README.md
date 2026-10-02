# PrefetchEvidenceReview

PrefetchEvidenceReview reads bounded, uncompressed Windows Prefetch v17, v23 and v26 records offline. It reviews the complete declared metrics, trace arrays, UTF-16 filename strings, volume entries, file references, directory strings, run counter and recorded FILETIME slots. No recorded path is opened and no target program is executed.

The new Python implementation has no runtime dependencies. It is informed by a complete review of the selected Windows-Prefetch-Parser mechanism, and does not import or wrap that package. AI assisted the implementation and review. Application eligibility and the applicant's required human contribution remain **OPEN**.

```sh
python -m pip install .
prefetch-evidence-review /absolute/canonical/path/record.pf
prefetch-evidence-review /absolute/canonical/path/record.pf --reveal-strings
```

The CLI emits bounded JSON. Exit 0 means the selected structural profile passed; exit 2 means OPEN. MAM compressed input and versions other than 17/23/26 are explicitly unsupported. Error messages contain fixed codes and numeric byte positions, without input paths or raw record strings. The local reader requires POSIX no-follow directory/file flags and directory-relative opening, and refuses symlinks in every supplied component, special files, empty components, `.` and `..`. On a platform missing these capabilities, including Windows, the file CLI reports OPEN. The immutable-byte library can still be used on Windows.

```python
from prefetch_evidence_review import Limits, review

report = review(record_bytes)                  # exact bytes; names are hashed
revealed = review(record_bytes, True)          # reveal validated record strings
limited = review(record_bytes, limits=Limits(file_bytes=1024 * 1024))
```

`record_bytes` must be exact immutable `bytes`. `reveal_strings` must be `bool`. `Limits` accepts positive integers that only lower defaults; booleans, subclasses and enlarged budgets are refused. Default ceilings are 16 MiB input, 4,096 metrics, 65,536 traces, 8,192 strings, 16,383 UTF-16 units per string, 1 MiB aggregate string bytes, 32 volumes, 65,536 volume file references, 8,192 directory entries, 250,000 followed trace references and 1 MiB compact JSON. Report budgets below 256 bytes are refused. A tight report budget produces a minimal OPEN response; omitted evidence remains unknown.

Default reports include source byte positions, raw numeric fields, whole-input and string SHA-256, slot-preserving 100 ns times and uninterpreted-range digests. They omit executable, device, directory and filename text. `--reveal-strings` adds only validated strings from a fully passing record; late errors discard all evidence. Even revealed record paths are untrusted declarations. Hashes can enable equality matching and are not anonymization guarantees.

PASS does not establish program execution, record authenticity, timestamp chronology, filesystem identity, maliciousness or Windows runtime behavior. Unknown fields and preserved gaps remain OPEN. See [scope](DEFENSIVE_SCOPE.md), [origin and licenses](ORIGIN.md) and [validation](VALIDATION.md).
