"""Independent bounded static Prefetch arrays, strings, volume and timestamp evidence."""

from hashlib import sha256
import json
import struct

from .model import DEFAULT_LIMITS, Issue, check_limits, time_evidence

END = 0xFFFFFFFF
INFO_SIZE = {17: 68, 23: 156, 26: 220}


class Prefetch:
    def __init__(self, raw, limits):
        self.raw = memoryview(raw)
        self.limits = limits
        self.regions = []
        self.row_bytes = 0
        self.string_bytes = 0
        self.string_count = 0
        self.directory_count = 0
        self.reference_count = 0
        self.followed = 0
        self.names = []
        self.filenames = []
        self.metrics = []
        self.traces = []
        self.volumes = []

    def number(self, offset, fmt="<I"):
        size = struct.calcsize(fmt)
        if offset < 0 or offset + size > len(self.raw):
            raise Issue("field_bounds", offset)
        return struct.unpack_from(fmt, self.raw, offset)[0]

    def span(self, offset, size, source, lower=0, upper=None):
        end = len(self.raw) if upper is None else upper
        if offset < lower or size < 0 or offset > end or size > end - offset:
            raise Issue("declared_range_bounds", source)
        return self.raw[offset : offset + size]

    def claim(self, regions, offset, size, source, lower=0, upper=None):
        raw = self.span(offset, size, source, lower, upper)
        if size:
            if any(offset < end and begin < offset + size for begin, end in regions):
                raise Issue("declared_ranges_overlap", source)
            regions.append((offset, offset + size))
        return raw

    def row_budget(self, row, source):
        self.row_bytes += (
            len(json.dumps(row, ensure_ascii=True, separators=(",", ":")).encode()) + 1
        )
        if self.row_bytes > self.limits.report_bytes:
            raise Issue("report_budget", source)

    def opaque(self, offset, size):
        return {
            "offset": offset,
            "bytes": size,
            "sha256": sha256(self.raw[offset : offset + size]).hexdigest(),
            "semantics": "OPEN",
        }

    def string(self, raw, offset):
        if len(raw) % 2 or len(raw) // 2 > self.limits.string_units:
            raise Issue("string_length_or_budget", offset)
        self.string_bytes += len(raw)
        self.string_count += 1
        if self.string_bytes > self.limits.string_bytes or self.string_count > self.limits.strings:
            raise Issue("aggregate_string_budget", offset)
        try:
            text = bytes(raw).decode("utf-16le", "strict")
        except UnicodeError:
            raise Issue("unsupported_utf16_encoding", offset) from None
        if not text or "\0" in text:
            raise Issue("string_empty_or_embedded_nul", offset)
        row = {"offset": offset, "utf16_units": len(raw) // 2, "sha256": sha256(raw).hexdigest()}
        self.names.append((row, text))
        self.row_budget(row, offset)
        return row

    def terminated(self, offset, chars, source, regions=None, lower=0, upper=None):
        if chars > self.limits.string_units:
            raise Issue("string_length_or_budget", source)
        raw = self.span(offset, (chars + 1) * 2, source, lower, upper)
        if bytes(raw[-2:]) != b"\0\0":
            raise Issue("string_terminator", offset + chars * 2)
        if regions is not None:
            self.claim(regions, offset, len(raw), source, lower, upper)
        return self.string(raw[:-2], offset)

    def header(self):
        if bytes(self.raw[:3]) == b"MAM":
            if len(self.raw) < 8:
                raise Issue("mam_truncated_header", 0)
            size = self.number(4)
            if size > self.limits.file_bytes:
                raise Issue("mam_declared_size_budget", 4)
            raise Issue("mam_compression_unsupported", 0)
        if len(self.raw) < 84:
            raise Issue("header_size", 0)
        self.version = self.number(0)
        if self.version not in INFO_SIZE:
            raise Issue("version_unsupported", 0)
        if bytes(self.raw[4:8]) != b"SCCA":
            raise Issue("signature", 4)
        if self.number(12) != len(self.raw):
            raise Issue("declared_file_size", 12)
        self.header_end = 84 + INFO_SIZE[self.version]
        self.claim(self.regions, 0, self.header_end, 0)
        rawname = self.raw[16:76]
        ending = next((p for p in range(0, 60, 2) if bytes(rawname[p : p + 2]) == b"\0\0"), None)
        if ending is None:
            raise Issue("executable_name_terminator", 16)
        self.executable = self.string(rawname[:ending], 16)
        self.header_evidence = {
            "version": self.version,
            "declared_file_bytes": len(self.raw),
            "recorded_prefetch_hash": self.number(76),
            "header_unknown_8": self.number(8),
            "header_unknown_80": self.number(80),
            "executable": self.executable,
            "unused_executable_bytes": self.opaque(16 + ending + 2, 58 - ending),
            "unknown_semantics": "OPEN",
        }
        words = [self.number(84 + i * 4) for i in range(9)]
        (
            self.metrics_offset,
            self.metric_count,
            self.trace_offset,
            self.trace_count,
            self.strings_offset,
            self.strings_size,
            self.volume_offset,
            self.volume_count,
            self.volume_size,
        ) = words
        if self.metric_count > self.limits.metrics:
            raise Issue("metric_count_budget", 88)
        if self.trace_count > self.limits.traces:
            raise Issue("trace_count_budget", 96)
        if self.volume_count > self.limits.volumes:
            raise Issue("volume_count_budget", 112)
        if self.strings_size > self.limits.string_bytes or self.strings_size % 2:
            raise Issue("filename_strings_size_or_budget", 104)
        self.metric_size = 20 if self.version == 17 else 32
        for start, size, source in [
            (self.metrics_offset, self.metric_count * self.metric_size, 84),
            (self.trace_offset, self.trace_count * 12, 92),
            (self.strings_offset, self.strings_size, 100),
            (self.volume_offset, self.volume_size, 108),
        ]:
            self.claim(
                self.regions,
                start,
                size,
                source,
                0 if size == 0 and start == 0 else self.header_end,
            )
        when = 120 if self.version == 17 else 128
        slots = 8 if self.version == 26 else 1
        self.times = [
            time_evidence(self.number(when + 8 * i, "<Q"), when + 8 * i) for i in range(slots)
        ]
        run_offset = {17: 144, 23: 152, 26: 208}[self.version]
        self.run_count = {
            "value": self.number(run_offset),
            "offset": run_offset,
            "meaning": "UNAUTHENTICATED_RECORD_COUNTER",
        }
        fields = {
            17: [(128, 16), (148, 4)],
            23: [(120, 8), (136, 16), (156, 84)],
            26: [(120, 8), (192, 16), (212, 92)],
        }
        self.info_unknown = [self.opaque(start, size) for start, size in fields[self.version]]

    def filename_strings(self):
        self.filename_by_relative = {}
        cursor = self.strings_offset
        ending = cursor + self.strings_size
        while cursor < ending:
            start = cursor
            while cursor < ending and self.number(cursor, "<H") != 0:
                cursor += 2
            if cursor == ending:
                raise Issue("filename_string_terminator", start)
            if cursor == start:
                if any(self.raw[cursor:ending]):
                    raise Issue("empty_filename_before_data", cursor)
                break
            row = self.string(self.raw[start:cursor], start)
            self.filename_by_relative[start - self.strings_offset] = row
            self.filenames.append(row)
            cursor += 2

    def trace_arrays(self):
        for index in range(self.trace_count):
            offset = self.trace_offset + index * 12
            nxt = self.number(offset)
            if nxt != END and nxt >= self.trace_count:
                raise Issue("trace_next_index_bounds", offset)
            row = {
                "index": index,
                "offset": offset,
                "next_index": None if nxt == END else nxt,
                "total_block_load_count": self.number(offset + 4),
                "flags_raw": self.raw[offset + 8],
                "sample_duration_raw": self.raw[offset + 9],
                "used_run_bits": self.raw[offset + 10],
                "prefetched_run_bits": self.raw[offset + 11],
                "behavior": "OPEN",
            }
            self.row_budget(row, offset)
            self.traces.append(row)
        # Each trace is visited at most once, including traces not claimed by a metric.
        done = set()
        for start in range(self.trace_count):
            current, path = start, set()
            while current is not None and current not in done:
                self.follow(current)
                if current in path:
                    raise Issue("trace_cycle", self.traces[current]["offset"])
                path.add(current)
                current = self.traces[current]["next_index"]
            done.update(path)

    def follow(self, index):
        self.followed += 1
        if self.followed > self.limits.followed_references:
            raise Issue("followed_reference_budget", self.trace_offset + 12 * index)

    def metric_arrays(self):
        owners = {}
        for index in range(self.metric_count):
            offset = self.metrics_offset + index * self.metric_size
            first, count = self.number(offset), self.number(offset + 4)
            where = offset + (8 if self.version == 17 else 12)
            relative, chars = self.number(where), self.number(where + 4)
            string = self.filename_by_relative.get(relative)
            if string is None or string["utf16_units"] != chars:
                raise Issue("metric_filename_reference", where)
            if (
                count > self.trace_count
                or (count == 0) != (first == END)
                or first != END
                and first >= self.trace_count
            ):
                raise Issue("metric_trace_reference_or_count", offset)
            current = None if first == END else first
            chain = []
            while current is not None:
                self.follow(current)
                if len(chain) >= count:
                    raise Issue("metric_trace_chain_longer", offset + 4)
                if current in owners:
                    raise Issue("shared_metric_trace", self.trace_offset + current * 12)
                owners[current] = index
                chain.append(current)
                current = self.traces[current]["next_index"]
            if len(chain) != count:
                raise Issue("metric_trace_chain_shorter", offset + 4)
            row = {
                "index": index,
                "offset": offset,
                "filename_offset": string["offset"],
                "filename_sha256": string["sha256"],
                "trace_index": None if first == END else first,
                "trace_entry_count": count,
                "trace_chain_sha256": sha256(
                    b"".join(struct.pack("<I", i) for i in chain)
                ).hexdigest(),
                "flags_raw": self.number(offset + (16 if self.version == 17 else 20)),
                "behavior": "OPEN",
            }
            if self.version != 17:
                row["blocks_to_prefetch_raw"] = self.number(offset + 8)
                row["file_reference"] = self.file_reference(offset + 24)
            self.row_budget(row, offset)
            self.metrics.append(row)
        if len(owners) != self.trace_count:
            unused = next(i for i in range(self.trace_count) if i not in owners)
            raise Issue("unclaimed_trace_profile", self.trace_offset + unused * 12)

    def file_reference(self, offset):
        value = self.number(offset, "<Q")
        return {
            "offset": offset,
            "raw_uint64": value,
            "ntfs_entry_index": value & 0xFFFFFFFFFFFF,
            "ntfs_sequence": value >> 48,
            "filesystem_identity": "OPEN",
            "meaning": "UNAUTHENTICATED_NTFS_INTERPRETATION",
        }

    def volume_arrays(self):
        entry_size = 40 if self.version == 17 else 104
        table_size = self.volume_count * entry_size
        end = self.volume_offset + self.volume_size
        regions = []
        self.claim(regions, self.volume_offset, table_size, 112, self.volume_offset, end)
        for index in range(self.volume_count):
            offset = self.volume_offset + index * entry_size
            path_relative, chars = self.number(offset), self.number(offset + 4)
            device = self.terminated(
                self.volume_offset + path_relative,
                chars,
                offset,
                regions,
                self.volume_offset + table_size,
                end,
            )
            created = time_evidence(self.number(offset + 8, "<Q"), offset + 8)
            ref_relative, ref_size = self.number(offset + 20), self.number(offset + 24)
            ref_start = self.volume_offset + ref_relative
            self.claim(
                regions, ref_start, ref_size, offset + 20, self.volume_offset + table_size, end
            )
            refs = []
            prefix = None
            if ref_size:
                header_size = 8 if self.version == 17 else 16
                if ref_size < header_size:
                    raise Issue("file_references_header", offset + 24)
                version = self.number(ref_start)
                if version != (1 if self.version == 17 else 3):
                    raise Issue("file_references_version_unsupported", ref_start)
                count = self.number(ref_start + 4)
                if count > self.limits.file_references - self.reference_count:
                    raise Issue("file_reference_count_budget", ref_start + 4)
                if ref_size != header_size + count * 8:
                    raise Issue("file_references_declared_size", offset + 24)
                self.reference_count += count
                if header_size == 16:
                    prefix = self.opaque(ref_start + 8, 8)
                for i in range(count):
                    ref = self.file_reference(ref_start + header_size + i * 8)
                    self.row_budget(ref, ref["offset"])
                    refs.append(ref)
            dirs_relative, dirs_count = self.number(offset + 28), self.number(offset + 32)
            if dirs_count > self.limits.directories - self.directory_count:
                raise Issue("directory_count_budget", offset + 32)
            self.directory_count += dirs_count
            cursor = self.volume_offset + dirs_relative
            dirs_start = cursor
            self.span(cursor, 0, offset + 28, self.volume_offset + table_size, end)
            directories = []
            for _ in range(dirs_count):
                self.span(cursor, 2, offset + 28, self.volume_offset + table_size, end)
                chars = self.number(cursor, "<H")
                cursor += 2
                row = self.terminated(
                    cursor, chars, cursor - 2, lower=self.volume_offset + table_size, upper=end
                )
                directories.append(row)
                cursor += (chars + 1) * 2
            self.claim(
                regions,
                dirs_start,
                cursor - dirs_start,
                offset + 28,
                self.volume_offset + table_size,
                end,
            )
            row = {
                "index": index,
                "offset": offset,
                "device": device,
                "creation_time": created,
                "serial_uint32": self.number(offset + 16),
                "file_references_offset": ref_start,
                "file_references_bytes": ref_size,
                "file_references": refs,
                "reference_unknown_prefix": prefix,
                "directories_offset": dirs_start,
                "directories": directories,
                "entry_unknown": self.opaque(offset + 36, entry_size - 36),
                "identity": "OPEN",
            }
            self.row_budget({**row, "file_references": [], "directories": []}, offset)
            self.volumes.append(row)
        self.volume_uninterpreted = self.gaps(regions, self.volume_offset, end)

    def gaps(self, regions, start, end):
        rows = []
        cursor = start
        for begin, stop in sorted(regions):
            if cursor < begin:
                rows.append(self.opaque(cursor, begin - cursor))
            cursor = stop
        if cursor < end:
            rows.append(self.opaque(cursor, end - cursor))
        return rows

    def run(self, reveal):
        self.header()
        self.filename_strings()
        self.trace_arrays()
        self.metric_arrays()
        self.volume_arrays()
        if reveal:
            for row, text in self.names:
                row["text"] = text
        return {
            "header": self.header_evidence,
            "run_count": self.run_count,
            "recorded_run_times": self.times,
            "information_unknown": self.info_unknown,
            "filenames": self.filenames,
            "metrics": self.metrics,
            "traces": self.traces,
            "volumes": self.volumes,
            "uninterpreted_file_ranges": self.gaps(self.regions, 0, len(self.raw)),
            "uninterpreted_volume_ranges": self.volume_uninterpreted,
            "followed_references": self.followed,
            "unknown_field_semantics": "OPEN",
        }


def review(data, reveal_strings=False, limits=DEFAULT_LIMITS):
    """Review exact immutable uncompressed v17/v23/v26 bytes without executing targets."""
    result = {
        "schema_version": 1,
        "status": "OPEN",
        "format_support": "OPEN",
        "issues": [],
        "evidence": None,
        "current_host_execution": "OPEN",
        "record_authenticity": "OPEN",
        "maliciousness": "OPEN",
        "windows_runtime": "OPEN",
        "unknown_field_semantics": "OPEN",
        "cvp_eligibility": "OPEN",
        "ai_assisted": True,
    }
    report_limit = DEFAULT_LIMITS.report_bytes
    try:
        check_limits(limits)
        report_limit = limits.report_bytes
        if type(data) is not bytes or len(data) > limits.file_bytes:
            raise Issue("input_type_or_byte_budget")
        if type(reveal_strings) is not bool:
            raise Issue("reveal_strings_type")
        result.update(input_bytes=len(data), input_sha256=sha256(data).hexdigest())
        if data[:3] == b"MAM":
            result["format_support"] = "UNSUPPORTED"
        result["evidence"] = Prefetch(data, limits).run(reveal_strings)
        result["format_support"] = "SUPPORTED_PROFILE"
        result["status"] = "PASS"
    except Issue as error:
        result["evidence"] = None
        result["issues"] = [{"code": error.code, "offset": error.offset}]
        if error.code in (
            "version_unsupported",
            "mam_compression_unsupported",
            "unsupported_utf16_encoding",
            "file_references_version_unsupported",
        ):
            result["format_support"] = "UNSUPPORTED"
    if len(json.dumps(result, ensure_ascii=True, separators=(",", ":")).encode()) > report_limit:
        return {
            "schema_version": 1,
            "status": "OPEN",
            "format_support": "OPEN",
            "issues": [{"code": "report_budget", "offset": None}],
            "evidence": None,
            "cvp_eligibility": "OPEN",
            "ai_assisted": True,
        }
    return result
