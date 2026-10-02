import dataclasses
import hashlib
import json
import random
import unittest

from prefetch_evidence_review import Limits, review
from fixtures import END, STAMP, example, put


class Structure(unittest.TestCase):
    def change(self, raw, offset, value, fmt="<I"):
        data = bytearray(raw)
        put(data, offset, value, fmt)
        return bytes(data)

    def assert_open(self, data, code=None, limits=Limits()):
        before = hashlib.sha256(data).digest()
        result = review(data, True, limits)
        self.assertEqual(result["status"], "OPEN", result)
        self.assertIsNone(result["evidence"])
        self.assertEqual(before, hashlib.sha256(data).digest())
        if code:
            self.assertEqual(result["issues"][0]["code"], code)
        return result

    def test_complete_three_versions_and_two_volumes(self):
        for version in (17, 23, 26):
            for volumes in (1, 2):
                raw, facts = example(version, volumes)
                result = review(raw, True)
                self.assertEqual(result["status"], "PASS", result)
                e = result["evidence"]
                self.assertEqual(e["header"]["executable"]["text"], facts["executable"])
                self.assertEqual(e["run_count"]["value"], facts["run_count"])
                self.assertEqual(
                    [t["ticks_100ns"] for t in e["recorded_run_times"]], facts["times"]
                )
                self.assertEqual([s["text"] for s in e["filenames"]], facts["strings"])
                self.assertEqual(len(e["metrics"]), 2)
                self.assertEqual(len(e["traces"]), 4)
                for row, expected in zip(e["volumes"], facts["volumes"]):
                    self.assertEqual(row["device"]["text"], expected["path"])
                    self.assertEqual(row["offset"], expected["entry"])
                    self.assertEqual(row["serial_uint32"], expected["serial"])
                    self.assertEqual(
                        [r["raw_uint64"] for r in row["file_references"]], expected["references"]
                    )
                    self.assertEqual(
                        [s["text"] for s in row["directories"]], expected["directories"]
                    )
                self.assertEqual(result["current_host_execution"], "OPEN")

    def test_empty_declared_arrays(self):
        for version in (17, 23, 26):
            result = review(example(version, empty=True)[0])
            self.assertEqual(result["status"], "PASS", result)
            self.assertEqual(result["evidence"]["volumes"], [])
            self.assertEqual(result["evidence"]["metrics"], [])

    def test_default_privacy_and_opt_in_strings(self):
        raw, _ = example()
        private = b"SYNTHETIC".decode()
        result = review(raw)
        self.assertEqual(result["status"], "PASS")
        self.assertNotIn(private, json.dumps(result))
        self.assertIn(private, json.dumps(review(raw, True)))
        self.assertEqual(result["input_sha256"], hashlib.sha256(raw).hexdigest())

    def test_full_ntfs_48bit_and_sequence(self):
        raw, _ = example()
        row = review(raw)["evidence"]["metrics"][0]["file_reference"]
        self.assertEqual(row["ntfs_entry_index"], 0x123456789ABC)
        self.assertEqual(row["ntfs_sequence"], 7)
        self.assertEqual(row["filesystem_identity"], "OPEN")

    def test_integer_filetimes_zeros_and_submicroseconds(self):
        raw, _ = example(26, times=[0, STAMP + 9, 0, STAMP, 0, 0, 0, 0])
        result = review(raw)["evidence"]["recorded_run_times"]
        self.assertEqual(len(result), 8)
        self.assertEqual(result[0]["status"], "UNSET")
        self.assertIsNone(result[0]["utc_100ns"])
        self.assertEqual(result[1]["utc_100ns"], "1970-01-01T00:00:00.0000009Z")
        self.assertEqual(result[3]["utc_100ns"], "1970-01-01T00:00:00.0000000Z")

    def test_size_signature_version_and_unknown(self):
        raw, _ = example()
        for offset, value, code in [
            (0, 30, "version_unsupported"),
            (0, 31, "version_unsupported"),
            (0, END, "version_unsupported"),
            (4, 0, "signature"),
            (12, len(raw) - 1, "declared_file_size"),
        ]:
            result = self.assert_open(self.change(raw, offset, value), code)
            self.assertEqual(result["issues"][0]["offset"], offset)

    def test_mam_never_decompresses_or_allocates_declared_size(self):
        for signature in (b"MAM\x04", b"MAM\x84", b"MAM\xff"):
            self.assert_open(
                signature + (100).to_bytes(4, "little") + b"FAKE_COMPRESSED",
                "mam_compression_unsupported",
            )
            self.assert_open(signature + END.to_bytes(4, "little"), "mam_declared_size_budget")
        for size in (3, 4, 7):
            self.assert_open(b"MAM\x04"[:size].ljust(size, b"\0"), "mam_truncated_header")

    def test_truncation_each_declared_structure(self):
        raw, facts = example()
        for stop in (
            0,
            1,
            8,
            83,
            84,
            120,
            303,
            facts["metrics_offset"] + 31,
            facts["trace_offset"] + 11,
            facts["strings_offset"] + 1,
            facts["volume_offset"] + 103,
            len(raw) - 1,
        ):
            data = bytearray(raw[:stop])
            if stop >= 16:
                put(data, 12, stop)
            self.assert_open(bytes(data))

    def test_all_top_ranges_bounds_and_nonoverlap(self):
        raw, _ = example()
        for field in (84, 92, 100, 108):
            for value in (1, len(raw) + 1, END):
                self.assert_open(self.change(raw, field, value))
        for field in (92, 100, 108):
            self.assert_open(self.change(raw, field, 304), "declared_ranges_overlap")
        self.assert_open(self.change(raw, 116, END), "declared_range_bounds")

    def test_array_count_and_strings_budgets(self):
        raw, _ = example()
        for field, code in [
            (88, "metric_count_budget"),
            (96, "trace_count_budget"),
            (112, "volume_count_budget"),
            (104, "filename_strings_size_or_budget"),
        ]:
            self.assert_open(self.change(raw, field, END), code)
        self.assert_open(self.change(raw, 104, 1), "filename_strings_size_or_budget")

    def test_executable_encoding_termination_and_remnant(self):
        raw, _ = example()
        self.assert_open(self.change(raw, 16, 0, "<H"), "string_empty_or_embedded_nul")
        self.assert_open(self.change(raw, 16, 0xD800, "<H"), "unsupported_utf16_encoding")
        changed = bytearray(raw)
        changed[16:76] = b"A\0" * 30
        self.assert_open(bytes(changed), "executable_name_terminator")
        changed = bytearray(raw)
        changed[44:76] = "PRIVATE_REMNANT".encode("utf-16le").ljust(32, b"X")
        result = review(bytes(changed), True)
        self.assertEqual(result["status"], "PASS")
        self.assertNotIn("PRIVATE_REMNANT", json.dumps(result))

    def test_filename_encoding_terminator_and_internal_empty(self):
        raw, f = example()
        self.assert_open(
            self.change(raw, f["strings_offset"], 0xD800, "<H"), "unsupported_utf16_encoding"
        )
        self.assert_open(
            self.change(raw, f["strings_offset"], 0, "<H"), "empty_filename_before_data"
        )
        size = int.from_bytes(raw[104:108], "little")
        self.assert_open(
            self.change(raw, f["strings_offset"] + size - 2, ord("x"), "<H"),
            "filename_string_terminator",
        )

    def test_metric_filename_exact_start_length_and_byte_endian(self):
        raw, f = example()
        base = f["metrics_offset"]
        for value in (1, 2, END):
            self.assert_open(self.change(raw, base + 12, value), "metric_filename_reference")
        self.assert_open(self.change(raw, base + 16, 1), "metric_filename_reference")
        changed = bytearray(raw)
        changed[base + 12 : base + 16] = (2).to_bytes(4, "big")
        self.assert_open(bytes(changed), "metric_filename_reference")

    def test_trace_bounds_all_rows_including_unclaimed(self):
        raw, f = example()
        for index in range(4):
            self.assert_open(
                self.change(raw, f["trace_offset"] + 12 * index, 4), "trace_next_index_bounds"
            )

    def test_trace_self_and_multi_cycle(self):
        raw, f = example()
        self.assert_open(self.change(raw, f["trace_offset"], 0), "trace_cycle")
        self.assert_open(self.change(raw, f["trace_offset"] + 12, 0), "trace_cycle")

    def test_metric_trace_bounds_empty_count_consistency(self):
        raw, f = example()
        offset = f["metrics_offset"]
        for value in (END, 4):
            self.assert_open(self.change(raw, offset, value), "metric_trace_reference_or_count")
        for count in (0, 5, END):
            self.assert_open(self.change(raw, offset + 4, count), "metric_trace_reference_or_count")

    def test_metric_trace_exact_length(self):
        raw, f = example()
        self.assert_open(self.change(raw, f["metrics_offset"] + 4, 1), "metric_trace_chain_longer")
        self.assert_open(self.change(raw, f["metrics_offset"] + 4, 3), "metric_trace_chain_shorter")

    def test_trace_sharing_and_orphan(self):
        raw, f = example()
        self.assert_open(self.change(raw, f["metrics_offset"] + 32, 0), "shared_metric_trace")
        changed = self.change(
            self.change(raw, f["metrics_offset"] + 32, END), f["metrics_offset"] + 36, 0
        )
        self.assert_open(changed, "unclaimed_trace_profile")

    def test_volume_entry_table_and_path_bounds(self):
        raw, f = example()
        entry = f["volume_offset"]
        for field in (0, 20, 28):
            for value in (0, END):
                self.assert_open(self.change(raw, entry + field, value))
        self.assert_open(self.change(raw, 112, 20), "declared_range_bounds")
        self.assert_open(self.change(raw, entry + 4, END), "string_length_or_budget")

    def test_volume_path_encoding_and_terminator(self):
        raw, f = example()
        path = f["volumes"][0]["path_offset"]
        self.assert_open(self.change(raw, path, 0xD800, "<H"), "unsupported_utf16_encoding")
        self.assert_open(self.change(raw, path, 0, "<H"), "string_empty_or_embedded_nul")
        chars = len(f["volumes"][0]["path"].encode("utf-16le")) // 2
        self.assert_open(self.change(raw, path + chars * 2, ord("x"), "<H"), "string_terminator")

    def test_volume_regions_cannot_alias_each_other_or_entry(self):
        raw, f = example(26, 2)
        entry = f["volumes"][1]["entry"]
        relative = f["volumes"][0]["path_offset"] - f["volume_offset"]
        self.assert_open(self.change(raw, entry, relative), "declared_ranges_overlap")
        relative = f["volumes"][0]["dirs_offset"] - f["volume_offset"]
        self.assert_open(self.change(raw, entry + 28, relative), "declared_ranges_overlap")

    def test_file_reference_version_size_and_count(self):
        for version in (17, 23, 26):
            raw, f = example(version)
            entry, refs = f["volumes"][0]["entry"], f["volumes"][0]["refs_offset"]
            self.assert_open(self.change(raw, refs, 7), "file_references_version_unsupported")
            self.assert_open(self.change(raw, refs + 4, END), "file_reference_count_budget")
            self.assert_open(self.change(raw, refs + 4, 1), "file_references_declared_size")
            self.assert_open(self.change(raw, entry + 24, 1), "file_references_header")
            self.assert_open(self.change(raw, entry + 24, END), "declared_range_bounds")

    def test_directory_count_prefix_encoding_nul_termination(self):
        raw, f = example()
        entry = f["volume_offset"]
        start = f["volumes"][0]["dirs_offset"]
        self.assert_open(self.change(raw, entry + 32, END), "directory_count_budget")
        self.assert_open(self.change(raw, start, 0xFFFF, "<H"), "string_length_or_budget")
        self.assert_open(self.change(raw, start + 2, 0xD800, "<H"), "unsupported_utf16_encoding")
        self.assert_open(self.change(raw, start + 2, 0, "<H"), "string_empty_or_embedded_nul")
        units = int.from_bytes(raw[start : start + 2], "little")
        self.assert_open(
            self.change(raw, start + 2 + units * 2, ord("x"), "<H"), "string_terminator"
        )

    def test_timestamp_out_of_range_positions(self):
        raw, f = example()
        for offset in (128, 184, f["volume_offset"] + 8):
            result = self.assert_open(
                self.change(raw, offset, 0xFFFFFFFFFFFFFFFF, "<Q"), "filetime_range"
            )
            self.assertEqual(result["issues"][0]["offset"], offset)

    def test_v26_info220_boundary_and_reordered_sections(self):
        raw, f = example()
        self.assertEqual(f["metrics_offset"], 304)
        result = review(raw)
        self.assertEqual(result["status"], "PASS")
        # Move a complete metrics array after the final volume composite, updating only its absolute declaration.
        begin = f["metrics_offset"]
        size = 64
        changed = bytearray(raw[:begin] + raw[begin + size :] + raw[begin : begin + size])
        for field in (92, 100, 108):
            put(changed, field, int.from_bytes(raw[field : field + 4], "little") - size)
        put(changed, 84, len(raw) - size)
        result = review(bytes(changed), True)
        self.assertEqual(result["status"], "PASS", result)
        self.assertEqual([s["text"] for s in result["evidence"]["filenames"]], f["strings"])

    def test_unknown_bytes_are_hashed_never_decoded(self):
        raw, f = example()
        changed = bytearray(raw)
        changed[212:242] = b"PRIVATE_UNKNOWN_CONTENT".ljust(30, b"X")
        result = review(bytes(changed), True)
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["unknown_field_semantics"], "OPEN")
        self.assertNotIn("PRIVATE_UNKNOWN_CONTENT", json.dumps(result))

    def test_limits_types_and_every_reduced_budget(self):
        raw, _ = example(26, 2)
        for limits in (
            None,
            {},
            dataclasses.replace(Limits(), metrics=True),
            dataclasses.replace(Limits(), volumes=0),
            dataclasses.replace(Limits(), file_bytes=16 * 1024 * 1024 + 1),
            dataclasses.replace(Limits(), report_bytes=255),
        ):
            self.assert_open(raw, limits=limits)
        for key in (
            "file_bytes",
            "metrics",
            "traces",
            "strings",
            "string_units",
            "string_bytes",
            "volumes",
            "file_references",
            "directories",
            "followed_references",
        ):
            self.assert_open(raw, limits=dataclasses.replace(Limits(), **{key: 1}))
        self.assert_open(raw, limits=dataclasses.replace(Limits(), report_bytes=256))
        for obj in (None, "text", bytearray(raw), memoryview(raw)):
            self.assertEqual(review(obj)["status"], "OPEN")
        self.assertEqual(review(raw, 1)["status"], "OPEN")

    def test_late_error_never_returns_clean_prefix_or_strings(self):
        raw, f = example(26, 2)
        result = self.assert_open(
            self.change(raw, f["volumes"][1]["entry"] + 8, 0xFFFFFFFFFFFFFFFF, "<Q")
        )
        self.assertIsNone(result["evidence"])
        self.assertNotIn("SYNTHETIC", json.dumps(result))

    def test_unicode_bmp_astral_and_exact_utf16_units(self):
        raw, f = example()
        changed = bytearray(raw)
        name = "合成😀.EXE"
        encoded = name.encode("utf-16le")
        changed[16:76] = (encoded + b"\0\0").ljust(60, b"\0")
        result = review(bytes(changed), True)
        self.assertEqual(result["status"], "PASS", result)
        self.assertEqual(result["evidence"]["header"]["executable"]["text"], name)
        self.assertEqual(result["evidence"]["header"]["executable"]["utf16_units"], 8)

    def test_uint32_counter_boundary_and_explicit_format_support(self):
        raw, _ = example()
        result = review(self.change(raw, 208, END))
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["format_support"], "SUPPORTED_PROFILE")
        self.assertEqual(result["evidence"]["run_count"]["value"], END)
        self.assertEqual(review(self.change(raw, 0, 30))["format_support"], "UNSUPPORTED")
        self.assertEqual(review(b"MAM")["format_support"], "UNSUPPORTED")
        self.assertEqual(review(b"bad")["format_support"], "OPEN")

    def test_zero_reference_count_and_zero_trace_chain(self):
        raw, f = example()
        changed = bytearray(raw)
        # Remove trace declarations consistently; untouched trace bytes remain opaque file gaps.
        put(changed, 96, 0)
        for i in range(2):
            put(changed, f["metrics_offset"] + i * 32, END)
            put(changed, f["metrics_offset"] + i * 32 + 4, 0)
        refs = f["volumes"][0]["refs_offset"]
        put(changed, refs + 4, 0)
        put(changed, f["volume_offset"] + 24, 16)
        result = review(bytes(changed))
        self.assertEqual(result["status"], "PASS", result)
        self.assertEqual(result["evidence"]["volumes"][0]["file_references"], [])
        self.assertEqual(result["evidence"]["metrics"][0]["trace_entry_count"], 0)
        self.assertTrue(result["evidence"]["uninterpreted_file_ranges"])

    def test_fixed_random_malformed_smoke(self):
        raw, _ = example()
        rng = random.Random(20261002)
        for _ in range(1000):
            data = bytearray(raw)
            for _ in range(3):
                data[rng.randrange(len(data))] = rng.randrange(256)
            result = review(bytes(data))
            self.assertIn(result["status"], ("PASS", "OPEN"))
            self.assertLessEqual(len(json.dumps(result).encode()), 1024 * 1024)


if __name__ == "__main__":
    unittest.main()
