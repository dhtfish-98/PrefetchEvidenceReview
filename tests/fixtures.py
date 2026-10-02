"""Independent complete harmless Prefetch records and recorded byte-position facts."""

import struct

STAMP = 116444736000000000
END = 0xFFFFFFFF


def put(raw, offset, value, fmt="<I"):
    struct.pack_into(fmt, raw, offset, value)


def example(version=26, volumes=1, times=None, empty=False):
    info_size = {17: 68, 23: 156, 26: 220}[version]
    raw = bytearray(84 + info_size)
    strings = (
        []
        if empty
        else [r"\DEVICE\SYNTHETICVOLUME1\SYNTHETIC.EXE", r"\DEVICE\SYNTHETICVOLUME1\HARMLESS.DLL"]
    )
    chars = []
    strings_bytes = bytearray()
    for name in strings:
        encoded = name.encode("utf-16le")
        chars.append((len(strings_bytes), len(encoded) // 2))
        strings_bytes += encoded + b"\0\0"
    metrics_offset = len(raw)
    metrics_size = 20 if version == 17 else 32
    for index, (relative, units) in enumerate(chars):
        row = bytearray(metrics_size)
        put(row, 0, index * 2)
        put(row, 4, 2)
        if version == 17:
            put(row, 8, relative)
            put(row, 12, units)
            put(row, 16, 0x200)
        else:
            put(row, 8, 3)
            put(row, 12, relative)
            put(row, 16, units)
            put(row, 20, 0x200)
            put(row, 24, (7 << 48) | (0x123456789ABC + index), "<Q")
        raw += row
    trace_offset = len(raw)
    for index in range(len(strings) * 2):
        row = bytearray(12)
        put(row, 0, index + 1 if index % 2 == 0 else END)
        put(row, 4, index + 2)
        row[8:12] = bytes([2, 8, 255, 127])
        raw += row
    strings_offset = len(raw)
    raw += strings_bytes
    volume_offset = len(raw)
    if empty:
        volumes = 0
    volume_entry = 40 if version == 17 else 104
    volume_raw = bytearray(volumes * volume_entry)
    volume_facts = []
    for index in range(volumes):
        entry = index * volume_entry
        path = rf"\DEVICE\SYNTHETICVOLUME{index + 1}"
        path_offset = len(volume_raw)
        encoded = path.encode("utf-16le")
        volume_raw += encoded + b"\0\0"
        ref_offset = len(volume_raw)
        refs = [(8 << 48) | 0x112233445566, (9 << 48) | 0xABCDEF012345]
        volume_raw += struct.pack("<II", 1 if version == 17 else 3, len(refs))
        if version != 17:
            volume_raw += bytes(8)
        volume_raw += b"".join(struct.pack("<Q", value) for value in refs)
        ref_size = len(volume_raw) - ref_offset
        dirs_offset = len(volume_raw)
        directories = [path + r"\SYNTHETIC", path + r"\SYNTHETIC\DATA"]
        for name in directories:
            data = name.encode("utf-16le")
            volume_raw += struct.pack("<H", len(data) // 2) + data + b"\0\0"
        for where, value in [
            (0, path_offset),
            (4, len(encoded) // 2),
            (16, 0xAABBCC00 + index),
            (20, ref_offset),
            (24, ref_size),
            (28, dirs_offset),
            (32, len(directories)),
        ]:
            put(volume_raw, entry + where, value)
        put(volume_raw, entry + 8, STAMP + index * 10000000, "<Q")
        volume_facts.append(
            {
                "path": path,
                "created": STAMP + index * 10000000,
                "serial": 0xAABBCC00 + index,
                "references": refs,
                "directories": directories,
                "entry": volume_offset + entry,
                "path_offset": volume_offset + path_offset,
                "refs_offset": volume_offset + ref_offset,
                "dirs_offset": volume_offset + dirs_offset,
            }
        )
    raw += volume_raw
    slots = 8 if version == 26 else 1
    times = [STAMP + (20 - i) * 10000000 + 9 for i in range(slots)] if times is None else times
    assert len(times) == slots
    for index, ticks in enumerate(times):
        put(raw, (120 if version == 17 else 128) + index * 8, ticks, "<Q")
    put(raw, {17: 144, 23: 152, 26: 208}[version], 18)
    for index, value in enumerate(
        [
            metrics_offset,
            len(strings),
            trace_offset,
            len(strings) * 2,
            strings_offset,
            len(strings_bytes),
            volume_offset,
            volumes,
            len(volume_raw),
        ]
    ):
        put(raw, 84 + index * 4, value)
    put(raw, 0, version)
    raw[4:8] = b"SCCA"
    put(raw, 8, 17)
    put(raw, 12, len(raw))
    raw[16:44] = "SYNTHETIC.EXE\0".encode("utf-16le")
    put(raw, 76, 0xABCDEF12)
    facts = {
        "version": version,
        "executable": "SYNTHETIC.EXE",
        "run_count": 18,
        "times": times,
        "strings": strings,
        "volumes": volume_facts,
        "metrics_offset": metrics_offset,
        "metric_size": metrics_size,
        "trace_offset": trace_offset,
        "strings_offset": strings_offset,
        "volume_offset": volume_offset,
        "volume_size": len(volume_raw),
    }
    return bytes(raw), facts
