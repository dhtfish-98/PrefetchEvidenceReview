"""Finite lower-only budgets and integer FILETIME evidence."""

from dataclasses import dataclass, fields
from datetime import datetime, timedelta, timezone


class Issue(Exception):
    def __init__(self, code, offset=None):
        self.code, self.offset = code, offset
        super().__init__(code)


@dataclass(frozen=True)
class Limits:
    file_bytes: int = 16 * 1024 * 1024
    metrics: int = 4096
    traces: int = 65536
    strings: int = 8192
    string_units: int = 16383
    string_bytes: int = 1024 * 1024
    volumes: int = 32
    file_references: int = 65536
    directories: int = 8192
    followed_references: int = 250000
    report_bytes: int = 1024 * 1024


DEFAULT_LIMITS = Limits()


def check_limits(limits):
    if type(limits) is not Limits:
        raise Issue("limits_type")
    for field in fields(Limits):
        value = getattr(limits, field.name)
        if type(value) is not int or not 0 < value <= getattr(DEFAULT_LIMITS, field.name):
            raise Issue("limits_range")
    if limits.report_bytes < 256:
        raise Issue("minimum_report_budget")


def time_evidence(ticks, offset):
    if ticks == 0:
        return {"ticks_100ns": 0, "utc_100ns": None, "status": "UNSET", "offset": offset}
    try:
        value = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=ticks // 10)
    except OverflowError:
        raise Issue("filetime_range", offset) from None
    stamp = value.strftime("%Y-%m-%dT%H:%M:%S") + f".{ticks % 10000000:07d}Z"
    return {"ticks_100ns": ticks, "utc_100ns": stamp, "status": "UNAUTHENTICATED", "offset": offset}
