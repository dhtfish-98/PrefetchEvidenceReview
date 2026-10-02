"""Sanitized bounded local-only immutable Prefetch input."""

import argparse
import json

from .files import read_local
from .model import Issue
from .parser import review


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise Issue("arguments")


def main(argv=None):
    parser = Parser(
        description="Static v17/v23/v26 Prefetch evidence; paths are never accessed or executed."
    )
    parser.add_argument("file")
    parser.add_argument("--reveal-strings", action="store_true")
    try:
        args = parser.parse_args(argv)
        result = review(read_local(args.file), args.reveal_strings)
    except (Issue, OSError, UnicodeError, ValueError) as error:
        result = review(None)
        result["issues"] = [
            {"code": error.code if isinstance(error, Issue) else "input_error", "offset": None}
        ]
    print(json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
    return 0 if result["status"] == "PASS" else 2
