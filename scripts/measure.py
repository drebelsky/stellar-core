"""
Run from root of repository
"""

import argparse
import subprocess
import enum
import os
import sys


class Action(enum.StrEnum):
    COMPILE = "compile"
    TIME = "time"


TEMPLATE = """\
#pragma once
#include "util/config.h"

namespace PopulateOptions
{{
constexpr Options options = Options::{};
constexpr DataEntriesType type = DataEntriesType::{};
constexpr Mode mode = Mode::{};
}}
"""


def main():
    parser = argparse.ArgumentParser("measure.py", description="")
    parser.add_argument(
        "action", type=Action, choices=["compile", "time"], default=Action.COMPILE
    )
    parser.add_argument(
        "--verbose", "-v", help="in compile, show make stdout; in time, show make stderr", action="store_true"
    )
    parser.add_argument(
        "-n",
        help="number of times to run each configuration",
        type=int,
    )
    args = parser.parse_args()
    if args.action == Action.COMPILE:
        stdout = None if args.verbose else subprocess.DEVNULL
        stderr = None
    else:
        stdout = subprocess.DEVNULL
        stderr = None if args.verbose else subprocess.DEVNULL
    stderr = (
        None if args.verbose and args.action == Action.COMPILE else subprocess.DEVNULL
    )
    for option in ["NONE", "PRESIZE"]:
        for mode in [
            "NORMAL",
            "N_WAY_MERGE",
            "N_WAY_MERGE_BUCKET_ENTRY_ID_CMP",
            "ITERATE_BACKWARDS",
            "ITERATE_PARALLEL",
        ]:
            types = (
                [
                    "DEFAULT",
                    "LEDGER_ENTRY_LK_HASH",
                    "LEDGER_ENTRY_TO_OPAQUE_HASH",
                    "LEDGER_ENTRY_XDR_COMPUTE_HASH",
                    "OPAQUE_VEC",
                    "OPAQUE_VEC_XDR_HASH",
                ]
                if mode != "ITERATE_BACKWARDS"
                else ["DEFAULT"]
            )
            for type_ in types:
                print("GREP CONFIG:", option, type_, mode, file=sys.stderr)
                with open("src/util/settings.h", "w") as f:
                    f.write(TEMPLATE.format(option, type_, mode))
                res = subprocess.run(
                    ["make", "-j{}".format(os.cpu_count())],
                    stdout=stdout,
                    stderr=stderr,
                )
                if args.action == Action.TIME:
                    assert res.returncode == 0
                    for i in range(args.n):
                        print("GREP ITER", i, file=sys.stderr)
                        for line in subprocess.run(
                            ["src/stellar-core", "test", "tmp"],
                            capture_output=True,
                            text=True,
                        ).stderr.splitlines():
                            if "GREP" in line:
                                print(line, file=sys.stderr)


if __name__ == "__main__":
    main()
