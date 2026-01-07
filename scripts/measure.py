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


def types_for(mode: str, check: bool) -> list[str]:
    types = ["DEFAULT"]
    if mode != "ITERATE_BACKWARDS":
        types += [
            "LEDGER_ENTRY_LK_HASH",
            "LEDGER_ENTRY_TO_OPAQUE_HASH",
            "LEDGER_ENTRY_XDR_COMPUTE_HASH",
        ]
        if not check:
            types += [
                "OPAQUE_VEC",
                "OPAQUE_VEC_XDR_HASH",
            ]
    return types


def main():
    parser = argparse.ArgumentParser("measure.py", description="")
    parser.add_argument(
        "action", type=Action, choices=["compile", "time"], default=Action.COMPILE
    )
    parser.add_argument(
        "--verbose",
        "-v",
        help="in compile, show make stdout; in time, show make stderr",
        action="store_true",
    )
    parser.add_argument(
        "--check",
        "-c",
        help="check that we generate the right in-memory state",
        action="store_true",
    )
    parser.add_argument(
        "-n",
        help="number of times to run each configuration",
        type=int,
        default=1,
    )
    args = parser.parse_args()

    if args.action == Action.COMPILE:
        stdout = None if args.verbose else subprocess.DEVNULL
        stderr = None
    else:
        stdout = subprocess.DEVNULL
        stderr = None if args.verbose else subprocess.DEVNULL

    reference = b""
    if args.check:
        try:
            with open("reference.bin", "rb") as f:
                reference = f.read()
        except FileNotFoundError:
            print(
                "--check specified, but reference.bin does not exist", file=sys.stderr
            )
            exit(1)

    for option in ["NONE", "PRESIZE"]:
        opt = option
        if args.check:
            opt += " | Options::DUMP"
        for mode in [
            "NORMAL",
            "N_WAY_MERGE",
            "N_WAY_MERGE_BUCKET_ENTRY_ID_CMP",
            "ITERATE_BACKWARDS",
            "ITERATE_PARALLEL",
        ]:
            for type_ in types_for(mode, args.check):
                print("GREP CONFIG:", option, type_, mode, file=sys.stderr)
                with open("src/util/settings.h", "w") as f:
                    f.write(TEMPLATE.format(opt, type_, mode))
                res = subprocess.run(
                    ["make", "-j{}".format(os.cpu_count())],
                    stdout=stdout,
                    stderr=stderr,
                )
                if args.action == Action.TIME:
                    assert res.returncode == 0
                    for i in range(args.n):
                        print("GREP ITER", i, file=sys.stderr)
                        try:
                            os.remove("/Users/daniel/sc-run/state.bin")
                        except FileNotFoundError:
                            pass
                        res = subprocess.run(
                            ["src/stellar-core", "test", "tmp"],
                            capture_output=True,
                            text=True,
                        )
                        assert res.returncode == 0
                        for line in res.stderr.splitlines():
                            if "GREP" in line:
                                print(line, file=sys.stderr)
                        if args.check:
                            with open("/Users/daniel/sc-run/state.bin", "rb") as f:
                                assert f.read() == reference


if __name__ == "__main__":
    main()
