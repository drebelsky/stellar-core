#!/usr/bin/env python3

# Copyright 2024 Stellar Development Foundation and contributors. Licensed
# under the Apache License, Version 2.0. See the COPYING file at the root
# of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

import argparse
from base64 import b64decode
from concurrent.futures import ProcessPoolExecutor
import csv
import json
from typing import Any, Callable
import subprocess
import sys

import numpy as np
import numpy.typing as npt

# Needed to be able to read large base64-encoded XDR blobs from the wasm_sizes table
csv.field_size_limit(sys.maxsize)


def make_decoder() -> Callable[[bytes], dict[str, Any]]:
    process = subprocess.Popen(
        [
            "stellar",
            "xdr",
            "decode",
            "--type",
            "TransactionEnvelope",
            "--input",
            "stream",
            "--output",
            "json",
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
    )

    # asserts and assignment to satisfy typechecker that these really are streams
    assert process.stdin
    assert process.stdout
    stdin = process.stdin
    stdout = process.stdout

    def decode_xdr(xdr: bytes) -> dict[str, Any]:
        """Decode a TransactionEnvelope using the stellar-xdr tool."""
        stdin.write(xdr)
        stdin.flush()
        return json.loads(stdout.readline())

    return decode_xdr


# Note: decode_xdr is a global that gets initialized in process_wasm_row so
# that each Python subprocess runs an independent copy of stellar xdr decode
decode_xdr = None


def process_wasm_row(row: dict[str, str]) -> int:
    """
    Process a row from the wasm_sizes table.
    """

    global decode_xdr
    if decode_xdr is None:
        decode_xdr = make_decoder()

    envelope_xdr = b64decode(row["tx_envelope"], validate=True)
    envelope = decode_xdr(envelope_xdr)

    # Grab inner transaction from fee bump frames
    if "tx_fee_bump" in envelope:
        envelope = envelope["tx_fee_bump"]["tx"]["inner_tx"]
    operations = envelope["tx"]["tx"]["operations"]
    assert len(operations) == 1
    body = operations[0]["body"]

    ihf = body["invoke_host_function"]
    assert "host_function" in ihf
    assert "upload_contract_wasm" in ihf["host_function"]
    # Count wasm bytes
    wasm = ihf["host_function"]["upload_contract_wasm"]
    return len(bytes.fromhex(wasm))


def to_normalized_histogram(
    data: npt.ArrayLike, max_bins: int, max_output_bins: int
) -> None:
    """
    Given a set of data, print a normalized histogram with at most
    MAX_OUTPUT_BINS bins formatted for easy pasting into supercluster.
    """
    for i in range(max_bins, max_output_bins - 1, -1):
        hist, bins = np.histogram(data, bins=i)

        # Add up counts in each bin
        total = np.sum(hist)

        # Normalize each count to parts per ten-thousand
        normalized = (hist / total) * 1000

        # Convert to ints
        normalized = normalized.round().astype(int)

        if len([x for x in normalized if x != 0]) <= max_output_bins:
            break
        # We have too many non-zero output bins. Reduce the number of total bins
        # and try again.
    else:
        raise RuntimeError(
            f"Could not generate {max_output_bins} bins (make sure max_output_bins is less than max_bins)!"
        )

    # Find midpoint of each bin
    midpoints = np.empty(len(bins) - 1)
    for i in range(len(bins) - 1):
        midpoints[i] = (bins[i] + bins[i + 1]) / 2

    # Convert to ints
    midpoints = midpoints.round().astype(int)

    # Format for easy pasting into supercluster
    print("[ ", end="")
    for count, point in zip(normalized, midpoints):
        if count == 0:
            # Drop empty bins
            continue
        print(f"({point}, {count}); ", end="")
    print("]")


def process_soroban_history(
    history_transactions_csv: str, max_bins: int, max_output_bins: int
) -> None:
    """Generate histograms from data in the history_transactions table."""
    with open(history_transactions_csv) as f:
        assert (
            f.readline().strip()
            == "soroban_resources_instructions,soroban_resources_write_bytes,envelope_size"
        )
        data = np.loadtxt(f, dtype=int, delimiter=",")
    assert len(data.shape) == 2 and data.shape[1] == 3
    print("Instructions:")
    to_normalized_histogram(data[:, 0], max_bins, max_output_bins)

    # Convert write_bytes to kilobytes
    write_kilobytes = (data[:, 1] / 1024).round().astype(int)
    print("\nI/O Kilobytes:")
    to_normalized_histogram(write_kilobytes, max_bins, max_output_bins)

    print("\nTransaction Size Bytes:")
    to_normalized_histogram(data[:, 2], max_bins, max_output_bins)


def process_wasm_sizes(
    wasm_sizes_csv: str, workers: int, max_bins: int, max_output_bins: int
) -> None:
    """Generate a histogram for wasm sizes from data in the wasm_sizes table."""
    with open(wasm_sizes_csv) as f:
        reader = csv.DictReader(f)

        # Decode XDR in parallel
        with ProcessPoolExecutor(workers) as executor:
            wasms = list(executor.map(process_wasm_row, reader))

    print("\nWasm Size Bytes:")
    to_normalized_histogram(wasms, max_bins, max_output_bins)


def process_soroban_events(
    history_contract_events_csv: str, max_bins: int, max_output_bins: int
) -> None:
    """
    Generate a histogram for data entries from data in the
    history_contract_events table.
    """
    with open(history_contract_events_csv) as f:
        assert f.readline().strip() == "topics_decoded,data_decoded"
        start = '"[{""symbol"":""core_metrics""},{""symbol"":""write_entry""}]","{""u64"":""'
        end = '""}"'
        processed_rows = []
        for line in f:
            line = line.strip()
            assert line.startswith(start) and line.endswith(
                end
            ), f"Unexpected line: {line}"
            number = line[len(start) : -len(end)]
            processed_rows.append(int(number))

        print("Data Entries:")
        to_normalized_histogram(processed_rows, max_bins, max_output_bins)


def process_classic_transactions(
    classic_transactions_csv: str, max_bins: int, max_output_bins: int
) -> None:
    """
    Generate a histogram for classic data entries from data in the
    history_transactions table.
    """
    with open(classic_transactions_csv) as f:
        assert f.readline().strip() == "envelope_size"
        data = np.loadtxt(f, dtype=int, delimiter=",")
    assert len(data.shape) == 1

    print("Classic Transaction Sizes:")
    to_normalized_histogram(data, max_bins, max_output_bins)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="See the comments at the end of this help for sample Hubble queries to generate the appropriate data.",
        epilog="""You can use the following sample queries as a jumping off point for writing your own queries to generate these CSV files:

history_transactions sample query
SELECT soroban_resources_instructions, soroban_resources_write_bytes, LENGTH(FROM_BASE64(tx_envelope)) envelope_size FROM `crypto-stellar.crypto_stellar.history_transactions` WHERE batch_run_date >= DATETIME("2026-07-01") AND batch_run_date < DATETIME("2026-07-08") AND soroban_resources_instructions > 0

wasm_sizes sample query
DECLARE start_ts TIMESTAMP DEFAULT TIMESTAMP("2026-07-01");
DECLARE end_ts   TIMESTAMP DEFAULT TIMESTAMP("2026-07-08");

WITH wasm_ops AS (
  SELECT DISTINCT transaction_hash
  FROM `crypto-stellar.crypto_stellar_dbt.enriched_history_operations_soroban`
  WHERE closed_at >= start_ts
    AND closed_at <  end_ts
    AND soroban_operation_type = "upload_wasm"
)
SELECT
  t.tx_envelope
FROM `crypto-stellar.crypto_stellar.history_transactions` AS t
JOIN wasm_ops USING (transaction_hash)
WHERE t.closed_at >= start_ts
  AND t.closed_at <  end_ts

history_contract_events sample query
SELECT
  topics_decoded, data_decoded
FROM
  `crypto-stellar.crypto_stellar.history_contract_events`
WHERE
  type = 2 
  AND closed_at >= TIMESTAMP("2026-07-01")
  AND closed_at < TIMESTAMP("2026-07-08")
  AND contains_substr(topics_decoded, "write_entry")

NOTE: this query filters out anything that isn't a write_entry. This is required for the script to work correctly!

classic_transactions sample query
SELECT
    LENGTH(FROM_BASE64(tx_envelope)) as envelope_size
FROM `crypto-stellar.crypto_stellar.history_transactions`
WHERE
    batch_run_date >= DATETIME("2026-07-01") AND batch_run_date < DATETIME("2026-07-08")
    AND soroban_resources_instructions = 0
""",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "history_transactions", type=str, help="history_transactions csv file"
    )
    parser.add_argument("wasm_sizes", type=str, help="wasm_sizes csv file")
    parser.add_argument(
        "history_contract_events", type=str, help="history_contract events csv file."
    )
    parser.add_argument(
        "classic_transactions", type=str, help="classic_transactions csv file."
    )
    parser.add_argument(
        "-j",
        "--workers",
        type=int,
        default=9,
        help="Number of Python subprocesses to run in parallel",
    )
    parser.add_argument(
        "--max-bins",
        type=int,
        default=100,
        help="Maximum number of histogram bins to generate",
    )
    parser.add_argument(
        "--max-output-bins",
        type=int,
        default=10,
        help="Maximum number of histogram bins to output. This is much lower than MAX_BINS, because most bins will be empty (and therefore pruned from the output). If there are too many bins with nonzero values, the script will reduce the number of bins until there are at most MAX_OUTPUT_BINS bins with nonzero values.",
    )
    args = parser.parse_args()

    print("Processing data. This might take a few minutes...")

    process_soroban_history(
        args.history_transactions, args.max_bins, args.max_output_bins
    )
    process_wasm_sizes(
        args.wasm_sizes, args.workers, args.max_bins, args.max_output_bins
    )
    print()
    process_soroban_events(
        args.history_contract_events, args.max_bins, args.max_output_bins
    )
    print()
    process_classic_transactions(
        args.classic_transactions, args.max_bins, args.max_output_bins
    )


if __name__ == "__main__":
    main()
