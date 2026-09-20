# Command-line interface: argument definitions only, no detection logic.

import argparse
from typing import List, Optional


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="A tool that detects TCP port scanning against your device. It monitors incoming SYN packets and tracks how many distinct ports each source IP touches within a rolling time window — the more ports touched in a shorter window, the more aggressive the scan is classified as."
    )

    parser.add_argument(
        "-n", "--threshold",
        type = int,
        default = 5,
        help = "The number of ports to trigger a scan alert"
    )

    parser.add_argument(
        "-w", "--window",
        type = float,
        default = 10.0,
        help = "The tracking time window in seconds"
    )

    parser.add_argument(
        "--allowlist",
        type = str,
        default = None,
        help = "A optional file of IP addresses that should not flagged no matter the amount of ports they hit - defaults to None if not passed"
    )

    parser.add_argument(
        "--log",
        type = str,
        default = None,
        help = "A optional file of the log, if passed it will log each alert to the file - defaults to None if not passed"
    )

    return parser


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = build_arg_parser()
    return parser.parse_args(argv)