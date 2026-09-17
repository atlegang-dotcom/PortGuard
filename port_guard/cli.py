# Command-line interface: argument definitions only, no detection logic.

import argparse
from typing import List, Optional


def build_arg_parser() -> argparse.ArgumentParser:
    raise NotImplementedError


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    raise NotImplementedError
