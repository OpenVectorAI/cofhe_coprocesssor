from __future__ import annotations

from dataclasses import dataclass

import argparse

@dataclass(frozen=True, slots=True)
class CliArgs:
    config_file_path: str

def parse_args():
    parser = argparse.ArgumentParser(description='Run the client network')
    parser.add_argument('config', type=str, help='Path to the config file')
    args = parser.parse_args()
    return CliArgs(config_file_path=args.config)