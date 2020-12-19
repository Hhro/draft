import glob
import argparse
import platform

import json
import logger
import numpy as np
import binlib
import clonelib

from typing import List, Dict
from pathlib import Path

if __name__ == '__main__':
    targets: List[Path] = []
    dataset: Dict[str, Path] = {}
    train_dir: Path = None

    # Setup ArgumentParser()
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-i", "--target", help="Target binary"
    )
    parser.add_argument(
        "-d", "--targets", help="Directory of target binaries", default="targets"
    )
    parser.add_argument(
        "-f", "--format", choices=["ELF", "PE"], help="Binary format", required=True
    )
    parser.add_argument(
        "--train", help="Directory of training functions", default="dataset/train"
    )

    args = parser.parse_args()

    # Collect target function(s)
    if args.target:
        target_path = Path(args.target).resolve()

        if not target_path.exists():
            raise Exception(f"File not found: {str(target_path)}")
        targets = [Path(args.target)]

    elif args.targets:
        target_path = Path(args.targets).resolve()

        if not target_path.exists():
            raise Exception(f"Directory not found: {str(target_path)}")
        targets = [Path(f) for f in glob.glob(args.targets+"/*.S")]

    # Collect train functions
    train_path = Path(args.train).resolve()
    trainees = [Path(f) for f in glob.glob(args.train+"/*.S")]

    # Disassemble all binaries in training_dir
    tifs = ["OpenProcess", "VirtualAlloc", "CreateRemoteThread", "AdjustTokenPrivileges",
            "EnumProcessModules", "GetMessage", "ShowWindow", "FindWindow", "GetForegroundWindow", "GetAsyncKeyState",
            "OpenFIle", "FindFirstFileA", "ReadFile", "inet_addr", "InternetOpen", "InternetOpenUrl", "InternetReadUrl",
            "SetWindowsHookEx", "WinExec", "VirtualProtect", "ShellExecute"]

    with open(train_path/"xref.json", "r") as train_xref_in:
        train_xref = json.load(train_xref_in)

    with open(target_path/"xref.json", "r") as target_xref_in:
        target_xref = json.load(target_xref_in)

    clonelib.train(trainees, targets, train_xref, target_xref, tifs)
