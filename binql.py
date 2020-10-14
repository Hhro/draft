import glob
import argparse
import platform

import logger
import numpy as np
import clonelib

from typing import List, Dict
from pathlib import Path

if __name__ == '__main__':
    targets: List[Path] = []
    dataset: Dict[str, Path] = {}
    train_dir: Path = None
    dll_dir: Path = None
    so_dir: Path = None

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
    parser.add_argument("--dll", help="Directory of DLLs")
    parser.add_argument("--so", help="Directory of SOs")

    args = parser.parse_args()

    # Collect target function(s)
    if args.target:
        target_path = Path(args.target).resolve()

        if not target_path.exists():
            raise Exception(f"File not found: {str(target_path)}")
        targets = [Path(args.target).resolve()]

    elif args.targets:
        targets_dir = Path(args.targets).resolve()

        if not targets_dir.exists():
            raise Exception(f"Directory not found: {str(targets_dir)}")
        targets = [Path(f).resolve() for f in glob.glob(args.targets+"/*")]

    # Directory of function repository
    train_dir = Path(args.train).resolve()
    os = platform.system()
    if not train_dir.exists():
        raise Exception(f"Directory not found: {str(train_dir)}")

    if args.format == "PE":
        if args.dll:
            dll_dir = Path(args.dll).resolve()
            if not dll_dir.exists():
                raise Exception(f"Directory not found: {str(dll_dir)}")
        else:
            if os == "Linux":
                raise Exception(
                    f"Argument missing: directory of DLL repository")
            elif os == "Windows":
                so_dir = find_system_dll_space()

        dataset.update({"train": train_dir, "library": dll_dir})

    elif args.format == "ELF":
        if args.so:
            so_dir = Path(args.so).resolve()
            if not so_dir.exists():
                raise Exception(f"Directory not found: {str(so_dir)}")
        else:
            if os == "Linux" and not args.so:
                so_dir = find_system_so_space()
            if os == "Windows" and not args.so:
                raise Exception(
                    f"Argument missing: directory of SO repository")

        dataset.update({"train": train_dir, "library": so_dir})

    clonelib.train(dataset["train"])
