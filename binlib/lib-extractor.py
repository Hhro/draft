import argparse
import context

from pathlib import Path
from binlib import Binary, PE

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-i", "--binary", help="Input binary", required=True
    )
    parser.add_argument(
        "--dll", help="dll search space"
    )
    parser.add_argument(
        "--so", help="so search space"
    )

    args = parser.parse_args()
    bin_path = Path(args.binary).resolve().absolute()

    context.DLL_SEARCH_SPACE = Path(args.dll) if args.dll else []
    context.SO_SEARCH_SPACE = Path(args.so) if args.so else []

    if not bin_path.exists():
        raise Exception(f"File not exists: '{str(bin_path)}'")

    binary = Binary(bin_path)

    if binary.fformat() == "PE":
        pe = PE(binary)
        pe.collect_imported_dlls()
    elif binary.fformat() == "ELF":
        elf = ELF(binary)
