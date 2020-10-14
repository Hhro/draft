import os
import pefile
from typing import Tuple
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_64


def is_PE(f: bytes): return f[:2] == b"MZ"
def is_ELF(f: bytes): return f[:4] == b"\x7fELF"
def MiB_size(f: bytes): return round(len(f)/(1024**2), 3)

def is_jxx(opcode: str):
    if opcode.startswith("j"):
        return True

def is_prolog(opcode: str, operands: str, raw: bytes):
    prolog_ops=['lea', 'xor', 'sub', 'jmp', 'ret', 'mov', 'push', 'cmp']

    if opcode in prolog_ops: return True     #wrapper
    else: return False 

class Binary:
    def __init__(self, path: Path):
        self._path: Path = path
        self._raw: bytes = path.read_bytes()
        self._fformat: str = None

        if is_PE(self._raw):
            self._fformat = "PE"
        elif is_ELF(self._raw):
            self._fformat = "ELF"
        else:
            raise Exception("Unknown file format.")

    def fformat(self):
        return self._fformat


class PE(Binary):
    def __init__(self, binary: Binary):
        self._path: Path = binary._path
        self._comm: str = self._path.stem
        self._raw: bytes = binary._raw
        self._fformat: str = binary._fformat
        self._pefile: pefile.PE = pefile.PE(data=self._raw)
        self._iat: Dict[bytes, pefile.ImportData] = None
        self._eat: Dict[bytes, pefile.ExportData] = None
        self._funcs: Dict[str, Tuple[int, int]] = None

        self._pefile.parse_data_directories()
    
    def __len__(self):
        return len(self._raw)
    
    def funcs(self):
        return self._funcs

    def disassemble(self, output: Path = None):
        eop = self._pefile.OPTIONAL_HEADER.AddressOfEntryPoint
        code_section = self._pefile.get_section_by_rva(eop)

        code_dump = code_section.get_data()

        code_addr = self._pefile.OPTIONAL_HEADER.ImageBase + code_section.VirtualAddress
        md = Cs(CS_ARCH_X86, CS_MODE_64)

        self._funcs = {}
        in_function = False
        is_oneline = False
        fnc_name = None
        fnc_st = None
        fnc_end = None
        disassembled = ""

        for insn in md.disasm(code_dump, code_addr):
            addr = insn.address
            opcode = insn.mnemonic
            operands = insn.op_str
            raw = insn.bytes

            #Function usually begins with 'prolog' or 
            #in case of wrapper, it simply begins with 'jmp'.
            if in_function:                
                if opcode == "int3" or is_oneline:
                    in_function = False
                    is_oneline = False
                    fnc_end = addr
                    self._funcs.update({fnc_name: (fnc_st, fnc_end)})
                else:
                    disassembled += f"\t{opcode}\t{operands}\n"

            if not in_function:
                if is_prolog(opcode, operands, raw):
                    fnc_name = f"sub_{hex(addr)[2:]}"
                    disassembled += f"{fnc_name}:\n\t{opcode}\t{operands}\n"
                    in_function = True
                    fnc_st = addr

                    if opcode == "jmp" or opcode == "ret":
                        is_oneline = True
            
        if output:
            output.write_text(disassembled)
        else:
            print(disassembled)

    def parse_iat(self):
        self._iat = {}
        try:
            for entry in self._pefile.DIRECTORY_ENTRY_IMPORT:
                self._iat.update(
                    {entry.dll: [imp for imp in entry.imports]}
                )
        except:
            return

    def parse_eat(self):
        self._eat = {}
        try:
            for entry in self._pefile.DIRECTORY_ENTRY_EXPORT.symbols:
                self._eat.update(
                    {
                        entry.name: entry
                    }
                )
        except:
            return

    def dump(self):
        print(f"[i] Dump of {self._comm}")
        print(f"Path: {self._path}")
        print(f"Format: {self._fformat}")

        if self._iat == None:
            self.parse_iat()
        print(f"IAT: ")
        for dll in self._iat.keys():
            print(f" {dll}")
            for func in self._iat[dll]:
                print(f"  |--- {hex(func.address)} {func.name}")

        if self._eat == None:
            self.parse_eat()
        print(f"EAT: ")
        for dll in self._eat.keys():
            print(f" {dll}")
            for func in self._eat[dll]:
                print(f"  |--- {hex(func.address)} {func.name}")
