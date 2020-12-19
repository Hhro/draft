import idautils
import pefile
import json
import time

from pathlib2 import Path

pe = pefile.PE(idaapi.get_input_file_path())
pe.parse_data_directories()
iat = {}
tifs = ["OpenProcess", "VirtualAlloc", "CreateRemoteThread", "AdjustTokenPrivileges", "EnumProcessModules", "GetMessage", "ShowWindow", "FindWindow", "GetForegroundWindow", "GetAsyncKeyState",
        "OpenFIle", "FindFirstFileA", "ReadFile", "inet_addr", "InternetOpen", "InternetOpenUrl", "InternetReadUrl", "SetWindowsHookEx", "WinExec", "VirtualProtect", "ShellExecute"]
callers = {}

# disassemble PE


def disasm_all(out=""):
    asm = ""

    for func_addr in idautils.Functions():
        func = idaapi.get_func(func_addr)
        start = func.start_ea
        end = func.end_ea

        asm += get_func_name(func_addr)+":\n"

        while start <= end:
            asm += "\t"+idc.GetDisasm(start)+"\n"
            start = idc.next_head(start)
        asm += "\n"

    if out != "":
        with open(out, "w") as asm_out:
            asm_out.write(asm)


auto_wait()

# parse IAT
try:
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        iat.update({imp.name: imp.address for imp in entry.imports})
except:
    qexit(1)

# get xrefs of target API functions
for target in tifs:
    callers.update({target: []})

    if target in iat.keys():
        for xref in XrefsTo(iat[target]):
            if xref.iscode:
                callers[target].append(get_func_name(xref.frm))

# write xrefs
pe_path = Path(idaapi.get_input_file_path())
xref_path = pe_path.parent / ("xref_" + idaapi.get_root_filename() + ".json")
with open(str(xref_path), "w") as xref_out:
    json.dump(callers, xref_out)

train_path = Path(idaapi.get_input_file_path()).parent.parent.parent / "train"
train_path.mkdir(exist_ok=True)

#disasm_all(out=str(train_path / (idaapi.get_root_filename() + ".S")))
qexit(0)
