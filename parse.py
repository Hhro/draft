#!/usr/bin/env python
import subprocess
import os
import json
import glob
import pefile
from tqdm import tqdm
from pathlib import Path

TRAIN = 10000
'''
# clean garbage
pes = glob.glob("dataset/malware/malwares_2018/*.vir")

for pe in pes[:TRAIN]:
    ida_trash = [".idb", ".id0", ".id1", ".id2", ".nam", ".til"]

    for tr in ida_trash:
        if Path(pe+tr).exists():
            print(f"Delete garbage of {pe+tr}")
            os.remove(pe+tr)

for x in glob.glob("dataset/malware/malwares_2018/xref_*"):
    print(f"Delete {x}")
    os.remove(str(Path(x)))

for x in glob.glob("dataset/train/*.S"):
    print(f"Delete {x}")
    os.remove(str(Path(x)))

# Benign to Target
estms = glob.glob("dataset/benign/pes/*.exe")
estms += glob.glob("dataset/benign/pes/*.vir")

target_dir = Path("dataset/target")
for estm in estms:
    print(f"Processing {estm}")

    if (target_dir / (Path(estm).name + ".S")).exists():
        continue

    pe = pefile.PE(estm)
    machine_bit = pe.FILE_HEADER.Machine
    res = 0
    if machine_bit == 0x14c:
        res = subprocess.run(["/mnt/c/Program Files/IDA Pro 7.5/ida.exe", "-c", "-A", "-Sscripts/gogogo.py",
                              estm])
    elif machine_bit == 0x8664:
        res = subprocess.run(["/mnt/c/Program Files/IDA Pro 7.5/ida64.exe", "-c", "-A", "-Sscripts/gogogo.py",
                              estm])

    if res == 0:
        print(f"Failed to process {estm}")

estms = glob.glob("dataset/benign/pes/*.exe")
estms += glob.glob("dataset/benign/pes/*.vir")
target_dir = Path("dataset/target")

merged = {}
with open("dataset/target/xref.json", "r") as xref_in:
    merged = json.load(xref_in)

print("Merge XREF of estimating set")
for estm in tqdm(estms):

    new_path = "dataset/target/"+Path(estm).name+".S"

    if not (target_dir / (Path(estm).name + ".S")).exists():
        asm_path = Path(estm).parent.parent.parent / \
            "train" / (Path(estm).name+".S")
        asm_path.rename(new_path)

    xref = "dataset/benign/pes/xref_"+Path(estm).name+".json"

    with open(xref, "r") as xref_in:
        xref_dict = json.load(xref_in)

    merged.update({new_path: xref_dict})

with open("dataset/target/xref.json", "w") as xref_out:
    json.dump(merged, xref_out)

# Malware to Training
pes = glob.glob("dataset/malware/malwares_2018/*.vir")
train_dir = Path("dataset/train")
for train in tqdm(pes[:TRAIN]):
    print(f"Processing {train}")

    pe = pefile.PE(train)
    machine_bit = pe.FILE_HEADER.Machine
    res = 0

    if machine_bit == 0x14c:
        res = subprocess.run(["/mnt/c/Program Files/IDA Pro 7.5/ida.exe", "-c", "-A", "-Sscripts/gogogo.py",
                              train])
    elif machine_bit == 0x8664:
        res = subprocess.run(["/mnt/c/Program Files/IDA Pro 7.5/ida64.exe", "-c", "-A", "-Sscripts/gogogo.py",
                              train])

    if res == 0:
        print(f"Failed to process {train}")

    if Path(train+".i64").exists():
        os.remove(train+".idb")
    if Path(train+".idb").exists():
        os.remove(train+".idb")
'''

merged = {}
pes = glob.glob("dataset/malware/malwares_2018/*.vir")
print("Merge XREF of training set")

# with open("dataset/train/xref.json", "r") as xref_out:
#merged = json.load(xref_out)

for pe in tqdm(pes[:TRAIN]):
    try:
        asm_path = "dataset/train/"+Path(pe).name+".S"
        xref = "dataset/malware/malwares_2018/xref_"+Path(pe).name+".json"

        with open(xref, "r") as xref_in:
            xref_dict = json.load(xref_in)

        merged.update({asm_path: xref_dict})
    except:
        continue

with open("dataset/train/xref.json", "w") as xref_out:
    json.dump(merged, xref_out)
