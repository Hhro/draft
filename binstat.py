import binlib
import csv
import glob

from tqdm import tqdm
from typing import Dict
from binlib import is_PE, Binary, PE
from pathlib import Path

def generate_iat_stat(dataset_path):
    dataset_path = Path(dataset_path)

    dataset = [Path(p).resolve() for p in glob.glob(str(dataset_path)+"/*")]
    import_stat: Dict[bytes, int] = dict()

    for data in tqdm(dataset):
        try:
            binary = Binary(data)

            if binary.fformat() != "PE":
                continue
            
            pe = PE(binary)
            iat = pe.iat()
            dlls = iat.keys()

            for dll in dlls:
                for func in iat[dll]:
                    if func.name not in import_stat.keys():
                        import_stat.update({func.name:1})
                    else:
                        import_stat[func.name] += 1
        except:
            continue

    with open(str(dataset_path.resolve() / Path("iat.csv")), "w") as iat_out:
        iat_writer = csv.writer(iat_out)
        
        for func, cnt in import_stat.items():
            iat_writer.writerow([func, cnt])

if __name__ == "__main__":
    generate_iat_stat("dataset/malware")
