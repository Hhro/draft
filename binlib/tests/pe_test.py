import unittest as ut
import os
import pe_spec

from pathlib import Path
from binlib import Binary, PE

test_path = Path(__file__).resolve().parent

class PETest(ut.TestCase):
    def test_parse_iat(self):
        pass

    def test_parse_eat(self):
        pass

    def test_disassemble(self):
        pe_path = test_path / Path("pe.exe")    #Built without SEH
        pe = PE(Binary(pe_path))
        pe.disassemble(output=(test_path / "pe.s"))
        
        for func in pe.funcs().keys():
            if func not in pe_spec.funcs.keys():
                raise Exception(f"{func} not in spec.")

    def test_collect_eat(self):
        pass
