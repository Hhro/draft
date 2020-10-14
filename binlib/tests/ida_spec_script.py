from idautils import Functions
from idc import *

funcs = [_ for _ in Functions()]
prolog_ops = set()
results = {}

for func in funcs:
    f = get_func(func)
    
    results.update({"sub_{}".format(hex(f.start_ea)[2:-1]):(hex(f.start_ea)[:-1], hex(f.end_ea)[:-1])})
    prolog_ops.add(GetDisasm(f.start_ea).split()[0])

print(len(funcs))
print(prolog_ops)
print(results)
    
    
