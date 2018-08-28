import json
from os import path

def save_export_renames(dest):
        exports = {}
        for i, ord, addr, name in idautils.Entries():
                exports[name] = idc.GetFunctionName(addr)
        with open(path.expanduser(dest), 'w') as f:
                json.dump(exports, f)

def load_export_renames(src):
        with open(path.expanduser(src), 'r') as f:
                exports = json.load(f)
        for orig, name in exports.items():
                addr = idc.get_name_ea_simple(orig.encode('utf-8'))
                idc.MakeName(addr, name.encode('utf-8'))
