import idautils
import idc
import json
from os import path

def save_export_renames(dest):
        exports = {}
        for addr in idautils.Functions():
                name = idc.GetFunctionName(addr)
                if name != 'sub_{:X}'.format(addr):
                        exports[addr] = name
        with open(path.expanduser(dest), 'w') as f:
                json.dump(exports, f, indent=4)

def load_export_renames(src):
        with open(path.expanduser(src), 'r') as f:
                exports = json.load(f)
        for addr, name in exports.items():
                addr = int(addr)
                name = name.encode('utf-8')
                idc.MakeName(addr, name)
