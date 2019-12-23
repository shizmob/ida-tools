import ida_idaapi
import ida_nalt
import ida_bytes
import ida_name
import ida_funcs
import ida_hexrays
import idautils


def is_str_literal(addr):
    return ida_bytes.is_strlit(ida_bytes.get_flags(addr))

def get_str_literal(addr):
    type = ida_nalt.get_str_type(addr)
    length = ida_bytes.get_max_strlit_length(addr, type, ida_bytes.ALOPT_IGNHEADS)
    return ida_bytes.get_strlit_contents(addr, length, type)


class CallAnalyzer(ida_hexrays.ctree_visitor_t):
    def __init__(self, targets):
        ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
        self.targets = targets
        self.results = []

    def reset(self):
        self.results = []

    def visit_expr(self, e):
        if e.op != ida_hexrays.cot_call:
            return 0

        func = e.x
        args = e.a
        if func.op != ida_hexrays.cot_obj:
            return 0

        name = ida_funcs.get_func_name(func.obj_ea)
        if name not in self.targets:
            return 0

        idx = self.targets[name]
        if idx >= len(args):
            return 0

        arg = args[idx].obj_ea
        if not is_str_literal(arg):
            return 0

        self.results.append(get_str_literal(arg))
        return 0


def auto_rename_single(ca, addr):
    cfunc = ida_hexrays.decompile(addr)
    if not cfunc:
        return

    ca.reset()
    ca.apply_to(cfunc.body, None)
    if ca.results:
        ida_name.set_name(addr, ca.results[-1], ida_name.SN_AUTO | ida_name.SN_NOCHECK | ida_name.SN_NOWARN)

def auto_rename_all(targets):
    refs = set()
    for name in targets:
        addr = ida_name.get_name_ea(ida_idaapi.BADADDR, name)
        if not addr:
            continue
        for ref in idautils.CodeRefsTo(addr, True):
            func = ida_funcs.get_func(ref)
            refs.add(func.start_ea)

    ca = CallAnalyzer(targets)
    for addr in refs:
        rename_single(ca, addr)
