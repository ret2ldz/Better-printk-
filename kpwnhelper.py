# -*- coding: utf-8 -*-

import ida_idaapi
import ida_hexrays
import ida_funcs
import ida_bytes
import ida_lines
import ida_typeinf
import idc
import re

KERN_LEVELS = {
    '0': "EMERG",
    '1': "ALERT",
    '2': "CRIT",
    '3': "ERR",
    '4': "WARNING",
    '5': "NOTICE",
    '6': "INFO",
    '7': "DEBUG"
}

debug = 0

def extract_kernel_printk_string(ea):
    """和你原来的 printk 提取函数一致"""
    try:
        if ea is None:
            return None
        b0 = ida_bytes.get_byte(ea)
        if b0 != 0x1:
            return None
        lvl_b = ida_bytes.get_byte(ea + 1)
        try:
            level_char = chr(lvl_b)
        except Exception:
            return None
        if level_char not in KERN_LEVELS:
            return None
        sstart = ea + 2
        send = sstart
        max_scan = 0x1000
        scanned = 0
        while ida_bytes.get_byte(send) != 0 and scanned < max_scan:
            send += 1
            scanned += 1
        raw = ida_bytes.get_bytes(sstart, send - sstart)
        if raw is None:
            return None
        try:
            actual = raw.decode('ascii', errors='replace')
        except Exception:
            actual = str(raw)
        actual = actual.replace('\n', '\\n')
        level_str = KERN_LEVELS[level_char]
        return f'KERN_{level_str}, "{actual}"'
    except Exception as e:
        print("[better_call] printk extract error:", e)
        return None

class VarAssignFinder(ida_hexrays.ctree_visitor_t):
    """
    用来在当前函数的 ctree 中查找所有赋值给 target_var 的 asg 语句，
    并把 RHS 解析成可能的地址（cot_ref -> obj_ea, cot_var -> 递归,
    cot_num/cot_obj/cot_cast -> 尝试解析为地址）。
    results 会被填充为 EA 列表。
    """
    def __init__(self, target_idx, parent_visitor, visited_vars):
        ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST | ida_hexrays.CV_INSNS)
        self.target_idx = target_idx
        self.parent = parent_visitor  # 用于递归调用 resolve_var_value
        self.visited = visited_vars if visited_vars is not None else set()
        self.results = []

    def _try_text_to_ea(self, text):
        """尝试把表达式文本解析为地址或通过名字拿到 EA（宽松解析）"""
        text = text.strip()
        if not text:
            return None
        # 常见的 hex/dec 形式
        try:
            ea = int(text, 0)
            return ea
        except Exception:
            pass
        # 如果是名字（symbol），尝试通过 ida 获取 EA
        try:
            ea = idc.get_name_ea_simple(text)
            if ea != idc.BADADDR:
                return ea
        except Exception:
            pass
        return None

    def visit_insn(self, insn):
        # 只处理表达式语句（赋值语句都在这里）
        if insn.op != ida_hexrays.cit_expr:
            return 0
        e = insn.cexpr
        if e is None:
            return 0
        # 只关心赋值，并且 LHS 是变量
        if e.op == ida_hexrays.cot_asg and e.x is not None and e.x.op == ida_hexrays.cot_var:
            try:
                lhs_idx = e.x.v.idx
            except Exception:
                return 0
            if lhs_idx != self.target_idx:
                return 0
            rhs = e.y
            # unwrap cast(s)
            while rhs is not None and rhs.op == ida_hexrays.cot_cast:
                # cot_cast 的子表达式通常放在 .x
                rhs = rhs.x

            if rhs is None:
                return 0

            # rhs == cot_ref (常见的字符串常量引用)
            if rhs.op == ida_hexrays.cot_ref:
                try:
                    ea = rhs.x.obj_ea
                    self.results.append(ea)
                except Exception:
                    pass
                return 0

            # rhs == cot_var -> 递归解析另一个变量
            if rhs.op == ida_hexrays.cot_var:
                try:
                    idx = rhs.v.idx
                    if idx not in self.visited:
                        # 避免循环
                        self.visited.add(idx)
                        res = self.parent.resolve_var_value(idx, self.visited)
                        self.results.extend(res)
                except Exception:
                    pass
                return 0

            # rhs == cot_num（数字常量），cot_obj（对象），或其它：尝试文本解析
            if rhs.op == ida_hexrays.cot_num:
                t = str(rhs)
                ea = self._try_text_to_ea(t)
                if ea is not None:
                    self.results.append(ea)
                return 0

            if rhs.op == ida_hexrays.cot_obj:
                # 有时会直接是对象引用
                try:
                    ea = rhs.obj_ea
                    self.results.append(ea)
                except Exception:
                    # fallback to text parse
                    t = str(rhs)
                    ea = self._try_text_to_ea(t)
                    if ea is not None:
                        self.results.append(ea)
                return 0

            # 其他情况：尝试以表达式文本解析
            try:
                t = str(rhs)
                ea = self._try_text_to_ea(t)
                if ea is not None:
                    self.results.append(ea)
            except Exception:
                pass

        return 0


class KernelCallVisitor(ida_hexrays.ctree_visitor_t):
    """
    通用的函数调用检测器，支持多个目标 API
    """
    def __init__(self, cfunc, targets, modifications):
        ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST | ida_hexrays.CV_INSNS)
        self.cfunc = cfunc
        self.targets = targets  # name -> handler
        self.modifications = modifications
        self.target_eas = self._resolve_target_addrs()
        self.printk_eas = {}
        self.kmalloc_eas = {}

    def _resolve_target_addrs(self):
        """解析目标函数名到 EA"""
        eas = {}
        for name in self.targets.keys():
            ea = idc.get_name_ea_simple(name)
            if ea != ida_idaapi.BADADDR:
                eas[ea] = name
        return eas

    def resolve_var_value(self, var_idx, visited=None):
        """
        对 var_idx 回溯赋值并返回一组可能的地址列表。
        visited 用于避免循环（set）。
        """
        if visited is None:
            visited = set()
        if var_idx in visited:
            return []
        visited.add(var_idx)

        finder = VarAssignFinder(var_idx, self, visited)
        # 这里用 apply_to 遍历当前函数的 ctree（注意：item 传 self.cfunc.body）
        try:
            finder.apply_to(self.cfunc.body, None)
        except Exception as e:
            # 应对极端情况打印错误并返回空
            print(f"[better_printk] VarAssignFinder.apply_to error: {e}")
            return []
        print(finder.results)
        return finder.results

    # ---- 放在 KernelCallVisitor 类内：辅助函数 ----
    def _strip_cast(self, e):
        """去掉连续的 cast，直到不是 cast 为止"""
        while e is not None and e.op == ida_hexrays.cot_cast:
            e = e.x
        return e

    def _num_of(self, e):
        """当 e 是常数时返回整数，否则 None"""
        try:
            if e is not None and e.op == ida_hexrays.cot_num:
                # IDA 不同版本 numval 获取略有差异，这里双保险
                try:
                    return e.numval()
                except Exception:
                    return int(e.n._value)
        except Exception:
            pass
        return None


    def visit_insn(self, insn):
        # 只处理表达式语句
        if insn.op != ida_hexrays.cit_expr:
            return 0
        expr = insn.cexpr
        if expr is None:
            return 0
        # 只处理函数调用
        if expr.op == ida_hexrays.cot_call: #printk&_printk is here
            # 获取被调用函数（call target）
            called = expr.x
            if called is None or called.op != ida_hexrays.cot_obj:
                return 0
            # 不是 target function 则跳过
            self.printk_eas = {ea for ea, name in self.target_eas.items() if name in ("printk", "_printk")}
            try:
                if called.obj_ea not in self.printk_eas:
                    return 0
            except Exception:
                return 0

            # 至少有一个参数
            if not expr.a or len(expr.a) < 1:
                return 0
            arg = expr.a[0]
            # unwrap cast
            while arg is not None and arg.op == ida_hexrays.cot_cast:
                arg = arg.x
            if arg is None:
                return 0

            addrs = []
            # 直接引用字符串
            if arg.op == ida_hexrays.cot_ref:
                try:
                    addrs.append(arg.x.obj_ea)
                except Exception:
                    pass
            # 变量：去回溯
            elif arg.op == ida_hexrays.cot_var:
                try:
                    strings = ""
                    addrs1 = self.resolve_var_value(arg.v.idx) #这里回溯
                    for i in addrs1:
                        opt = extract_kernel_printk_string(i)
                        strings += f"| {i:#x} | {opt}"
                    self.modifications.append(strings)
                    try:
                        idc.set_cmt(insn.ea, opt, 0)
                    except Exception:
                        pass
                    print(f"[better_printk] Found printk @ {insn.ea:#x}, extract: {strings}")
                except Exception:
                    pass
            # 数字常量或其它，尝试文本解析
            else:
                t = str(arg)
                # 简单解析 hex/dec 或 symbol 名
                try:
                    ea = int(t, 0)
                    addrs.append(ea)
                except Exception:
                    # 尝试按名字解析
                    ea = idc.get_name_ea_simple(t)
                    if ea != idc.BADADDR:
                        addrs.append(ea)

            my_dict = {}
            """
            if addr in addr_to_str:
                addr_to_str[addr] += " | " + string2
            else:
                addr_to_str[addr] = string2
            """
            for a in addrs:
                try:
                    opt = extract_kernel_printk_string(a)
                    if opt is None:
                        continue
                    self.modifications.append(opt)
                    # 将注释放在调用处（insn.ea）
                    try:
                        idc.set_cmt(insn.ea, opt, 0)
                    except Exception:
                        pass
                    print(f"[better_printk] Found printk @ {insn.ea:#x}, extract: {opt}")
                except Exception as e:
                    print("[better_printk] handle addr error:", e)
            return 0
        elif expr.op == ida_hexrays.cot_asg:
            # 赋值：LHS <- RHS
            lhs = expr.x
            rhs = expr.y

            # RHS 可能是 (type *)kmalloc_trace(...)
            call_expr = self._strip_cast(rhs)
            if call_expr is None or call_expr.op != ida_hexrays.cot_call:
                return 0

            # 被调函数
            called = call_expr.x
            if called is None or called.op != ida_hexrays.cot_obj:
                return 0

            target_name = self.target_eas.get(called.obj_ea)
            if target_name == "kmalloc_trace" or "_kmalloc_cache_noprof": #more ...
                if not call_expr.a or len(call_expr.a) < 2:
                    return 0
                # 第一个参数：cachep（可以是数组/指针表达式）
                cachep_expr = call_expr.a[0]
                cachep_arg = cachep_expr.x.print1(None)
                cachep_arg1 = cachep_expr.y.print1(None)
                get1 = cachep_arg1.split(' ', 1)[1]
                get0 = cachep_arg.split('"', 1)[1]
                print(f"Get Value {get0[:14]}:{get1}")
                if get0[:14] == "kmalloc_caches":
                    kmalloc_trace_array = [0,96,192,8,16,32,64,128,256,512,1024,2048,4096,8192,16384,32768,
                                           65536,131072,262144,524288,1048576,2097152]
                    get1 = re.sub(r'\D', '', get1)  # 移除所有非数字字符
                    get1 = int(get1)  # 将清理后的字符串转换为整数
                    get1 = kmalloc_trace_array[get1]
                    """const struct kmalloc_info_struct kmalloc_info[] __initconst = {
                    INIT_KMALLOC_INFO(0, 0),
                    INIT_KMALLOC_INFO(96, 96),
                    INIT_KMALLOC_INFO(192, 192),
                    INIT_KMALLOC_INFO(8, 8),
                    INIT_KMALLOC_INFO(16, 16),
                    INIT_KMALLOC_INFO(32, 32),
                    INIT_KMALLOC_INFO(64, 64),
                    INIT_KMALLOC_INFO(128, 128),
                    INIT_KMALLOC_INFO(256, 256),
                    INIT_KMALLOC_INFO(512, 512),
                    INIT_KMALLOC_INFO(1024, 1k),
                    INIT_KMALLOC_INFO(2048, 2k),
                    INIT_KMALLOC_INFO(4096, 4k),
                    INIT_KMALLOC_INFO(8192, 8k),
                    INIT_KMALLOC_INFO(16384, 16k),
                    INIT_KMALLOC_INFO(32768, 32k),
                    INIT_KMALLOC_INFO(65536, 64k),
                    INIT_KMALLOC_INFO(131072, 128k),
                    INIT_KMALLOC_INFO(262144, 256k),
                    INIT_KMALLOC_INFO(524288, 512k),
                    INIT_KMALLOC_INFO(1048576, 1M),
                    INIT_KMALLOC_INFO(2097152, 2M)
                    };
                    enum {
                    ___GFP_DMA_BIT,
                    ___GFP_HIGHMEM_BIT,
                    ___GFP_DMA32_BIT,
                    ___GFP_MOVABLE_BIT,
                    ___GFP_RECLAIMABLE_BIT,
                    ___GFP_HIGH_BIT,
                    ___GFP_IO_BIT,
                    ___GFP_FS_BIT,
                    ___GFP_ZERO_BIT,
                    ___GFP_UNUSED_BIT,	/* 0x200u unused */
                    ___GFP_DIRECT_RECLAIM_BIT,
                    ___GFP_KSWAPD_RECLAIM_BIT,
                    ___GFP_WRITE_BIT,
                    ___GFP_NOWARN_BIT,
                    ___GFP_RETRY_MAYFAIL_BIT,
                    ___GFP_NOFAIL_BIT,
                    ___GFP_NORETRY_BIT,
                    ___GFP_MEMALLOC_BIT,
                    ___GFP_COMP_BIT,
                    ___GFP_NOMEMALLOC_BIT,
                    ___GFP_HARDWALL_BIT,
                    ___GFP_THISNODE_BIT,
                    ___GFP_ACCOUNT_BIT,
                    ___GFP_ZEROTAGS_BIT,
                    """
                gfp_flags_array = ["GFP_DMA","__GFP_HIGHMEM","GFP_DMA32","__GFP_MOVABLE","__GFP_RECLAIMABLE","__GFP_HIGH","__GFP_IO","__GFP_FS","__GFP_ZERO","__GFP_UNUSED","__GFP_DIRECT_RECLAIM","__GFP_KSWAPD_RECLAIM",
                                    "__GFP_WRITE","__GFP_NOWARN","__GFP_RETRY_MAYFAIL","__GFP_NOFAIL","__GFP_NORETRY","__GFP_MEMALLOC","__GFP_COMP","__GFP_NOMEMALLOC","__GFP_HARDWALL","__GFP_THISNODE","__GFP_ACCOUNT","__GFP_ZEROTAGS"]
                arg12 = call_expr.a[1].print1(None)
                arg12 = arg12.split(' ', 1)[1]
                print(arg12)
                arg12 = re.sub(r'[^0-9a-fA-F]', '', arg12)  # 只删非数字和非空格的字符 # 移除所有非数字字符
                arg12 = int(arg12, 10)
                print(hex(arg12))
                flag_str = ""

                #=========check if it is gfp_kernel,atomic,user first...
                if arg12&0x400cc0 == 0x400cc0:
                    flag_str += "GFP_KERNEL_ACCOUNT" + "|"
                    arg12 -= 0x400cc0
                if arg12 & 0x100cc0 == 0x100cc0:
                    flag_str += "GFP_USER" + "|"
                    arg12 -= 0x100cc0
                if arg12&0xcc0 == 0xcc0:
                    flag_str += "GFP_KERNEL" + "|"
                    arg12 -= 0xcc0
                if arg12&0xcc0 == 0x820:
                    flag_str += "GFP_ATOMIC" + "|"
                    arg12 -= 0x820

                m = 1
                for i in range(24):
                    if arg12 < m:
                        break
                    if arg12&m != 0:
                        flag_str += gfp_flags_array[i] + "|"
                    m *= 2
                msg = f"kmalloc_trace @size={get1} @flag={flag_str}"
                self.modifications.append(msg)
                try:
                    idc.set_cmt(insn.ea, msg, 0)
                except Exception:
                    print("[E] Exception id 5")
                    return 0
                print(f"[better_alloc] {msg} @ {insn.ea:#x}")

        return 0

class KernelCallOptimizer(ida_hexrays.Hexrays_Hooks):
    """
    多功能内核函数调用优化器（printk, kmalloc, kmalloc_trace ...）
    """
    def __init__(self):
        super(KernelCallOptimizer, self).__init__()
        self.modifications = []
        # 注册所有要检测的 API 及其处理函数
        self.targets = {
            "printk": self.handle_printk,
            "_printk": self.handle_printk,
            "kmalloc": self.handle_kmalloc,
            "kmalloc_trace": self.handle_kmalloc
        }

    def handle_printk(self, call_expr):
        """解析 printk 第一个参数"""
        if not call_expr.a or len(call_expr.a) < 1:
            return None
        arg = call_expr.a[0]
        while arg and arg.op == ida_hexrays.cot_cast:
            arg = arg.x
        ea = None
        if arg.op == ida_hexrays.cot_ref:
            ea = arg.x.obj_ea
        elif arg.op == ida_hexrays.cot_obj:
            ea = arg.obj_ea
        if ea:
            return extract_kernel_printk_string(ea)
        return None

    def handle_kmalloc(self, call_expr):
        """解析 kmalloc/kmalloc_trace 第一个参数（size）"""
        if not call_expr.a or len(call_expr.a) < 1:
            print("[W] Wrong....")
            return None
        size_arg = call_expr.a[0]
        print(f"kmalloc size={size_arg}")
        return f"kmalloc size={size_arg}"

    def func_printed(self, cfunc):
        """Hex-Rays 反编译完成时调用一次"""
        visitor = KernelCallVisitor(cfunc, self.targets, self.modifications)
        visitor.apply_to(cfunc.body, None)
        # 遍历伪代码行，顺序给注释
        ord = 0
        for sl in cfunc.get_pseudocode():
            clean_line = ida_lines.tag_remove(sl.line)
            if debug:
                print(f"[G] Pseudocode: {clean_line}")
            if any(name in clean_line for name in self.targets):
                if ord < len(self.modifications):
                    comment = f"  /* {self.modifications[ord]} */"
                    sl.line = sl.line + ida_lines.COLSTR(comment, ida_lines.SCOLOR_AUTOCMT)
                    ord += 1
        self.modifications.clear()
        return 0


class KernelCallPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_HIDE
    wanted_name = "Kernel Call Optimizer"
    wanted_hotkey = ""
    comment = "Optimize multiple kernel API calls"
    help = "Decode printk, kmalloc, kmalloc_trace calls automatically"

    def init(self):
        print(">>> KernelCallPlugin: Init called.")
        if not ida_hexrays.init_hexrays_plugin():
            print("Hex-Rays not found, skipping.")
            return ida_idaapi.PLUGIN_SKIP
        self.hooks = KernelCallOptimizer()
        self.hooks.hook()
        return ida_idaapi.PLUGIN_KEEP

    def term(self):
        if hasattr(self, 'hooks'):
            self.hooks.unhook()
        return

    def run(self, arg):
        print(">>> KernelCallPlugin: run() invoked.")
        return 0


def PLUGIN_ENTRY():
    print("[P] KernelCallPlugin entry.")
    return KernelCallPlugin()
