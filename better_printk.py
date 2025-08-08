"""
This project is a fork and modification of the original `Better-printk-IDA9` by Zj_W1nd.
Original Repository: https://github.com/ZjW1nd/Better-printk-IDA9
Repository name: lenreK-IDA9-ret2ldz
Description: A fork of Zj_W1nd's Better-printk-IDA9 project, with bug fixes and improvements.
Extra: If u wants to contact me(ret2ldz),use email:2691605373@qq.com or PhoneCall:+86-18600398261
"""
import ida_idaapi
import ida_bytes
import ida_funcs
import ida_hexrays
import idc
import ida_lines
import ida_typeinf

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
debug = 0 #0:user_mode 1:debug_mode

def extract_kernel_printk_string(ea):
    """
    给定可能的 printk 字符串地址，按你的格式判断并返回优化字符串（或 None）。
    原逻辑：第一个字节 == 0x1，再读第二字节作为 level，然后从 +2 开始读 C-string。
    """
    try:
        if ea is None:
            return None
        b0 = ida_bytes.get_byte(ea)
        if b0 != 0x1:
            return None
        lvl_b = ida_bytes.get_byte(ea + 1)
        # lvl_b 是 int，转成字符再查字典（沿用你原来的写法）
        try:
            level_char = chr(lvl_b)
        except Exception:
            return None
        if level_char not in KERN_LEVELS:
            return None
        # 读字符串
        sstart = ea + 2
        send = sstart
        # 防止死循环，加个简单上限（可根据需要调整）
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
        print("[better_printk] extract error:", e)
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


class PrintkVisitor(ida_hexrays.ctree_visitor_t):
    """负责遍历函数内的 printk 调用并把字符串提取出来（支持 var 回溯）"""
    def __init__(self, cfunc, printk_ea, modifications):
        ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST | ida_hexrays.CV_INSNS)
        self.cfunc = cfunc
        self.printk_ea = printk_ea
        self.modifications = modifications

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
        return finder.results

    def visit_insn(self, insn):
        # 只处理表达式语句
        if insn.op != ida_hexrays.cit_expr:
            return 0
        expr = insn.cexpr
        if expr is None:
            return 0
        # 只处理函数调用
        if expr.op != ida_hexrays.cot_call:
            return 0
        # 获取被调用函数（call target）
        called = expr.x
        if called is None or called.op != ida_hexrays.cot_obj:
            return 0
        # 不是 printk 则跳过
        try:
            if called.obj_ea != self.printk_ea:
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
                addrs.extend(self.resolve_var_value(arg.v.idx))
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

        # 对找到的每个地址进行提取并写注释
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



"""
class PrintkVisitor(ida_hexrays.ctree_visitor_t):
    
    def __init__(self, printk_func, modifications):
        ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST | ida_hexrays.CV_INSNS)
        self.printk_func = printk_func
        self.modifications = modifications

    def visit_insn(self, insn):
        # 检查指令类型
        if insn.op != ida_hexrays.cit_expr:
            #if debug==1:print("\n[R] Return Point 1\n")
            return 0
        # 获取表达式
        expr = insn.cexpr
        if expr.op != ida_hexrays.cot_call:
            #if debug == 1: print("\n[R] Return Point 2\n")
            return 0
        # 获取被调用函数
        called_func = expr.x
        if called_func.op != ida_hexrays.cot_obj:
            return 0
        if called_func.obj_ea != self.printk_func:
            #if debug == 1: print("\n[R] Return Point 3\n")
            return 0
        # 获取第一个参数
        if len(expr.a) < 1:
            return 0
        arg = expr.a[0]
        if arg.op == ida_hexrays.cot_var:
            print("[M] Meet a cot var. And we need to extract the value of it")
        if arg.op != ida_hexrays.cot_ref:
            return 0
        # 获取字符串地址
        print("[M] Meet a cot ref. Then we'll extract the strings")
        str_addr = arg.x.obj_ea
        print(f"[G] Get Strings addr at {str_addr}")
        # 读取字符串内容
        if ida_bytes.get_byte(str_addr) != 0x1:
            return 0
        
        level = chr(ida_bytes.get_byte(str_addr + 1))
        if level not in KERN_LEVELS:
            return 0
        # 读取实际字符串
        str_start = str_addr + 2
        str_end = str_start
        while ida_bytes.get_byte(str_end) != 0:
            str_end += 1
        actual_str = ida_bytes.get_bytes(str_start, str_end - str_start).decode('ascii')
        # 处理回车
        actual_str = actual_str.replace('\n', '\\n')
        # 生成优化后的字符串
        level_str = KERN_LEVELS[level]
        optimized_str = f'KERN_{level_str}, "{actual_str}"'
        self.modifications.append(optimized_str)
        print(f"Found printk at {insn.ea}, extract string: {optimized_str}")
        idc.set_cmt(insn.ea, optimized_str, 0) # 汇编页面的注释
        return 0"""

class PrintkOptimizer(ida_hexrays.Hexrays_Hooks):
    """负责管理printk优化过程的主类"""
    def __init__(self):
        super(PrintkOptimizer, self).__init__()
        self.printk_func = None
        self.modifications = [] # 存储需要修改的printk

    def find_printk(self):
        """查找printk函数的地址"""
        printk_ea = idc.get_name_ea_simple("printk")
        if printk_ea != ida_idaapi.BADADDR:
            self.printk_func = printk_ea
            print(f"[*] Found 'printk' function at {hex(printk_ea)}")
            return True

        _printk_ea = idc.get_name_ea_simple("_printk")
        if _printk_ea != ida_idaapi.BADADDR:
            self.printk_func = _printk_ea
            print(f"[*] Found '_printk' symbol at {hex(_printk_ea)}")

            # 验证是否为导入符号
            if ida_bytes.is_func(_printk_ea):
                print(f"[*] '_printk' is a function, continuing...")
            else:
                # 如果不是函数，说明是导入符号，需要特殊处理
                # 这里的逻辑取决于你的二进制文件类型
                # 比如，在 PLT/GOT 表中，_printk的实际地址可能在另一个位置
                # 但对于你的插件，只要能找到它的引用地址就够了
                print(f"[*] '_printk' is an import symbol, treating it as the target.")

            return True

        func = ida_funcs.get_next_func(0)
        while func:
            func_name = ida_funcs.get_func_name(func.start_ea)
            if debug==1:
                print(f"[*] Get function name :{func_name}")
            if func_name == "printk" or "_printk":
                self.printk_func = func.start_ea
                print(f"[*] Get Printk addr :{self.printk_func}")
                return True
            func = ida_funcs.get_next_func(func.start_ea)
        print("Error: printk function not found.")
        return False

    def optimize_printk(self, cfunc):
        """优化printk调用"""
        if self.printk_func is None:
            try:
                res = self.find_printk()
                if res == False:
                    if debug == 1:print("[X] Not Found Printk Func in this files! Or maybe we just meeet a Bug~")
                    return -1
            except Exception as e:
                print(f"Better-printk: {e}")
                return False
        
        # 创建并应用访问者
        visitor = PrintkVisitor(cfunc,self.printk_func, self.modifications)
        if debug==1:print(f"[i] Traversal is Done, and we've got {self.modifications}")
        visitor.apply_to(cfunc.body, None)
        return True
    
    def modify_printk_line(self, sl, ord):
        """伪代码行的注释，按序匹配"""
        # 实际修改太麻烦了，而且还需要hook双击动作，尝试修改后发现很僵硬，双击跳转参数也没了
        # 因此选择在伪代码行尾添加注释
        # todo: 匹配是按照printk在反汇编Ctree中遍历的先后顺序来的
        # 如果输出反编译伪代码时printk调用行与Ctree遍历顺序不一致则会有问题
        # 汇编是100%正确的
        # Actually modifying the code is too troublesome, and it also requires hooking double-click actions. 
        # After attempting to modify it, I found it to be very rigid, and the double-click jump parameters were lost.
        # Therefore, I chose to add comments at the end of the pseudocode lines.
        # todo: The matching is based on the order in which printk is traversed in the disassembled Ctree.
        # If the order of printk call lines in the decompiled pseudocode output does not match the Ctree traversal order, there will be problems.
        # The assembly is 100% correct.
        l : str = sl.line
        if ord < len(self.modifications):
            print(self.modifications[ord])
            optimized_str=self.modifications[ord]
        else:
            print(f"[x] Out of Bound! The ord value is {ord}. We probability meeeeeeeeeet a Bug.")
            return
        # 在行尾添加注释
        comment = f"  /* {optimized_str} */"
        # 设置注释颜色为灰色
        colored_comment = ida_lines.COLSTR(comment, ida_lines.SCOLOR_AUTOCMT)
        # 将注释添加到行尾
        sl.line = l + colored_comment

    def func_printed(self, cfunc): ##hooked
        """Hex-Rays回调函数，在函数反编译完成后调用"""
        # 优化 printk 调用
        self.optimize_printk(cfunc)
        ord=0
        for sl in cfunc.get_pseudocode():
            clean_line = ida_lines.tag_remove(sl.line)
            if debug==1:print(f"[G] Get pseudocode :{clean_line}")
            if("printk" in sl.line):
                if debug ==1 :print(f"[F] Find Printk Function is lines {clean_line}")
                self.modify_printk_line(sl,ord)
                #print(ord)
                ord+=1
        self.modifications.clear()
        return 0

class PrintkOptimizerPlugin(ida_idaapi.plugin_t):
    """Module provided by ida examples"""
    flags = ida_idaapi.PLUGIN_HIDE
    wanted_name = "Printk Optimizer"
    wanted_hotkey = ""
    comment = "Optimize printk calls in Linux kernel modules"
    help = "This plugin optimizes printk calls by decoding kernel log levels and messages"

    def init(self):
        print(">>> PrintkOptimizerPlugin: Init called.")
        if not ida_hexrays.init_hexrays_plugin():
            print("Hex-Rays plugin not found, skipping PrintkOptimizer initialization.")
            return ida_idaapi.PLUGIN_SKIP
        self.hooks = PrintkOptimizer()
        self.hooks.hook()
        return ida_idaapi.PLUGIN_KEEP

    def term(self):
        if hasattr(self, 'hooks'):
            self.hooks.unhook()
        return

    def run(self, arg):
        print(">>> PrintkOptimizer: run() is invoked.")
        return 0

def PLUGIN_ENTRY():
    print("[P] Plugin entrying now...")
    return PrintkOptimizerPlugin()

# 允许更好查看数据，右键指针选择Better printk即可
# Warning: 对于低于9.0版本的ida（个人使用8.3）来说，相关api存在问题，可以注释掉使用
# Warning: For ida below 9.0 (I use 8.3), there are problems with the related api
class PrintkDataType(ida_bytes.data_type_t):
    def __init__(self):
        ida_bytes.data_type_t.__init__(
            self,
            "Better_printk_string",
            1,  # 最小大小
            "Better printk string",
            None,
            "printk_str")

    def calc_item_size(self, ea, maxsize):
        # 检查是否是结构体成员
        tif = ida_typeinf.tinfo_t()
        if tif.get_udm_by_tid(None, ea) != -1:
            return 1

        # 检查第一个字节是否为 0x1
        if ida_bytes.get_byte(ea) != 0x1:
            return 0

        # 检查第二个字节是否为有效的日志等级
        level = chr(ida_bytes.get_byte(ea + 1))
        if level not in KERN_LEVELS:
            return 0

        # 计算字符串长度
        str_start = ea + 2
        str_end = str_start
        while ida_bytes.get_byte(str_end) != 0:
            str_end += 1
            if str_end - ea > maxsize:
                return 0

        return str_end - ea + 1  # 包括结束符

class PrintkDataFormat(ida_bytes.data_format_t):
    FORMAT_NAME = "py_printk_string_format"
    def __init__(self):
        ida_bytes.data_format_t.__init__(
            self,
            PrintkDataFormat.FORMAT_NAME)

    def printf(self, value, current_ea, operand_num, dtid):
        # 检查第一个字节是否为 0x1
        if value[0] != 0x1:
            return None

        # 获取日志等级
        level = chr(value[1])
        if level not in KERN_LEVELS:
            return None

        # 获取实际字符串
        str_start = 2
        str_end = len(value)
        actual_str = value[str_start:str_end].decode('ascii', errors='replace')
        # 处理回车
        actual_str = actual_str.replace('\n', '\\n')
        # 生成格式化字符串
        level_str = KERN_LEVELS[level]
        return f"KERN_{level_str} '{actual_str}'\x00"

# 注册自定义数据类型和格式
new_formats = [
    (PrintkDataType(), PrintkDataFormat()),
]

if ida_bytes.find_custom_data_type(PrintkDataFormat.FORMAT_NAME) == -1:
    if not ida_bytes.register_data_types_and_formats(new_formats):
        print("Failed to register printk data type!")
    else:
        print("printk data type registered successfully!")