# Created By Zj_W1nd
# Repo: https://github.com/ZjW1nd/Better-printk-IDA9
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

class PrintkVisitor(ida_hexrays.ctree_visitor_t):
    """负责遍历和优化printk调用的访问者类"""
    def __init__(self, printk_func, modifications):
        ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST | ida_hexrays.CV_INSNS)
        self.printk_func = printk_func
        self.modifications = modifications

    def visit_insn(self, insn):
        # 检查指令类型
        if insn.op != ida_hexrays.cit_expr:
            return 0
        # 获取表达式
        expr = insn.cexpr
        if expr.op != ida_hexrays.cot_call:
            return 0
        # 获取被调用函数
        called_func = expr.x
        if called_func.op != ida_hexrays.cot_obj:
            return 0
        if called_func.obj_ea != self.printk_func:
            return 0
        # 获取第一个参数
        if len(expr.a) < 1:
            return 0
        arg = expr.a[0]
        if arg.op != ida_hexrays.cot_ref:
            return 0
        # 获取字符串地址
        str_addr = arg.x.obj_ea
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
        return 0

class PrintkOptimizer(ida_hexrays.Hexrays_Hooks):
    """负责管理printk优化过程的主类"""
    def __init__(self):
        super(PrintkOptimizer, self).__init__()
        self.printk_func = None
        self.modifications = [] # 存储需要修改的printk

    def find_printk(self):
        """查找printk函数的地址"""
        func = ida_funcs.get_next_func(0)
        while func:
            func_name = ida_funcs.get_func_name(func.start_ea)
            if func_name == "printk":
                self.printk_func = func.start_ea
                return
            func = ida_funcs.get_next_func(func.start_ea)
        raise Exception("printk function not found.")

    def optimize_printk(self, cfunc):
        """优化printk调用"""
        if self.printk_func is None:
            try:
                self.find_printk()
            except Exception as e:
                print(f"Better-printk: {e}")
                return False
        
        # 创建并应用访问者
        visitor = PrintkVisitor(self.printk_func, self.modifications)
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
        optimized_str=self.modifications[ord]
        # 在行尾添加注释
        comment = f"  /* {optimized_str} */"
        # 设置注释颜色为灰色
        colored_comment = ida_lines.COLSTR(comment, ida_lines.SCOLOR_AUTOCMT)
        # 将注释添加到行尾
        sl.line = l + colored_comment

    def func_printed(self, cfunc):
        """Hex-Rays回调函数，在函数反编译完成后调用"""
        # 优化 printk 调用
        self.optimize_printk(cfunc)
        ord=0
        for sl in cfunc.get_pseudocode():
            if("printk" in sl.line):
                self.modify_printk_line(sl,ord)
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