# KPwnHelper (Fork by ZjW1nd/Better-printk-IDA9)
- [eng readme](https://github.com/ret2ldz/Better-printk-/blob/main/README.en.md)
- [中文 readme](https://github.com/ret2ldz/Better-printk-/blob/main/README.md)


本项目是基于我同事的项目 [Better-printk-IDA9](https://github.com/ZjW1nd/Better-printk-IDA9) 的 Fork 版本，原作者为 [ZjW1nd](https://github.com/ZjW1nd)。


原版 README 链接：
- [原版中文 README](https://github.com/ZjW1nd/Better-printk-IDA9/blob/main/README.md)
- [Original English README](https://github.com/ZjW1nd/Better-printk-IDA9/blob/main/README.en.md)

---

## 新增功能

在原版功能基础上，本 Fork 增加了以下功能：

1. **支持 `printk` 参数为局部变量的情况**  
   - 自动回溯变量赋值链，提取字符串地址
   - 兼容 `v0 = v1; v1 = 0x1234; printk(v0);` 这种多层赋值形式、例如下方的情况

```c
  {
    v11 = 1024;
    if ( a3 < 0x400 )
      v11 = a3;
    _check_object_size(v9, v11, 1);
    if ( !copy_to_user(a2, v9, v11) )
      goto LABEL_7;
    v11 = -14;
    v13 = &unk_6DF;
  }
  else
  {
    v11 = -12;
    v13 = &unk_68B;
  }
  printk(v13);
```

2. **支持多个可能字符串地址的解析**  
   - 如果变量在函数中多次被赋值不同地址，全部解析并提取字符串,如下所示，您可以在调试信息里找到它

```
[better_printk] Found printk @ 0x133, extract: KERN_INFO, "[kbook:] Failed to copy data back to user space!\n"
[better_printk] Found printk @ 0x133, extract: KERN_ALERT, "[kbook:] RUN OUT OF ALL MEMORY!\n"
```

3. **优化了部分printk被解析成_printk时无法提取字符串的bug**
   - 如下所示
```
.text:0000000000000100 loc_100:                                ; CODE XREF: kbook_read+19↑j
.text:0000000000000100                 mov     rdi, offset unk_6B4
.text:0000000000000107                 call    _printk         ; KERN_ERR, "[kbook:] You should firstly get a book!\n"
```

   - demo由上面相关的例子，您可以使用demo测试
---

## 未来计划

- [ ] 更多复杂表达式解析
- [ ] 内联汇编中的字符串解析
- [ ] 多线程 / 异步 `printk` 调用支持
- [ ] 更多的功能，例如在编译优化成冷代码“_cold_”的解析与源代码的合并

如果您对ida插件编写和kernel pwn感兴趣，也欢迎联系我！
