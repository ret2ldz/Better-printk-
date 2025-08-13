# KPwnHelper (Fork from ZjW1nd/Better-printk-IDA9)

This project is a fork of my colleague's project [Better-printk-IDA9](https://github.com/ZjW1nd/Better-printk-IDA9), originally created by [ZjW1nd](https://github.com/ZjW1nd).

Original README links:
- [Chinese README](https://github.com/ZjW1nd/Better-printk-IDA9/blob/main/README.md)
- [English README](https://github.com/ZjW1nd/Better-printk-IDA9/blob/main/README.en.md)

---

## New Features

Based on the original functionality, this fork introduces the following improvements:

1. **Support for cases where the `printk` argument is a local variable**  
   - Automatically backtracks the variable assignment chain to extract the string address.
   - Supports multi-level assignments like `v0 = v1; v1 = 0x1234; printk(v0);`  
     Example:
```c
{
    v11 = 1024;
    if (a3 < 0x400)
        v11 = a3;
    _check_object_size(v9, v11, 1);
    if (!copy_to_user(a2, v9, v11))
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

  2. **Support for multiple possible string addresses**
    - If a variable is assigned different addresses multiple times in a function, all of them will be parsed and extracted. U can find it in debuf Info~
     Example:
```
[better_printk] Found printk @ 0x133, extract: KERN_INFO, "[kbook:] Failed to copy data back to user space!\n"
[better_printk] Found printk @ 0x133, extract: KERN_ALERT, "[kbook:] RUN OUT OF ALL MEMORY!\n"
```

  3. **Fixed a bug where some printk calls were optimized into _printk and failed to extract strings**
    - See the demo for details; you can use the demo to test this fix.
```
.text:0000000000000100 loc_100:                                ; CODE XREF: kbook_read+19↑j
.text:0000000000000100                 mov     rdi, offset unk_6B4
.text:0000000000000107                 call    _printk         ; KERN_ERR, "[kbook:] You should firstly get a book!\n"
```
## Future Plans
 - More complex expression parsing

 - String extraction from inline assembly

 - Multi-threaded / asynchronous printk call support

 - Additional features such as parsing code optimized into cold sections (_cold_) and merging with source code

If you are interested in IDA plugin development or kernel pwn, feel free to contact me!
