[English](README.en.md) | [简体中文](README.md)

# Better printk for IDA
When I was using IDA to reverse engineer kernel modules, I was troubled by the printk format for a long time. IDA could not automatically recognize it, and I had to manually look at each byte in the data area, which was very unintuitive and troublesome. So, this plugin was created.
This plugin is developed based on IDAPython 9.0, core function works properly in version 8.3, it implements:
1. Automatically generates printk strings and kernel log levels in the pseudocode window and disassembly window when analyzing kernel drivers.
2. Registers a new data type `printk_str` for IDA. In the data view, right-click on the pointer to select Better printk to format the output.

# Usage
## Better Printk Output
Copy `better_printk.py` into the `/$IDAdir(9.0)/plugins` directory, and the plugin will automatically work when decompiling functions, generating related comments to display the content and kernel log level of printk in the pseudocode window and disassembly window.
![better_printk](/assets/operation2.gif)

## Optimize printk str
Right-click on the string in the data window to directly convert it to printk.
![turn_data_into_printkstr](/assets/operation.gif)

# Notes/Potential Bugs

1. For pseudocode interface comments, IDA **does not** provide a good API to match the pseudocode line from the address (operations about output pseudocode can only modify the raw text). Therefore, the matching of comments is based on the order of function calls decompiled by IDA. **If** the printk call in the CTree appears before the line containing printk in the pseudocode interface, the order of comments will be problematic. In this case, refer to the optimized output of the **assembly** interface.

2. For IDA versions below 9.0 (the author personally uses version 8.3), there are problems with the data structure registration part due to API conflicts, but the decompilation hook part can be used normally (at least in version 8.3).

# Others
As a student, I made this plugin just on impulse. Everyone is welcome to optimize and modify this plugin or perform secondary development based on its template.

Also, thanks for Cursor and deepseek-v3.