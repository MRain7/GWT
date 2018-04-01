# GWT

Gadget Weighted Tagging to Protect Against Code Reuse Attacks

## Static

### 目录结构

```
.
├── batch.py
├── detail
│   ├── heap_test.txt
│   ├── heap_test_static.txt
│   ├── libc2.21.txt
│   ├── ls.txt
│   ├── mv.txt
│   ├── stack_test.txt
│   └── stack_test_static.txt
├── elf
│   ├── heap_test
│   ├── heap_test_static
│   ├── libc2.21
│   ├── ls
│   ├── mv
│   ├── stack_test
│   └── stack_test_static
├── fragment
│   ├── heap_test.txt
│   ├── heap_test_static.txt
│   ├── libc2.21.txt
│   ├── ls.txt
│   ├── mv.txt
│   ├── stack_test.txt
│   └── stack_test_static.txt
├── ganalyzer.py
├── gcollector.py
├── gvalidator.py
├── lib
│   ├── __init__.py
│   ├── __init__.pyc
│   ├── classifier.py
│   ├── classifier.pyc
│   ├── extra_archinfo.py
│   ├── extra_archinfo.pyc
│   ├── gadget.py
│   ├── gadget.pyc
│   ├── utils.py
│   ├── utils.pyc
│   ├── validator.py
│   └── validator.pyc
├── pin
│   ├── heap_test.txt
│   ├── heap_test_static.txt
│   ├── libc2.21.txt
│   ├── ls.txt
│   ├── mv.txt
│   ├── stack_test.txt
│   └── stack_test_static.txt
└── result.txt

5 directories, 46 files
```

### 执行流程

![img](http://7xttlj.com1.z0.glb.clouddn.com/REAMME.png)

### 具体步骤

1. 将要分析的 elf 文件放入 elf 目录
2. 在主目录运行`python batch.py`
3. 脚本会批量使用 ida 静态分析 elf 目录内的所有 elf 文件并在完成后自动关闭 ida
4. 由于版本功能限制，无法完全自动化，每个 elf 需要在弹窗时手动回车确认 2 次
5. 中间结果分别保存于 fragment, detail 和 pin 目录，最终结果保存于主目录下的 result.txt

### 主要模块

##### gcollector.py

1. 目标

找到所有间接跳转（IBR)，再按 IBR 所在地址回溯，直到上一条跳转指令为止，输出其间所有可能构成 gadget 的指令片段，按不同文件名保存到 fragment 目录 

2. 例如

```
> length: 1
|-- .fini:80485B7	retn
c3
----------------------------------------
> length: 2
|-- .fini:80485B6	pop     ebx
|-- .fini:80485B7	retn
5bc3
----------------------------------------
> length: 3
|-- .fini:80485B3	add     esp, 8
|-- .fini:80485B6	pop     ebx
|-- .fini:80485B7	retn
83c4085bc3
----------------------------------------
> length: 4
|-- .fini:80485AD	add     ebx, 1217h
|-- .fini:80485B3	add     esp, 8
|-- .fini:80485B6	pop     ebx
|-- .fini:80485B7	retn
81c31712000083c4085bc3
```

回溯到第 5 条指令时为另一条跳转指令，所以以 `80485B7	retn`为结尾所有可能为 gadget 的指令片段一共只有 4 种

3. 思路

- 利用 ida-python 提供的 api `Segments()`获得所有段起始地址，`SegEnd()`获取段结束地址
- 根据对应段的起止地址，利用`Heads(start, end)`得到段内所有指令的起始地址
- 利用`disasm(head)`函数获得指令的机器码和汇编代码
- 通过正则表达式和机器码判断指令是否为`间接跳转指令`并按如上目标格式保存，同时加上`call-preceded`和`syscall`等标记
- 对总指令数等数据进行统计，同时利用`Functions()`收集所有函数入口


##### gvalidator.py

1. 目标

以每个间接跳转为单位，对所有以该间接跳转为结尾的指令片段进行判断：

- 是否存在 functional gadget， 最大长度多少
- 是否存在 nop gadget， 最大长度多少
- 是否为 call-preceded gadget

2. 思路

- 遍历 fragment 目录中所有 txt 文件并依次进行逐行读取，根据`+>|-*`等预设标记判断该行内容类型，然后收集对应长度的指令片段、片段内部遭到修改的寄存器
- 读取到整个指令片段的机器码时，利用 Q 的 api `classifier.GadgetClassifier()`判断片段是否为 functional gadget，并统计相关数据
- 若非 functional gadget，根据可容忍的最大寄存器修改数量判断可否归为 nop gadget，并统计相关数据
- 按文件名保存所有统计数据到 detail 目录
- 另外按照 pin 动态分析所需的输入数据格式将对应部分数据保存到 pin 目录

##### ganalyzer.py

1. 目标

将 detail 目录中所有统计数据汇总到 result.txt 中

2. 输出样例

```
heap_test, heap_test_static, libc2, ls, mv, stack_test, stack_test_static
+ Files: 7

+ [AVG]
|-- Functions: 794.00
|-- Instructions: 86870.29
|-- Branch instructions: 17118.00
|-- Indirect branch instructions: 1609.29
    |-- ret: 1211.43 (9 ~ 5587)
    |-- jmp: 88.00 (1 ~ 408)
    |-- call: 284.43 (4 ~ 1300)
    |-- system call: 90.57 (0 ~ 462)
    |-- call preceded: 284.43 (4 ~ 1300)
|-- Functional gadgets: 6145.29
    |-- length: 4.15 (0 ~ 48)
|-- Nop gadgets: 3634.14
    |-- length: 2.07 (0 ~ 71)
|-- Normal code fragments: 924.57
    |-- length: 9.01 (0 ~ 80)
    
```

## Dynamic

### 需求

依据静态分析后的信息，监测一个二进制可执行文件的具体运行过程，分析如下信息：

##### 指令信息统计：

- 总指令数、call、indirect\_call、syscll、return、branch、indirect\_branch、total\_branch指令数量；
- 总分支指令数量  占  总指令数量  比例；
- 间接分支指令数量  占  分支指令数量  比例；
- 间接分支指令数量  占  总指令数量  比例。

##### 配件加权统计： 

- 动态运行间接分支指令  占  静态标记间接分支指令数量  比例；
- 依据 **“配件判断算法”**，统计Function配件类型、真实Function配件类型、真实Nop配件类型、真实正常配件类型数量；
- coi峰值统计，如果coi峰值 > 阈值，则发出攻击警告。

##### 配件判断算法

1. 程序运行时，每执行一条指令（包括间接跳转指令），将gadget length加一。
2. 当执行一条间接跳转指令时，读取对应的配件标记信息（包括gadget type，最大长度），判断当前配件的真实类型（real gadget type）。然后，将gadget length清零。

```C++
if（gadget type == normal code）
    real gadget type = normal code；
else if（gadget type == NOP gadget）
    if（gadget length <= maximum length of NOP gadget ） 
        real gadget type = NOP gadget;
    else 
        real gadget type = normal code
else if (gadget type == functional gadget)
    if (gadget length <=  maximum length of functional gadget ) 
            real gadget type = functional gadget
    else if (gadget length <=  maximum length of NOP gadget ) 
 		real gadget type = NOP gadget 
    else
 		real gadget type = normal code 
```

3. 根据真实的配件类型（real gadget type），判断是否发生代码复用攻击。设置代码复用攻击发生概率因子（CRA occurrence index ，COI），和代码复用攻击发生概率最大因子MaxCOI。

```C++
// 根据real gadget type计算COI。
if(real gadget type == normal code)
    COI =0;
else
    COI = COI + 配件类型加权值 of (real gadget type)
```

4. 如果（COI > MaxCOI）则认为发生代码复用攻击，报警，并终止程序运行。MaxCOI可以设为8，还可以用其他值（6-20），看看最终效果。此外，配件的加权值也可以调整。

### 文件描述

PinTools目录结构：~/pin/source/tools/AAA/

```
- DynamicAnalysis.cpp          #PinTools源码
- makefile.rules                    
- makefile                            
- obj-ia32/DynamicAnalysis.so  #编译生成的动态链接库文件夹  
- elf/xxx                          #目标测试样例文件夹 
- static\_results/xxx.txt           #静态分析结果数据文件夹
- static\_results.txt           #依据elf文件名从静态分析结果中拷贝一份数据供动态分析使用 
- dynamic\_results/xxx.txt     #动态分析的结果文件夹
- dynamic\_batch.py           #动态分析批处理脚本
```

### 测试样例

1. 设置测试样例到各个文件夹：`.../elf : heap_test  stack_test`, `.../static_results : heap_test.txt  stack_test.txt`
2. 运行批处理脚本：`$ Python dynamic_batch.py` 
3. 查看测试结果：`.../dynamic_results : heap_test.txt  stack_test.txt`
