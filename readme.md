
# MagicGadget

`MagicGadget` 是一个用于分析 ELF 文件的工具，主要用于查找可执行段（如 `.text` 段）中的Magic Gadget。它可以显示段的权限信息，并反汇编指定段的指令。

## 功能

- 显示 ELF 文件中各个段的权限和信息。
- 反汇编任意段，寻找Magic Gadget。

## 依赖

该程序依赖于以下 Python 库：

- `pyelftools`
- `capstone`

你可以使用以下命令安装它们：

```bash
pip install pyelftools capstone
```

## 使用方法

### 基本用法

```bash
python MagicGadget.py <elf_file> [options]
```

### 参数说明

- `<elf_file>`: 需要分析的 ELF 文件的路径。
- `-help`: 显示帮助信息。
- `-seg`: 显示所有段的权限和信息。
- `-set <segment_name>`: 反汇编指定的段并查找Magic Gadget。例如，使用 `-set .text` 来分析 `.text` 段。

### 示例

1. **查看帮助信息**

   ```bash
   python MagicGadget.py -help
   ```

2. **显示段权限**

   ```bash
   python MagicGadget.py my_program -seg
   ```

3. **反汇编 `.text` 段**

   ```bash
   python MagicGadget.py my_program
   ```

4. **反汇编指定段**

   ```bash
   python MagicGadget.py my_program -set .data
   ```

## 输出示例

- 段权限信息示例：

```
Segment              Address       Permission         Type
text                 0x400000      r-x                SHT_PROGBITS
data                 0x600000      rw-                SHT_PROGBITS
```

- 反汇编输出示例：

```
Magic Gadgets:
-------------------------------------------------------------
0x400658:       add     dword ptr [rbp - 0x3d], ebx
0x400665:       mov     dword ptr [rbp - 0x14], edi
0x400668:       mov     qword ptr [rbp - 0x20], rsi
```
