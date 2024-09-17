import sys
from elftools.elf.elffile import ELFFile
from capstone import (
    Cs,
    CS_ARCH_X86,
    CS_MODE_64,
    CS_ARCH_ARM,
    CS_MODE_ARM,
    CS_ARCH_MIPS,
    CS_MODE_MIPS32,
)


def get_arch_and_mode(elf):
    arch = elf.get_machine_arch()

    if arch in ["EM_X86_64", "x64"]:
        return CS_ARCH_X86, CS_MODE_64
    elif arch == "EM_ARM":
        return CS_ARCH_ARM, CS_MODE_ARM
    elif arch == "EM_MIPS":
        return CS_ARCH_MIPS, CS_MODE_MIPS32
    else:
        raise ValueError(f"Unsupported architecture: {arch}")


def check_segment_permissions(elf):
    print("Information for all segments:")
    print(
        "Segment".ljust(21, " "),
        "Address".ljust(15, " "),
        "Permission".ljust(20, " "),
        "Type",
    )
    for section in elf.iter_sections():
        if section.name == "":
            continue
        sectionName = section.name
        if sectionName.startswith("."):
            sectionName = sectionName[1:]
        permissions = section["sh_flags"]
        readable = "r" if permissions & 0x4 else "-"
        writable = "w" if permissions & 0x2 else "-"
        executable = "x" if permissions & 0x1 else "-"

        permissions_str = f"{readable}{writable}{executable}"

        print(
            f"{sectionName}".ljust(21, " "),
            f"0x{section['sh_addr']:x}".ljust(15, " "),
            f"{permissions_str}".ljust(20, " "),
            f"{section['sh_type']}",
        )


ListOfReg = [
    "rax",
    "eax",
    "rbx",
    "ebx",
    "rcx",
    "ecx",
    "edx",
    "rdx",
    "rsi",
    "esi",
    "edi",
    "rdi",
    "esp",
    "rsp",
    "ebp",
    "rbp",
    "eip",
    "rip",
    "r0",
    "r1",
    "r2",
    "r3",
    "r4",
    "r5",
    "r6",
    "r7",
    "r8",
    "r9",
    "r10",
    "r11",
    "r12",
    "r13",
]


def checkMagic(op_str):
    if "[" in op_str and "]" in op_str:
        if "+" in op_str or "-" in op_str:
            for reg in ListOfReg:
                if reg in op_str:
                    return True
    return False


def disByElf(elf, seg):
    print(
        "Magic Gadgets:\n-------------------------------------------------------------"
    )
    arch, mode = get_arch_and_mode(elf)

    dest_segment = elf.get_section_by_name(seg)

    if dest_segment is not None:
        data = dest_segment.data()
        address = dest_segment["sh_addr"]
        md = Cs(arch, mode)
        AtLeastCheck = False
        for instruction in md.disasm(data, address):
            if checkMagic(instruction.op_str):
                AtLeastCheck = True
                print(
                    f"0x{instruction.address:x}:\t{instruction.mnemonic}\t{instruction.op_str}"
                )
        if not AtLeastCheck:
            print("No magic gadget")
    else:
        print(f"Error: {seg} segment not found.")


def disassemble_elf(file_path, type):
    with open(file_path, "rb") as f:
        elf = ELFFile(f)
        if type == "normal":
            disByElf(elf, ".text")
        elif type == "showSegmentOnly":
            check_segment_permissions(elf)
        elif type == "set":
            disByElf(elf, setSeg)


def helpMenu():
    print("Usage: python MagicGadget.py <elf_file> [options]")
    print("Options:")
    print("  -help                  Show this help message.")
    print("  -seg                   Show segment permissions and information.")
    print(
        "  -set <segment_name>    Disassemble the specified segment for magic gadgets."
    )
    print("                        Example: -set .text")
    print(
        "  If no options are given, it will disassemble the .text segment by default."
    )


def MainProcessor():
    global setSeg
    if len(sys.argv) >= 2:
        if sys.argv[1] != "-help":
            elf_file_path = sys.argv[1]
        else:
            helpMenu()
            return
        if len(sys.argv) >= 3:
            if sys.argv[2] == "-seg":
                disassemble_elf(elf_file_path, "showSegmentOnly")
                return
            elif sys.argv[2] == "-set":
                if len(sys.argv) == 4:
                    setSeg = sys.argv[3]
                    disassemble_elf(elf_file_path, "set")
                    return
                else:
                    print("[-] Invalid argument for -set")
                    return

        disassemble_elf(elf_file_path, "normal")
    return


if __name__ == "__main__":
    MainProcessor()
