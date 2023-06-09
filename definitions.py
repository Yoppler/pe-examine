from enum import Enum, IntEnum, Flag

class Characteristics(Flag):
    IMAGE_FILE_RELOCS_STRIPPED = 0x1
    IMAGE_FILE_EXECUTABLE_IMAGE = 0x2
    IMAGE_FILE_LINE_NUMS_STRIPPED = 0x4
    IMAGE_FILE_LOCAL_SYMS_STRIPPED = 0x8
    IMAGE_FILE_AGGRESSIVE_WS_TRIM = 0x10
    IMAGE_FILE_LARGE_ADDRESS_AWARE = 0x20
    IMAGE_FILE_BYTES_REVERSED_LO = 0x80
    IMAGE_FILE_32BIT_MACHINE = 0x100
    IMAGE_FILE_DEBUG_STRIPPED = 0x200
    IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP = 0x400
    IMAGE_FILE_NET_RUN_FROM_SWAP = 0x800
    IMAGE_FILE_SYSTEM = 0x1000
    IMAGE_FILE_DLL = 0x2000
    IMAGE_FILE_UP_SYSTEM_ONLY = 0x4000
    IMAGE_FILE_BYTES_REVERSED_HI = 0x8000
    
    def desc(flag):
        return characteristics_descs[flag]

characteristics_descs = {
    "IMAGE_FILE_RELOCS_STRIPPED": "No base relocations",
    "IMAGE_FILE_EXECUTABLE_IMAGE": "Image is executable",
    "IMAGE_FILE_LINE_NUMS_STRIPPED": "COFF line numbers removed (deprecated)",
    "IMAGE_FILE_LOCAL_SYMS_STRIPPED": "COFF symbol table entries removed (deprecated)",
    "IMAGE_FILE_AGGRESSIVE_WS_TRIM": "Working set aggressively trimmed (obsolete)",
    "IMAGE_FILE_LARGE_ADDRESS_AWARE": "Can handle > 2GB addresses",
    "IMAGE_FILE_BYTES_REVERSED_LO": "Little endian (deprecated)",
    "IMAGE_FILE_32BIT_MACHINE": "32-bit-word architecture",
    "IMAGE_FILE_DEBUG_STRIPPED": "Debugging information removed",
    "IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP": "If image is on removable media, load & copy to swap file",
    "IMAGE_FILE_NET_RUN_FROM_SWAP": "If image is on network media, load & copy to swap file",
    "IMAGE_FILE_SYSTEM": "System file, not user program",
    "IMAGE_FILE_DLL": "Dynamic-link library (DLL) file",
    "IMAGE_FILE_UP_SYSTEM_ONLY": "Run on uniprocessor only",
    "IMAGE_FILE_BYTES_REVERSED_HI": "Big endian (deprecated)",
}

class DLLCharacteristics(Flag):
    IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA = 0x20
    IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x40
    IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY = 0x80
    IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x100
    IMAGE_DLLCHARACTERISTICS_NO_ISOLATION = 0x200
    IMAGE_DLLCHARACTERISTICS_NO_SEH = 0x400
    IMAGE_DLLCHARACTERISTICS_NO_BIND = 0x800
    IMAGE_DLLCHARACTERISTICS_APPCONTAINER = 0x1000
    IMAGE_DLLCHARACTERISTICS_WDM_DRIVER = 0x2000
    IMAGE_DLLCHARACTERISTICS_GUARD_CF = 0x4000
    IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE = 0x8000
    
    def desc(flag):
        return dllcharacteristics_desc[flag]

dllcharacteristics_desc = {
    "IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA": "Can handle a high entropy 64-bit virtual address space",
    "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE": "DLL can be relocated at load time",
    "IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY": "Code integrity checks are enforced",
    "IMAGE_DLLCHARACTERISTICS_NX_COMPAT": "Image is Non-Execute (NX) compatible",
    "IMAGE_DLLCHARACTERISTICS_NO_ISOLATION": "Isolation aware, but do not isolate the image",
    "IMAGE_DLLCHARACTERISTICS_NO_SEH": "Does not use structured exception (SE) handling",
    "IMAGE_DLLCHARACTERISTICS_NO_BIND": "Do not bind the image",
    "IMAGE_DLLCHARACTERISTICS_APPCONTAINER": "Image must execute in an AppContainer",
    "IMAGE_DLLCHARACTERISTICS_WDM_DRIVER": "A WDM driver",
    "IMAGE_DLLCHARACTERISTICS_GUARD_CF": "Image supports Control Flow Guard",
    "IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE": "Terminal Server aware",
}

class MachineType(IntEnum):
    IMAGE_FILE_MACHINE_UNKNOWN = 0x0
    IMAGE_FILE_MACHINE_ALPHA = 0x184
    IMAGE_FILE_MACHINE_ALPHA64 = 0x284
    IMAGE_FILE_MACHINE_AM33 = 0x1d3
    IMAGE_FILE_MACHINE_AMD64 = 0x8664
    IMAGE_FILE_MACHINE_ARM = 0x1c0
    IMAGE_FILE_MACHINE_ARM64 = 0xaa64
    IMAGE_FILE_MACHINE_ARMNT = 0x1c4
    IMAGE_FILE_MACHINE_AXP64 = 0x284
    IMAGE_FILE_MACHINE_EBC = 0xebc
    IMAGE_FILE_MACHINE_I386 = 0x14c
    IMAGE_FILE_MACHINE_IA64 = 0x200
    IMAGE_FILE_MACHINE_LOONGARCH32 = 0x6232
    IMAGE_FILE_MACHINE_LOONGARCH64 = 0x6264
    IMAGE_FILE_MACHINE_M32R = 0x9041
    IMAGE_FILE_MACHINE_MIPS16 = 0x266
    IMAGE_FILE_MACHINE_MIPSFPU = 0x366
    IMAGE_FILE_MACHINE_MIPSFPU16 = 0X466
    IMAGE_FILE_MACHINE_POWERPC = 0x1f0
    IMAGE_FILE_MACHINE_POWERPCFP = 0x1f1
    IMAGE_FILE_MACHINE_R4000 = 0x166
    IMAGE_FILE_MACHINE_RISCV32 = 0x5032
    IMAGE_FILE_MACHINE_RISCV64 = 0x5064
    IMAGE_FILE_MACHINE_RISCV128 = 0x5128
    IMAGE_FILE_MACHINE_SH3 = 0x1a2
    IMAGE_FILE_MACHINE_SH3DSP = 0x1a3
    IMAGE_FILE_MACHINE_SH4 = 0x1a6
    IMAGE_FILE_MACHINE_SH5 = 0x1a8
    IMAGE_FILE_MACHINE_THUMB = 0x1c2
    IMAGE_FILE_MACHINE_WCEMIPSV2 = 0x169
    
    def desc(value):
        return machinetype_descs[value]

machinetype_descs = {
    "IMAGE_FILE_MACHINE_UNKNOWN": "Unknown",
    "IMAGE_FILE_MACHINE_ALPHA": "Alpha AXP, 32-bit address space",
    "IMAGE_FILE_MACHINE_ALPHA64": "Alpha 64, 64-bit address space",
    "IMAGE_FILE_MACHINE_AM33": "Matsushita AM33",
    "IMAGE_FILE_MACHINE_AMD64": "x64",
    "IMAGE_FILE_MACHINE_ARM": "ARM little endian",
    "IMAGE_FILE_MACHINE_ARM64": "ARM64 little endian",
    "IMAGE_FILE_MACHINE_ARMNT": "ARM Thumb-2 little endian",
    "IMAGE_FILE_MACHINE_AXP64": "AXP 64",
    "IMAGE_FILE_MACHINE_EBC": "EFI byte code",
    "IMAGE_FILE_MACHINE_I386": "Intel 386 or later processors and compatible processors",
    "IMAGE_FILE_MACHINE_IA64": "Intel Itanium processor family",
    "IMAGE_FILE_MACHINE_LOONGARCH32": "LoongArch 32-bit processor family",
    "IMAGE_FILE_MACHINE_LOONGARCH64": "LoongArch 64-bit processor family", 
    "IMAGE_FILE_MACHINE_M32R": "Mitsubishi M32R little endian",
    "IMAGE_FILE_MACHINE_MIPS16": "MIPS16",
    "IMAGE_FILE_MACHINE_MIPSFPU": "MIPS with FPU",
    "IMAGE_FILE_MACHINE_MIPSFPU16": "MIPS16 with FPU",
    "IMAGE_FILE_MACHINE_POWERPC": "Power PC little endian",
    "IMAGE_FILE_MACHINE_POWERPCFP": "Power PC with floating point support",
    "IMAGE_FILE_MACHINE_R4000": "MIPS little endian",
    "IMAGE_FILE_MACHINE_RISCV32": "RISC-V 32-bit address space",
    "IMAGE_FILE_MACHINE_RISCV64": "RISC-V 64-bit address space",
    "IMAGE_FILE_MACHINE_RISCV128": "RISC-V 128-bit address space",
    "IMAGE_FILE_MACHINE_SH3": "Hitachi SH3",
    "IMAGE_FILE_MACHINE_SH3DSP": "Hitachi SH3 DSP",
    "IMAGE_FILE_MACHINE_SH4": "Hitachi SH4",
    "IMAGE_FILE_MACHINE_SH5": "Hitachi SH5",
    "IMAGE_FILE_MACHINE_THUMB": "Thumb",
    "IMAGE_FILE_MACHINE_WCEMIPSV2": "MIPS little-endian WCE v2",
}

class SectionFlags(Flag):
    IMAGE_SCN_TYPE_NO_PAD = 0x8
    IMAGE_SCN_CNT_CODE = 0x20
    IMAGE_SCN_CNT_INITIALIZED_DATA = 0x40
    IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x80
    IMAGE_SCN_LNK_INFO = 0x200
    IMAGE_SCN_LNK_REMOVE = 0x800
    IMAGE_SCN_LNK_COMDAT = 0x1000
    IMAGE_SCN_GPREL = 0x8000
    IMAGE_SCN_ALIGN_1BYTES = 0x100000
    IMAGE_SCN_ALIGN_2BYTES = 0x200000
    IMAGE_SCN_ALIGN_4BYTES = 0x300000
    IMAGE_SCN_ALIGN_8BYTES = 0x400000
    IMAGE_SCN_ALIGN_16BYTES = 0x500000
    IMAGE_SCN_ALIGN_32BYTES = 0x600000
    IMAGE_SCN_ALIGN_64BYTES = 0x700000
    IMAGE_SCN_ALIGN_128BYTES = 0x800000
    IMAGE_SCN_ALIGN_256BYTES = 0x900000
    IMAGE_SCN_ALIGN_512BYTES = 0xA00000
    IMAGE_SCN_ALIGN_1024BYTES = 0xB00000
    IMAGE_SCN_ALIGN_2048BYTES = 0xC00000
    IMAGE_SCN_ALIGN_4096BYTES = 0xD00000
    IMAGE_SCN_ALIGN_8192BYTES = 0xE00000
    IMAGE_SCN_LNK_NRELOC_OVFL = 0x1000000
    IMAGE_SCN_MEM_DISCARDABLE = 0x2000000
    IMAGE_SCN_MEM_NOT_CACHED = 0x4000000
    IMAGE_SCN_MEM_NOT_PAGED = 0x8000000
    IMAGE_SCN_MEM_SHARED = 0x10000000
    IMAGE_SCN_MEM_EXECUTE = 0x20000000
    IMAGE_SCN_MEM_READ = 0x40000000
    IMAGE_SCN_MEM_WRITE = 0x80000000
    
    def desc(flag):
        return sectionflags_descs[flag]

sectionflags_descs = {
    "IMAGE_SCN_TYPE_NO_PAD": "The section should not be padded to the next boundary (obsolete)",
    "IMAGE_SCN_CNT_CODE": "Contains executable code",
    "IMAGE_SCN_CNT_INITIALIZED_DATA": "Contains initialized data",
    "IMAGE_SCN_CNT_UNINITIALIZED_DATA": "Contains uninitialized data",
    "IMAGE_SCN_LNK_INFO": "Contains comments or other information",
    "IMAGE_SCN_LNK_REMOVE": "Will not become part of the image",
    "IMAGE_SCN_LNK_COMDAT": "Contains COMDAT data",
    "IMAGE_SCN_GPREL": "Contains data referenced through the global pointer (GP)",
    "IMAGE_SCN_ALIGN_1BYTES": "Align data on a 1-byte boundary",
    "IMAGE_SCN_ALIGN_2BYTES": "Align data on a 2-byte boundary",
    "IMAGE_SCN_ALIGN_4BYTES": "Align data on a 4-byte boundary",
    "IMAGE_SCN_ALIGN_8BYTES": "Align data on a 8-byte boundary",
    "IMAGE_SCN_ALIGN_16BYTES": "Align data on a 16-byte boundary",
    "IMAGE_SCN_ALIGN_32BYTES": "Align data on a 32-byte boundary",
    "IMAGE_SCN_ALIGN_64BYTES": "Align data on a 64-byte boundary",
    "IMAGE_SCN_ALIGN_128BYTES": "Align data on a 128-byte boundary",
    "IMAGE_SCN_ALIGN_256BYTES": "Align data on a 256-byte boundary",
    "IMAGE_SCN_ALIGN_512BYTES": "Align data on a 512-byte boundary",
    "IMAGE_SCN_ALIGN_1024BYTES": "Align data on a 1024-byte boundary",
    "IMAGE_SCN_ALIGN_2048BYTES": "Align data on a 2048-byte boundary",
    "IMAGE_SCN_ALIGN_4096BYTES": "Align data on a 4096-byte boundary",
    "IMAGE_SCN_ALIGN_8192BYTES": "Align data on a 8192-byte boundary",
    "IMAGE_SCN_LNK_NRELOC_OVFL": "Contains extended relocations",
    "IMAGE_SCN_MEM_DISCARDABLE": "Can be discarded",
    "IMAGE_SCN_MEM_NOT_CACHED": "Cannot be cached",
    "IMAGE_SCN_MEM_NOT_PAGED": "Is not pageable",
    "IMAGE_SCN_MEM_SHARED": "Can be shared in memory",
    "IMAGE_SCN_MEM_EXECUTE": "Can be executed as code",
    "IMAGE_SCN_MEM_READ": "Can be read",
    "IMAGE_SCN_MEM_WRITE": "Can be written to",
}

class WindowsSubsystem(IntEnum):
    IMAGE_SUBSYSTEM_UNKNOWN = 0
    IMAGE_SUBSYSTEM_NATIVE = 1
    IMAGE_SUBSYSTEM_WINDOWS_GUI = 2
    IMAGE_SUBSYSTEM_WINDOWS_CUI = 3
    IMAGE_SUBSYSTEM_OS2_CUI = 5
    IMAGE_SUBSYSTEM_POSIX_CUI = 7
    IMAGE_SUBSYSTEM_NATIVE_WINDOWS = 8
    IMAGE_SUBSYSTEM_WINDOWS_CE_GUI = 9
    IMAGE_SUBSYSTEM_EFI_APPLICATION = 10
    IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER = 11
    IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER = 12
    IMAGE_SUBSYSTEM_EFI_ROM = 13
    IMAGE_SUBSYSTEM_XBOX = 14
    IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION = 16
    
    def desc(value):
        return windowssubsystem_descs[value]

windowssubsystem_descs = {
    "IMAGE_SUBSYSTEM_UNKNOWN": "Unknown subsystem",
    "IMAGE_SUBSYSTEM_NATIVE": "Device drivers and native Windows processes",
    "IMAGE_SUBSYSTEM_WINDOWS_GUI": "Windows graphical user interface (GUI) subsystem",
    "IMAGE_SUBSYSTEM_WINDOWS_CUI": "Windows character subsystem",
    "IMAGE_SUBSYSTEM_OS2_CUI": "OS/2 character subsystem",
    "IMAGE_SUBSYSTEM_POSIX_CUI": "Posix character subsystem",
    "IMAGE_SUBSYSTEM_WINDOWS_NATIVE_WINDOWS": "Native Win9x driver",
    "IMAGE_SUBSYSTEM_WINDOWS_CE_GUI": "Windows CE",
    "IMAGE_SUBSYSTEM_EFI_APPLICATION": "Extensible Firmware Interface (EFI) application",
    "IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER": "EFI driver with boot services",
    "IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER": "EFI driver with run-time services",
    "IMAGE_SUBSYSTEM_EFI_ROM": "An EFI ROM image",
    "IMAGE_SUBSYSTEM_XBOX": "XBOX",
    "IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION": "Windows boot application",
}