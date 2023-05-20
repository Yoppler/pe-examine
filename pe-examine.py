import sys
from pathlib import Path

from dataclasses import dataclass
from typing import Callable
from enum import Enum
import inspect
from datetime import datetime
from copy import deepcopy

import definitions as defs

@dataclass
class Field:
    name: str
    offset: int
    size: int
    value: int | None = None
    format: Callable[[int],str] | Enum | None = None
    int: bool = True
    
    @property
    def value(self):
        return self._value
    
    @value.setter
    def value(self, v):
        if self.format is None:
            self.fmt_value = v
        elif inspect.isclass(self.format) and issubclass(self.format, Enum):
            fmt = self.format(v).name
            if "|" in fmt:
                values = fmt.split("|")
            else:
               values = [fmt]
            
            res = ""
            for i in range(len(values)):
                res += self.format.desc(values[i])
                if i != len(values) - 1:
                    res += "\n" + " "*43
            
            self.fmt_value = res
        elif callable(self.format):
            self.fmt_value = self.format(v)
        
        self._value = v
    
    def __str__(self):
        return f"{self.name:>40} : {self.fmt_value}"
    
    def __add__(self, other):
        self.offset += other
    
    def __sub__(self, other):
        self.offset -= other

class Header:
    def __init__(self, name, fields, start, content):
        self.name = name
        self.fields = fields
        self.start = start
        self.end = 0
        self.content = content
        self.size = 0
    
    @property
    def fields(self):
        return self._fields
    
    @fields.setter
    def fields(self, value):
        if not isinstance(value, list):
            raise TypeError
        
        if not all([isinstance(item, Field) for item in value]):
            raise TypeError
        
        self._fields = value
    
    @property
    def content(self):
        return self._content
    
    @content.setter
    def content(self, value):
        self._content = value
        self.populate_fields()
    
    def populate_fields(self):
        fields = [field + self.start for field in self.fields]
        
        for field in self.fields:
            if field.int:
                field.value = int.from_bytes(self.content[field.offset:field.offset + field.size], 'little')
            else:
                field.value = self.content[field.offset:field.offset + field.size]
            
            setattr(self, self.format_name(field.name), field.value)
            
            if field.offset + field.size > self.end:
                self.end = field.offset + field.size
    
    def reverse_fields(self):
        fields = [field - self.start for field in self.fields]
    
    def format_name(self, name):
        name = name.lower().replace(" ", "_")
        return name
    
    def __str__(self):
        if self.name is None:
            if hasattr(self, "header_name"):
                name = self.header_name.replace(b'\x00', b'').decode('utf-8')
            else:
                raise ValueError
        else:
            name = self.name.upper()
        res = "="*20 + f" {name} " + "="*20
        res = f"{res:^80}\n"
        
        for field in self.fields:
            res += str(field) + "\n"
        
        return res

class Executable:
    def __init__(self, filename):
        self.filename = filename
        self.DOS = Header("MS-DOS Stub", DOSHEADER, 0, self.content)
        self.COFF = Header("COFF File Header", COFFHEADER, self.DOS.pe_header_address, self.content)
        
        # Not a great solution, but it works
        Optional = Header("PE32 Header", PE32HEADER, self.COFF.end, self.content)
        if Optional.magic_number == b"\x0b\x01":
            self.Optional = Optional
            self.Data_dirs = Header("PE32 Data Directories", PE32DATADIRECTORIES, self.COFF.end, self.content)
        elif Optional.magic_number == b"\x0b\x02":
            Optional.reverse_fields()
            self.Optional = Header("PE32+ Header", PE32PLUSHEADER, self.COFF.end, self.content)
            self.Data_dirs = Header("PE32+ Data Directories", PE32PLUSDATADIRECTORIES, self.COFF.end, self.content)
                
        section_table = []
        start = self.COFF.end + self.COFF.optional_header_size
        
        # Deepcopy is a hacky kind of workaround
        header_defs = deepcopy(SECTIONHEADERS)
        for section in range(self.COFF.number_of_sections):
            header = Header(None, header_defs, start, self.content)
            section_table.append(header)
            start = header.end
            header_defs = deepcopy(SECTIONHEADERS)
        
        self.headers = [
            self.DOS,
            self.COFF,
            self.Optional,
            self.Data_dirs,
        ]
        
        self.headers += section_table
    
    @property
    def filename(self):
        return self._filename
    
    @filename.setter
    def filename(self, value):
        path = Path(value)
        
        if not path.exists():
            raise FileNotFoundError
        
        self._filename = path
        
        with open(value, "rb") as f:
            self.content = f.read()
    
    def __str__(self):
        res = "-"*20 + f" {self.filename.name.upper()} " + "-"*20
        res = f"{res:^80}\n"
        
        for header in self.headers:
            res += str(header) + "\n"
        
        return res

def bytes_str(s):
    labels = ["B", "KB", "MB", "GB"]
    
    counter = 0
    while s >= 1024:
        s /= 1024
        counter += 1
    return f"{s:.02f} {labels[counter]}"
        
    """
    if s >= 1024:
        b = s / 1024
        if b >= 1024:
            c = b / 1024
            return f"{c:.02f} MB"
        return f"{b:.02f} KB"
    return str(s) + " bytes"
    """
    
DOSHEADER = [
    Field("Magic Number", 0, 2, int=False),
    Field("PE Header Address", 0x3c, 4, format=hex), 
]

COFFHEADER = [
    Field("Signature", 0, 4, int=False),
    Field("Machine Type", 4, 2, format=defs.MachineType),
    Field("Number of Sections", 6, 2),
    Field("Time Date Stamp", 8, 4),
    Field("Symbol Table Address", 12, 4, format=hex),
    Field("Number of Symbols", 16, 4),
    Field("Optional Header Size", 20, 2, format=bytes_str),
    Field("Characteristics", 22, 2, format=defs.Characteristics)
]

COFFOPTIONALUNCHANGED = [
    Field("Magic Number", 0, 2, int=False),
    Field("Major Linker Version", 2, 1),
    Field("Minor Linker Version", 3, 1),
    Field("Size of Code", 4, 4, format=bytes_str),
    Field("Size of Initialized Data", 8, 4, format=bytes_str),
    Field("Size of Uninitialized Data", 12, 4, format=bytes_str),
    Field("Entry Point Address", 16, 4, format=hex),
    Field("Base of Code", 20, 4, format=hex),
]

COFFOPTIONALUNCHANGED2 = [
    Field("Section Alignment", 32, 4, format=bytes_str),
    Field("File Alignment", 36, 4, format=bytes_str),
    Field("Major OS Version", 40, 2),
    Field("Minor OS Version", 42, 2),
    Field("Major Image Version", 44, 2),
    Field("Minor Image Version", 46, 2),
    Field("Major Subsystem Version", 48, 2),
    Field("Minor Subsystem Version", 50, 2),
    Field("Win32 Version Value", 52, 4),
    Field("Size of Image", 56, 4, format=bytes_str),
    Field("Size of Headers", 60, 4, format=bytes_str),
    Field("Checksum", 64, 4, format=hex),
    Field("Subsystem", 68, 2, format=defs.WindowsSubsystem),
    Field("DLL Characteristics", 70, 2, format=defs.DLLCharacteristics),
]

PE32HEADER = [
    *COFFOPTIONALUNCHANGED,
    Field("Base of Data", 24, 4, format=hex),
    Field("Image Base", 28, 4, format=hex),
    *COFFOPTIONALUNCHANGED2,
    Field("Size of Stack Reserve", 72, 4, format=bytes_str),
    Field("Size of Stack Commit", 76, 4, format=bytes_str),
    Field("Size of Heap Reserve", 80, 4, format=bytes_str),
    Field("Size of Heap Commit", 84, 4, format=bytes_str),
    Field("Loader Flags", 88, 4),
    Field("Number of RVA and Sizes", 92, 4),
]

PE32DATADIRECTORIES = [
    Field("Export Table Address", 96, 4, format=hex),
    Field("Export Table Size", 100, 4, format=bytes_str),
    Field("Import Table Address", 104, 4, format=hex),
    Field("Import Table Size", 108, 4, format=bytes_str),
    Field("Resource Table Address", 112, 4, format=hex),
    Field("Resource Table Size", 116, 4, format=bytes_str),
    Field("Exception Table Address", 120, 4, format=hex),
    Field("Exception Table Size", 124, 4, format=bytes_str),
    Field("Certificate Table Address", 128, 4, format=hex),
    Field("Certificate Table Size", 132, 4, format=bytes_str),
    Field("Base Relocation Table Address", 136, 4, format=hex),
    Field("Base Relocation Table Size", 140, 4, format=bytes_str),
    Field("Debug Data Address", 144, 4, format=hex),
    Field("Debug Data Size", 148, 4, format=bytes_str),
    Field("Architecture", 152, 8),
    Field("Global Pointer", 160, 4, format=hex),
    Field("TLS Table Address", 168, 4, format=hex),
    Field("TLS Table Size", 172, 4, format=bytes_str),
    Field("Load Config Table Address", 176, 4, format=hex),
    Field("Load Config Table Size", 180, 4, format=bytes_str),
    Field("Bound Import Table Address", 184, 4, format=hex),
    Field("Bound Import Table Size", 188, 4, format=bytes_str),
    Field("Import Address Table(IAT) Address", 192, 4, format=hex),
    Field("Import Address Table(IAT) Size", 196, 4, format=bytes_str),
    Field("Delay Import Descriptor Address", 200, 4, format=hex),
    Field("Delay Import Descriptor Size", 204, 4, format=bytes_str),
    Field("CLR Runtime Header Address", 208, 4, format=hex),
    Field("CLR Runtime Header Size", 212, 4, format=bytes_str),
]

PE32PLUSHEADER = [
    *COFFOPTIONALUNCHANGED,
    Field("Image Base", 24, 8, format=hex),
    *COFFOPTIONALUNCHANGED2,
    Field("Size of Stack Reserve", 72, 8, format=bytes_str),
    Field("Size of Stack Commit", 80, 8, format=bytes_str),
    Field("Size of Heap Reserve", 88, 8, format=bytes_str),
    Field("Size of Heap Commit", 96, 8, format=bytes_str),
    Field("Loader Flags", 104, 4),
    Field("Number of RVA and Sizes", 108, 4),
]

PE32PLUSDATADIRECTORIES = [
    Field("Export Table Address", 112, 4, format=hex),
    Field("Export Table Size", 116, 4, format=bytes_str),
    Field("Import Table Address", 120, 4, format=hex),
    Field("Import Table Size", 124, 4, format=bytes_str),
    Field("Resource Table Address", 128, 4, format=hex),
    Field("Resource Table Size", 132, 4, format=bytes_str),
    Field("Exception Table Address", 136, 4, format=hex),
    Field("Exception Table Size", 140, 4, format=bytes_str),
    Field("Certificate Table Address", 144, 4, format=hex),
    Field("Certificate Table Size", 148, 4, format=bytes_str),
    Field("Base Relocation Table Address", 152, 4, format=hex),
    Field("Base Relocation Table Size", 156, 4, format=bytes_str),
    Field("Debug Data Address", 160, 4, format=hex),
    Field("Debug Data Size", 164, 4, format=bytes_str),
    Field("Architecture", 168, 8),
    Field("Global Pointer", 176, 4, format=hex),
    Field("TLS Table Address", 184, 4, format=hex),
    Field("TLS Table Size", 188, 4, format=bytes_str),
    Field("Load Config Table Address", 192, 4, format=hex),
    Field("Load Config Table Size", 196, 4, format=bytes_str),
    Field("Bound Import Table Address", 200, 4, format=hex),
    Field("Bound Import Table Size", 204, 4, format=bytes_str),
    Field("Import Address Table(IAT) Address", 208, 4, format=hex),
    Field("Import Address Table(IAT) Size", 212, 4, format=bytes_str),
    Field("Delay Import Descriptor Address", 216, 4, format=hex),
    Field("Delay Import Descriptor Size", 220, 4, format=bytes_str),
    Field("CLR Runtime Header Address", 224, 4, format=hex),
    Field("CLR Runtime Header Size", 228, 4, format=bytes_str),
]

SECTIONHEADERS = [
    Field("Header Name", 0, 8, int=False),
    Field("Virtual Size", 8, 4, format=bytes_str),
    Field("Virtual Address", 12, 4, format=hex),
    Field("Size of Raw Data", 16, 4, format=bytes_str),
    Field("Pointer to Raw Data", 20, 4, format=hex),
    Field("Pointer to Relocations", 24, 4, format=hex),
    Field("Pointer to Line Numbers", 28, 4, format=hex),
    Field("Number of Relocations", 32, 2),
    Field("Number of Linenumbers", 34, 2),
    Field("Characteristics", 36, 4, format=defs.SectionFlags),
]

def main(fn):
    exe = Executable(fn)
    
    print(exe)

if __name__ == "__main__":
    if not len(sys.argv) == 2:
        print(f"Usage python {sys.argv[0]} <filename>")
        exit()
    main(sys.argv[1])