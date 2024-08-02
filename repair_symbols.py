import r2pipe
import logging
from ctypes import *
from struct import unpack

log = logging.getLogger(__name__)

SHN_UNDEF = 0
STB_GLOBAL_FUNC = 0x12


class Symbol:
    def __init__(self, name, info, value, size, shname, shndx=-1):
        self.name = name
        self.info = info
        self.value = value
        self.size = size
        self.shname = shname
        self.shndx = shndx

    def __str__(self):
        return "%s;%s;%s;%s;%s" % (self.name, self.value, self.size,
                                   self.info, self.shname)


class SHTypes:
    SHT_NULL      = 0
    SHT_PROGBITS  = 1
    SHT_SYMTAB    = 2
    SHT_STRTAB    = 3
    SHT_RELA      = 4
    SHT_HASH      = 5
    SHT_DYNAMIC   = 6
    SHT_NOTE      = 7
    SHT_NOBITS    = 8
    SHT_REL       = 9
    SHT_SHLIB     = 10
    SHT_DYNSYM    = 11
    SHT_NUM       = 12
    SHT_LOPROC    = 0x70000000
    SHT_HIPROC    = 0x7fffffff
    SHT_LOUSER    = 0x80000000
    SHT_HIUSER    = 0xffffffff

class ELFFlags:
    ELFCLASS32  = 0x01
    ELFCLASS64  = 0x02
    EI_CLASS    = 0x04
    EI_DATA     = 0x05
    ELFDATA2LSB = 0x01
    ELFDATA2MSB = 0x02
    EM_386      = 0x03
    EM_X86_64   = 0x3e
    EM_ARM      = 0x28
    EM_MIPS     = 0x08
    EM_SPARCv8p = 0x12
    EM_PowerPC  = 0x14
    EM_ARM64    = 0xb7

class SymFlags:
    STB_LOCAL   = 0
    STB_GLOBAL  = 1
    STB_WEAK    = 2
    STT_NOTYPE  = 0
    STT_OBJECT  = 1
    STT_FUNC    = 2
    STT_SECTION = 3
    STT_FILE    = 4
    STT_COMMON  = 5
    STT_TLS     = 6

class Elf32_Ehdr_LSB(LittleEndianStructure):
    _fields_ =  [
                    ("e_ident",         c_ubyte * 16),
                    ("e_type",          c_ushort),
                    ("e_machine",       c_ushort),
                    ("e_version",       c_uint),
                    ("e_entry",         c_uint),
                    ("e_phoff",         c_uint),
                    ("e_shoff",         c_uint),
                    ("e_flags",         c_uint),
                    ("e_ehsize",        c_ushort),
                    ("e_phentsize",     c_ushort),
                    ("e_phnum",         c_ushort),
                    ("e_shentsize",     c_ushort),
                    ("e_shnum",         c_ushort),
                    ("e_shstrndx",      c_ushort)
                ]
 
class Elf64_Ehdr_LSB(LittleEndianStructure):
    _fields_ =  [
                    ("e_ident",         c_ubyte * 16),
                    ("e_type",          c_ushort),
                    ("e_machine",       c_ushort),
                    ("e_version",       c_uint),
                    ("e_entry",         c_ulonglong),
                    ("e_phoff",         c_ulonglong),
                    ("e_shoff",         c_ulonglong),
                    ("e_flags",         c_uint),
                    ("e_ehsize",        c_ushort),
                    ("e_phentsize",     c_ushort),
                    ("e_phnum",         c_ushort),
                    ("e_shentsize",     c_ushort),
                    ("e_shnum",         c_ushort),
                    ("e_shstrndx",      c_ushort)
                ]

class Elf32_Phdr_LSB(LittleEndianStructure):
    _fields_ =  [
                    ("p_type",          c_uint),
                    ("p_offset",        c_uint),
                    ("p_vaddr",         c_uint),
                    ("p_paddr",         c_uint),
                    ("p_filesz",        c_uint),
                    ("p_memsz",         c_uint),
                    ("p_flags",         c_uint),
                    ("p_align",         c_uint)
                ]

class Elf64_Phdr_LSB(LittleEndianStructure):
    _fields_ =  [
                    ("p_type",          c_uint),
                    ("p_flags",         c_uint),
                    ("p_offset",        c_ulonglong),
                    ("p_vaddr",         c_ulonglong),
                    ("p_paddr",         c_ulonglong),
                    ("p_filesz",        c_ulonglong),
                    ("p_memsz",         c_ulonglong),
                    ("p_align",         c_ulonglong)
                ]

class Elf32_Shdr_LSB(LittleEndianStructure):
    _fields_ =  [
                    ("sh_name",         c_uint),
                    ("sh_type",         c_uint),
                    ("sh_flags",        c_uint),
                    ("sh_addr",         c_uint),
                    ("sh_offset",       c_uint),
                    ("sh_size",         c_uint),
                    ("sh_link",         c_uint),
                    ("sh_info",         c_uint),
                    ("sh_addralign",    c_uint),
                    ("sh_entsize",      c_uint)
                ]

class Elf64_Shdr_LSB(LittleEndianStructure):
    _fields_ =  [
                    ("sh_name",         c_uint),
                    ("sh_type",         c_uint),
                    ("sh_flags",        c_ulonglong),
                    ("sh_addr",         c_ulonglong),
                    ("sh_offset",       c_ulonglong),
                    ("sh_size",         c_ulonglong),
                    ("sh_link",         c_uint),
                    ("sh_info",         c_uint),
                    ("sh_addralign",    c_ulonglong),
                    ("sh_entsize",      c_ulonglong)
                ]

class Elf32_Ehdr_MSB(BigEndianStructure):
    _fields_ =  [
                    ("e_ident",         c_ubyte * 16),
                    ("e_type",          c_ushort),
                    ("e_machine",       c_ushort),
                    ("e_version",       c_uint),
                    ("e_entry",         c_uint),
                    ("e_phoff",         c_uint),
                    ("e_shoff",         c_uint),
                    ("e_flags",         c_uint),
                    ("e_ehsize",        c_ushort),
                    ("e_phentsize",     c_ushort),
                    ("e_phnum",         c_ushort),
                    ("e_shentsize",     c_ushort),
                    ("e_shnum",         c_ushort),
                    ("e_shstrndx",      c_ushort)
                ]
 
class Elf64_Ehdr_MSB(BigEndianStructure):
    _fields_ =  [
                    ("e_ident",         c_ubyte * 16),
                    ("e_type",          c_ushort),
                    ("e_machine",       c_ushort),
                    ("e_version",       c_uint),
                    ("e_entry",         c_ulonglong),
                    ("e_phoff",         c_ulonglong),
                    ("e_shoff",         c_ulonglong),
                    ("e_flags",         c_uint),
                    ("e_ehsize",        c_ushort),
                    ("e_phentsize",     c_ushort),
                    ("e_phnum",         c_ushort),
                    ("e_shentsize",     c_ushort),
                    ("e_shnum",         c_ushort),
                    ("e_shstrndx",      c_ushort)
                ]

class Elf32_Phdr_MSB(BigEndianStructure):
    _fields_ =  [
                    ("p_type",          c_uint),
                    ("p_offset",        c_uint),
                    ("p_vaddr",         c_uint),
                    ("p_paddr",         c_uint),
                    ("p_filesz",        c_uint),
                    ("p_memsz",         c_uint),
                    ("p_flags",         c_uint),
                    ("p_align",         c_uint)
                ]

class Elf64_Phdr_MSB(BigEndianStructure):
    _fields_ =  [
                    ("p_type",          c_uint),
                    ("p_flags",         c_uint),
                    ("p_offset",        c_ulonglong),
                    ("p_vaddr",         c_ulonglong),
                    ("p_paddr",         c_ulonglong),
                    ("p_filesz",        c_ulonglong),
                    ("p_memsz",         c_ulonglong),
                    ("p_align",         c_ulonglong)
                ]

class Elf32_Shdr_MSB(BigEndianStructure):
    _fields_ =  [
                    ("sh_name",         c_uint),
                    ("sh_type",         c_uint),
                    ("sh_flags",        c_uint),
                    ("sh_addr",         c_uint),
                    ("sh_offset",       c_uint),
                    ("sh_size",         c_uint),
                    ("sh_link",         c_uint),
                    ("sh_info",         c_uint),
                    ("sh_addralign",    c_uint),
                    ("sh_entsize",      c_uint)
                ]

class Elf64_Shdr_MSB(BigEndianStructure):
    _fields_ =  [
                    ("sh_name",         c_uint),
                    ("sh_type",         c_uint),
                    ("sh_flags",        c_ulonglong),
                    ("sh_addr",         c_ulonglong),
                    ("sh_offset",       c_ulonglong),
                    ("sh_size",         c_ulonglong),
                    ("sh_link",         c_uint),
                    ("sh_info",         c_uint),
                    ("sh_addralign",    c_ulonglong),
                    ("sh_entsize",      c_ulonglong)
                ]

class Elf32_Sym_LSB(LittleEndianStructure):
    _fields_ =  [
                    ("st_name",         c_uint),
                    ("st_value",        c_uint),
                    ("st_size",         c_uint),
                    ("st_info",         c_ubyte),
                    ("st_other",        c_ubyte),
                    ("st_shndx",        c_ushort)
                ]

class Elf64_Sym_LSB(LittleEndianStructure):
    _fields_ =  [
                    ("st_name",         c_uint),
                    ("st_info",         c_ubyte),
                    ("st_other",        c_ubyte),
                    ("st_shndx",        c_ushort),
                    ("st_value",        c_ulonglong),
                    ("st_size",         c_ulonglong)
                ]

class Elf32_Sym_MSB(BigEndianStructure):
    _fields_ =  [
                    ("st_name",         c_uint),
                    ("st_value",        c_uint),
                    ("st_size",         c_uint),
                    ("st_info",         c_ubyte),
                    ("st_other",        c_ubyte),
                    ("st_shndx",        c_ushort)
                ]

class Elf64_Sym_MSB(BigEndianStructure):
    _fields_ =  [
                    ("st_name",         c_uint),
                    ("st_info",         c_ubyte),
                    ("st_other",        c_ubyte),
                    ("st_shndx",        c_ushort),
                    ("st_value",        c_ulonglong),
                    ("st_size",         c_ulonglong)
                ]

""" This class parses the ELF """
class ELF:
    def __init__(self, binary):
        self.binary    = bytearray(binary)
        self.ElfHeader = None
        self.shdr_l    = []
        self.phdr_l    = []
        self.syms_l    = []
        self.e_ident   = self.binary[:15]
        self.ei_data   = unpack("<B", self.e_ident[ELFFlags.EI_DATA:ELFFlags.EI_DATA+1])[0] # LSB/MSB
        
        self.__setHeaderElf()
        self.__setShdr()
        self.__setPhdr()

    def is_stripped(self):
        if not self.get_symtab():
            return True
        if not self.get_strtab():
            return True
        return False

    def strip_symbols(self):        
        sh2delete = 2
        size2dec  = 0
        end_shdr  = self.ElfHeader.e_shoff + (self.sizeof_sh() * self.ElfHeader.e_shnum)

        symtab = self.get_symtab()
        strtab = self.get_strtab()

        if not symtab or not strtab:
            return False

        log.debug("Stripping binary...")

        if symtab.sh_offset < end_shdr:
            size2dec += symtab.sh_size

        if strtab.sh_offset < end_shdr:
            size2dec += strtab.sh_size

        self.ElfHeader.e_shoff -= size2dec
        self.ElfHeader.e_shnum -= sh2delete

        e_shnum = self.ElfHeader.e_shnum
        e_shoff = self.ElfHeader.e_shoff
        sz_striped = (e_shoff + (e_shnum * self.sizeof_sh()))        

        if strtab.sh_offset > symtab.sh_offset:
            self.cut_at_offset(strtab.sh_offset, strtab.sh_size)  
            self.cut_at_offset(symtab.sh_offset, symtab.sh_size)
        else:
            self.cut_at_offset(symtab.sh_offset, symtab.sh_size)
            self.cut_at_offset(strtab.sh_offset, strtab.sh_size)

        self.binary = self.binary[0:sz_striped]
        self.write(0, self.ElfHeader)
        return True

    def get_symtab(self):
        shstrtab = bytes(self.get_shstrtab_data())
        for sh in self.shdr_l:
            sh_name = shstrtab[sh.sh_name:].split(b"\0")[0]
            if  sh.sh_type == SHTypes.SHT_SYMTAB and \
                (sh.sh_name == SHN_UNDEF or sh_name == ".symtab"):
                return sh
        return None

    def get_strtab(self):
        shstrtab = bytes(self.get_shstrtab_data())
        for sh in self.shdr_l:
            sh_name = shstrtab[sh.sh_name:].split(b"\0")[0]
            if  sh.sh_type == SHTypes.SHT_STRTAB and \
                (sh.sh_name == SHN_UNDEF or sh_name == ".strtab"):
                return sh
        return None

    def getArchMode(self):
        if self.ElfHeader.e_ident[ELFFlags.EI_CLASS] == ELFFlags.ELFCLASS32: 
            return 32
        elif self.ElfHeader.e_ident[ELFFlags.EI_CLASS] == ELFFlags.ELFCLASS64: 
            return 64
        else:
            log.error("ELF.getArchMode() - Bad Arch size")
            return None

    """ Parse ELF header """
    def __setHeaderElf(self):
        e_ident = self.binary[:15]

        ei_class = unpack("<B", e_ident[ELFFlags.EI_CLASS:ELFFlags.EI_CLASS+1])[0]
        ei_data  = unpack("<B", e_ident[ELFFlags.EI_DATA:ELFFlags.EI_DATA+1])[0]

        if ei_class != ELFFlags.ELFCLASS32 and ei_class != ELFFlags.ELFCLASS64:
            log.error("ELF.__setHeaderElf() - Bad Arch size")
            return None

        if ei_data != ELFFlags.ELFDATA2LSB and ei_data != ELFFlags.ELFDATA2MSB:
            log.error("ELF.__setHeaderElf() - Bad architecture endian")
            return None

        if ei_class == ELFFlags.ELFCLASS32: 
            if   ei_data == ELFFlags.ELFDATA2LSB: self.ElfHeader = Elf32_Ehdr_LSB.from_buffer_copy(self.binary)
            elif ei_data == ELFFlags.ELFDATA2MSB: self.ElfHeader = Elf32_Ehdr_MSB.from_buffer_copy(self.binary)
        elif ei_class == ELFFlags.ELFCLASS64: 
            if   ei_data == ELFFlags.ELFDATA2LSB: self.ElfHeader = Elf64_Ehdr_LSB.from_buffer_copy(self.binary)
            elif ei_data == ELFFlags.ELFDATA2MSB: self.ElfHeader = Elf64_Ehdr_MSB.from_buffer_copy(self.binary)

    """ Write the section header to self.binary """
    def write_shdr(self):
        off = self.ElfHeader.e_shoff
        for sh in self.shdr_l:
            self.write(off, sh)
            off += off + sizeof(sh) 

    """ Parse Section header """
    def __setShdr(self):
        shdr_num = self.ElfHeader.e_shnum
        base = self.binary[self.ElfHeader.e_shoff:]
        shdr_l = []

        e_ident = self.binary[:15]
        ei_data = unpack("<B", e_ident[ELFFlags.EI_DATA:ELFFlags.EI_DATA+1])[0]

        for i in range(shdr_num):
            if self.getArchMode() == 32:
                if   ei_data == ELFFlags.ELFDATA2LSB: shdr = Elf32_Shdr_LSB.from_buffer_copy(base)
                elif ei_data == ELFFlags.ELFDATA2MSB: shdr = Elf32_Shdr_MSB.from_buffer_copy(base)
            elif self.getArchMode() == 64:
                if   ei_data == ELFFlags.ELFDATA2LSB: shdr = Elf64_Shdr_LSB.from_buffer_copy(base)
                elif ei_data == ELFFlags.ELFDATA2MSB: shdr = Elf64_Shdr_MSB.from_buffer_copy(base)

            self.shdr_l.append(shdr)
            base = base[self.ElfHeader.e_shentsize:]

        string_table = self.binary[(self.shdr_l[self.ElfHeader.e_shstrndx].sh_offset):]
        for i in range(shdr_num):
            self.shdr_l[i].str_name = string_table[self.shdr_l[i].sh_name:].split(b'\0')[0]

    """ Parse Program header """
    def __setPhdr(self):
        pdhr_num = self.ElfHeader.e_phnum
        base = self.binary[self.ElfHeader.e_phoff:]
        phdr_l = []

        e_ident = self.binary[:15]
        ei_data = unpack("<B", e_ident[ELFFlags.EI_DATA:ELFFlags.EI_DATA+1])[0]

        for i in range(pdhr_num):
            if self.getArchMode() == 32:
                if   ei_data == ELFFlags.ELFDATA2LSB: phdr = Elf32_Phdr_LSB.from_buffer_copy(base)
                elif ei_data == ELFFlags.ELFDATA2MSB: phdr = Elf32_Phdr_MSB.from_buffer_copy(base)
            elif self.getArchMode() == 64:
                if   ei_data == ELFFlags.ELFDATA2LSB: phdr = Elf64_Phdr_LSB.from_buffer_copy(base)
                elif ei_data == ELFFlags.ELFDATA2MSB: phdr = Elf64_Phdr_MSB.from_buffer_copy(base)

            self.phdr_l.append(phdr)
            base = base[self.ElfHeader.e_phentsize:]

    def get_section_id(self, sh_name):
        alternative = None
        for idx, sh in enumerate(self.shdr_l):
            # if (str(sh.str_name) in sh_name.encode('ascii')) or (sh_name.encode('ascii') in str(sh.str_name)):
            if (str(sh.str_name) in sh_name) or (sh_name in str(sh.str_name)):
                alternative = idx
            if sh.str_name == sh_name.encode('ascii'):
                return idx
            
        return alternative

    def get_shstrtab_data(self):
        sh = self.shdr_l[self.ElfHeader.e_shstrndx]
        if sh.sh_type == SHTypes.SHT_STRTAB:
            return self.binary[sh.sh_offset:sh.sh_offset+sh.sh_size]
        return None

    # def get_sym_at_offset(self, off):
    #     if self.getArchMode() == 32:
    #         if   ei_data == ELFFlags.ELFDATA2LSB: sym = Elf32_Sym_LSB.from_buffer_copy(self.binary[off:])
    #         elif ei_data == ELFFlags.ELFDATA2MSB: sym = Elf32_Sym_MSB.from_buffer_copy(self.binary[off:])
    #     elif self.getArchMode() == 64:
    #         if   ei_data == ELFFlags.ELFDATA2LSB: sym = Elf64_Sym_LSB.from_buffer_copy(self.binary[off:])
    #         elif ei_data == ELFFlags.ELFDATA2MSB: sym = Elf64_Sym_MSB.from_buffer_copy(self.binaryGetInputFilePath[off:])
    #     return sym

    def get_entrypoint(self):
        return self.e_entry

    def sizeof_sh(self):
        size = None
        if self.getArchMode() == 32:
            size = sizeof(Elf32_Shdr_LSB())
        elif self.getArchMode() == 64:
            size = sizeof(Elf64_Shdr_LSB())
        return size

    def sizeof_sym(self):
        size = None
        if self.getArchMode() == 32:
            size = sizeof(Elf32_Sym_LSB)
        elif self.getArchMode() == 64:
            size = sizeof(Elf64_Sym_LSB)
        return size

    def append_section_header(self, section):
        sh = None

        if self.getArchMode() == 32:
            if   self.ei_data == ELFFlags.ELFDATA2LSB: sh = Elf32_Shdr_LSB()
            elif self.ei_data == ELFFlags.ELFDATA2MSB: sh = Elf32_Shdr_MSB()
        elif self.getArchMode() == 64:
            if   self.ei_data == ELFFlags.ELFDATA2LSB: sh = Elf64_Shdr_LSB()
            elif self.ei_data == ELFFlags.ELFDATA2MSB: sh = Elf64_Shdr_MSB()

        sh.sh_name      = section["name"]
        sh.sh_type      = section["type"]
        sh.sh_flags     = section["flags"]
        sh.sh_addr      = section["addr"]
        sh.sh_offset    = section["offset"]
        sh.sh_size      = section["size"]
        sh.sh_link      = section["link"]
        sh.sh_info      = section["info"]
        sh.sh_addralign = section["addralign"]
        sh.sh_entsize   = section["entsize"]

        self.binary.extend(sh)

    def append_symbol(self, symbol):
        if self.getArchMode() == 32:
            if   self.ei_data == ELFFlags.ELFDATA2LSB: sym = Elf32_Sym_LSB()
            elif self.ei_data == ELFFlags.ELFDATA2MSB: sym = Elf32_Sym_MSB()
        elif self.getArchMode() == 64:
            if   self.ei_data == ELFFlags.ELFDATA2LSB: sym = Elf64_Sym_LSB()
            elif self.ei_data == ELFFlags.ELFDATA2MSB: sym = Elf64_Sym_MSB()

        sym.st_name   = symbol["name"]
        sym.st_value  = symbol["value"]
        sym.st_size   = symbol["size"]
        sym.st_info   = symbol["info"]
        sym.st_other  = symbol["other"]
        sym.st_shndx  = symbol["shndx"]

        self.binary.extend(sym)

    def get_binary(self):
        return self.binary

    def write(self, offset, data):
        self.binary[offset:offset+sizeof(data)] = data

    def expand_at_offset(self, offset, data):
        self.binary = self.binary[:offset] + data + self.binary[offset:]

    def cut_at_offset(self, offset, size):
        self.binary = self.binary[:offset] + self.binary[offset+size:]

    def save(self, output):
        with open(output, 'wb') as f:
            f.write(self.binary)

class RepairSymbols:
    def __init__(self, input=None, output=None, symbols=None) -> None:
        self.input = input
        self.output = output
        self.symbols = symbols
        self.r2 = None

    def r2_fcn_filter(self, fcn):
        if fcn['name'].startswith(("sym.imp", "loc.imp", "section")):
            return False
        return True

    def get_r2_symbols(self, repair_symbols = None):
        def r2_fcn_filter(fcn):
            if fcn['name'].startswith(("sym.imp", "loc.imp", "section")):
                return False
            return True

        def get_section(addr):
            for idx, s in enumerate(self.r2.cmdj("iSj")):
                if s['vaddr'] <= addr < (s['vaddr'] + s['size']):
                    return (idx, s['name'])
            return None

        symbols = []

        for fnc in filter(r2_fcn_filter, self.r2.cmdj("aflj")):
            sh_idx, sh_name = get_section(fnc['offset'])
            if repair_symbols.get(fnc['offset']):
                fnc_name = repair_symbols.get(fnc['offset'])
            else:
                fnc_name = fnc['name']
                
            if fnc_name.startswith(("sym", "fcn")):
                fnc_name = fnc_name[4:]
                if fnc_name.startswith("go."):
                    fnc_name = fnc_name[3:]

            symbols.append(Symbol(fnc_name, STB_GLOBAL_FUNC,
                                  fnc['offset'], int(fnc['size']), sh_name))
        return symbols

    def write_symbols(self, input_file, output_file, symbols):
        try:
            with open(input_file, 'rb') as f:
                bin = ELF(f.read())

            if len(symbols) < 1:
                log.error("No symbols to export")
                return

            log.debug("Exporting symbols to ELF...")
            bin.strip_symbols()

            # raw strtab
            strtab_raw = b"\x00" + \
                b"\x00".join([sym.name.encode('ascii')
                             for sym in symbols]) + b"\x00"

            symtab = {
                "name": SHN_UNDEF,
                "type": SHTypes.SHT_SYMTAB,
                "flags": 0,
                "addr": 0,
                "offset": len(bin.binary) + (bin.sizeof_sh() * (bin.ElfHeader.e_shnum + 2)),
                "size": (len(symbols) + 1) * bin.sizeof_sym(),
                "link": bin.ElfHeader.e_shnum + 1,  # index of SHT_STRTAB
                "info": 1,
                "addralign": 4,
                "entsize": bin.sizeof_sym()
                }

            off_strtab = (len(bin.binary) + (bin.sizeof_sh() *
                          (bin.ElfHeader.e_shnum + 2)) + (bin.sizeof_sym() * (len(symbols) + 1)))

            strtab = {
                "name": SHN_UNDEF,
                "type": SHTypes.SHT_STRTAB,
                "flags": 0,
                "addr": 0,
                "offset": off_strtab,
                "size": len(strtab_raw),
                "link": 0,
                "info": 0,
                "addralign": 1,
                "entsize": 0
                }

            shdrs = bin.binary[bin.ElfHeader.e_shoff:bin.ElfHeader.e_shoff +
                (bin.sizeof_sh() * bin.ElfHeader.e_shnum)]
            bin.ElfHeader.e_shnum += 2
            bin.ElfHeader.e_shoff = len(bin.binary)
            bin.write(0, bin.ElfHeader)
            bin.binary.extend(shdrs)

            base = bin.binary[bin.ElfHeader.e_shoff:]
            _off = bin.ElfHeader.e_shoff
            for i in range(bin.ElfHeader.e_shnum - 2):
                if bin.getArchMode() == 32:
                    if bin.ei_data == ELFFlags.ELFDATA2LSB:
                        shdr = Elf32_Shdr_LSB.from_buffer_copy(base)
                    elif bin.ei_data == ELFFlags.ELFDATA2MSB: shdr = Elf32_Shdr_MSB.from_buffer_copy(base)
                elif bin.getArchMode() == 64:
                    if bin.ei_data == ELFFlags.ELFDATA2LSB:
                        shdr = Elf64_Shdr_LSB.from_buffer_copy(base)
                    elif bin.ei_data == ELFFlags.ELFDATA2MSB: shdr = Elf64_Shdr_MSB.from_buffer_copy(base)
                base = base[bin.ElfHeader.e_shentsize:]
                bin.write(_off, shdr)
                _off += bin.sizeof_sh()
            bin.append_section_header(symtab)
            bin.append_section_header(strtab)

            # Local symbol - separator
            sym = {
                "name"  : 0,
                "value" : 0,
                "size"  : 0,
                "info"  : SymFlags.STB_LOCAL,
                "other" : 0,
            "shndx" : 0
                }
            bin.append_symbol(sym)

            # add symbols
            for s in symbols:

                sh_idx = bin.get_section_id(s.shname)
                if not sh_idx:
                    log.error("Section ID for '%s' not found" % s.shname)
                    continue

                sym = {
                    "name"  : strtab_raw.index(s.name.encode('ascii')),
                    "value" : s.value,
                    "size"  : s.size,
                    "info"  : s.info,
                    "other" : 0,
                    "shndx" : sh_idx
                    }

                # log.debug("0x%08x - 0x%08x - %s - %d/%d - %d" % (s.value, s.size, s.name, strtab_raw.index(s.name), len(strtab_raw), s.info))
                bin.append_symbol(sym)

            # add symbol strings
            bin.binary.extend(strtab_raw)

            log.debug("ELF saved to: %s" % output_file)
            bin.save(output_file)

        except Exception as e:
            log.exception(e)

    def run(self):
        if not self.input or not self.output:
            return -1

        self.r2 = r2pipe.open(self.input)
        if self.r2 is None:
            return -1

        self.r2.cmd('aa')
        self.r2.cmd('aac')
        self.r2.cmd('aflir')

        file_info = self.r2.cmdj("ij").get("core")

        if file_info['format'].lower() in ('elf', 'elf64'):
            symbols = self.get_r2_symbols(self.symbols)
            self.write_symbols(file_info['file'], self.output, symbols)
        else:
            log.error("The input file is not a ELF")
            return -1
            
        self.r2.quit()
        return 0
