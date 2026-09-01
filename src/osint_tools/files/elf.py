from __future__ import annotations

import struct
from .binary_common import BinaryLimits, entropy

MACHINES={3:"x86",40:"arm",62:"x86_64",183:"arm64"}

def parse_elf(data: bytes, limits: BinaryLimits) -> dict:
    try:
        if len(data)<52 or data[:4]!=b"\x7fELF": raise ValueError
        cls,encoding=data[4],data[5]
        if cls not in (1,2) or encoding not in (1,2): raise ValueError
        endian="<" if encoding==1 else ">"; endianness="little" if encoding==1 else "big"
        if cls==2:
            if len(data)<64: raise ValueError
            obj,machine=struct.unpack_from(endian+"HH",data,16); entry=struct.unpack_from(endian+"Q",data,24)[0]
            phoff,shoff=struct.unpack_from(endian+"QQ",data,32); phentsize,phnum,shentsize,shnum,shstr=struct.unpack_from(endian+"HHHHH",data,54); fmt=endian+"IIQQQQIIQQ"
        else:
            obj,machine=struct.unpack_from(endian+"HH",data,16); entry=struct.unpack_from(endian+"I",data,24)[0]
            phoff,shoff=struct.unpack_from(endian+"II",data,28); phentsize,phnum,shentsize,shnum,shstr=struct.unpack_from(endian+"HHHHH",data,42); fmt=endian+"IIIIIIIIII"
        expected=struct.calcsize(fmt)
        if shnum>limits.max_sections or shentsize<expected or shoff+shnum*shentsize>len(data): raise ValueError
        raw=[]
        for i in range(shnum): raw.append(struct.unpack_from(fmt,data,shoff+i*shentsize))
        names=b""
        if shstr<shnum:
            row=raw[shstr]; offset,size=row[4],row[5]
            if offset+size<=len(data): names=data[offset:offset+size]
        def name_at(offset):
            if offset>=len(names): return ""
            end=names.find(b"\0",offset); return names[offset:end if end>=0 else len(names)].decode("utf-8","replace")[:256]
        sections=[]; interpreter=None
        for row in raw:
            name=name_at(row[0]); offset,size=row[4],row[5]
            body=data[offset:min(len(data),offset+size)] if offset<=len(data) else b""
            sections.append({"name":name,"type":row[1],"size":size,"entropy":entropy(body)})
            if name==".interp": interpreter=body.split(b"\0",1)[0].decode("utf-8","replace")[:1024]
        stripped=not any(item["name"]==".symtab" for item in sections)
        return {"status":"success","format":"elf","variant":"ELF64" if cls==2 else "ELF32","architecture":MACHINES.get(machine,f"machine_{machine}"),"bits":64 if cls==2 else 32,"endianness":endianness,"object_type":obj,"entry_point":entry,"program_header_count":phnum,"section_count":shnum,"sections":sections,"interpreter":interpreter,"needed_libraries":[],"imports":[],"exports":[],"stripped":stripped}
    except (ValueError,struct.error,OverflowError): return {"status":"failed","format":"elf","reason":"malformed_elf"}
