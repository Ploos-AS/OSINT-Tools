from __future__ import annotations

import struct
from .binary_common import BinaryLimits, entropy

MACHINES={0x14c:"x86",0x8664:"x86_64",0x1c0:"arm",0xaa64:"arm64"}

def parse_pe(data: bytes, limits: BinaryLimits) -> dict:
    try:
        if len(data)<0x40 or data[:2]!=b"MZ": raise ValueError
        pe=struct.unpack_from("<I",data,0x3c)[0]
        if pe+24>len(data) or data[pe:pe+4]!=b"PE\0\0": raise ValueError
        machine,count,timestamp,_,_,optional_size,characteristics=struct.unpack_from("<HHIIIHH",data,pe+4)
        if count>limits.max_sections or pe+24+optional_size+count*40>len(data): raise ValueError
        optional=pe+24; magic=struct.unpack_from("<H",data,optional)[0]
        if magic==0x10b: bits=32; image_base=struct.unpack_from("<I",data,optional+28)[0]; dd=optional+96
        elif magic==0x20b: bits=64; image_base=struct.unpack_from("<Q",data,optional+24)[0]; dd=optional+112
        else: raise ValueError
        entry=struct.unpack_from("<I",data,optional+16)[0]; subsystem=struct.unpack_from("<H",data,optional+68)[0]
        sections=[]; maximum_end=0; section_offset=optional+optional_size
        for index in range(count):
            off=section_offset+index*40; name=data[off:off+8].split(b"\0",1)[0].decode("ascii","replace")
            virtual_size,virtual_address,raw_size,raw_pointer=struct.unpack_from("<IIII",data,off+8)
            flags=struct.unpack_from("<I",data,off+36)[0]
            raw=data[raw_pointer:min(len(data),raw_pointer+raw_size)] if raw_pointer<=len(data) else b""
            maximum_end=max(maximum_end,raw_pointer+raw_size)
            sections.append({"name":name,"virtual_address":virtual_address,"virtual_size":virtual_size,"raw_size":raw_size,"characteristics":flags,"entropy":entropy(raw)})
        certificate=False
        if dd+8*5<=optional+optional_size:
            cert_offset,cert_size=struct.unpack_from("<II",data,dd+8*4); certificate=bool(cert_offset and cert_size)
        pdb=[]
        for marker in (b".pdb",b".PDB"):
            start=0
            while len(pdb)<10:
                end=data.find(marker,start)
                if end<0: break
                begin=max(data.rfind(b"\0",0,end),data.rfind(b"\n",0,end))+1
                pdb.append(data[begin:end+4].decode("utf-8","replace")[-1024:]); start=end+4
        return {"status":"success","format":"pe","variant":"PE32+" if bits==64 else "PE32","architecture":MACHINES.get(machine,f"machine_{machine:#x}"),"bits":bits,"endianness":"little","timestamp":timestamp,"entry_point":entry,"image_base":image_base,"subsystem":subsystem,"dll":bool(characteristics&0x2000),"section_count":count,"sections":sections,"imports":[],"exports":[],"pdb_paths":pdb,"authenticode_present":certificate,"overlay_size":max(0,len(data)-maximum_end),"truncated_scan":False}
    except (ValueError,struct.error,OverflowError):
        return {"status":"failed","format":"pe","reason":"malformed_pe"}
