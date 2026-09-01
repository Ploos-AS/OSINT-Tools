from __future__ import annotations

import struct
from .binary_common import BinaryLimits, entropy

CPUS={7:"x86",0x01000007:"x86_64",12:"arm",0x0100000c:"arm64"}

def parse_macho(data: bytes, limits: BinaryLimits) -> dict:
    try:
        if len(data)<28: raise ValueError
        magic=data[:4]
        configs={b"\xce\xfa\xed\xfe":("<",32),b"\xcf\xfa\xed\xfe":("<",64),b"\xfe\xed\xfa\xce":(">",32),b"\xfe\xed\xfa\xcf":(">",64)}
        if magic in (b"\xca\xfe\xba\xbe",b"\xbe\xba\xfe\xca"):
            endian=">" if magic==b"\xca\xfe\xba\xbe" else "<"; count=struct.unpack_from(endian+"I",data,4)[0]
            if count>32 or 8+count*20>len(data): raise ValueError
            architectures=[]
            for i in range(count):
                cpu,subtype,offset,size,_=struct.unpack_from(endian+"IIIII",data,8+i*20)
                if offset+size>len(data): raise ValueError
                architectures.append({"architecture":CPUS.get(cpu,f"cpu_{cpu}"),"offset":offset,"size":size})
            return {"status":"success","format":"macho","variant":"fat","architectures":architectures,"architecture_count":count}
        if magic not in configs: raise ValueError
        endian,bits=configs[magic]; header=32 if bits==64 else 28
        cpu,subtype,filetype,ncmds,sizeofcmds,flags=struct.unpack_from(endian+"IIIIII",data,4)
        if ncmds>limits.max_sections*4 or header+sizeofcmds>len(data): raise ValueError
        offset=header; segments=[]; dylibs=[]; rpaths=[]; uuid=None; entry=None; signed=False
        for _ in range(ncmds):
            if offset+8>len(data): raise ValueError
            command,size=struct.unpack_from(endian+"II",data,offset)
            if size<8 or offset+size>len(data): raise ValueError
            if command in (1,0x19):
                name=data[offset+8:offset+24].split(b"\0",1)[0].decode("ascii","replace")
                if command==0x19: vmaddr,vmsize,fileoff,filesize=struct.unpack_from(endian+"QQQQ",data,offset+24); nsects=struct.unpack_from(endian+"I",data,offset+64)[0]
                else: vmaddr,vmsize,fileoff,filesize=struct.unpack_from(endian+"IIII",data,offset+24); nsects=struct.unpack_from(endian+"I",data,offset+48)[0]
                if nsects>limits.max_sections: raise ValueError
                body=data[fileoff:min(len(data),fileoff+filesize)] if fileoff<=len(data) else b""
                segments.append({"name":name,"virtual_address":vmaddr,"virtual_size":vmsize,"file_size":filesize,"section_count":nsects,"entropy":entropy(body)})
            elif command in (0xc,0x18,0x1f,0x80000018):
                nameoff=struct.unpack_from(endian+"I",data,offset+8)[0]
                if nameoff<size: dylibs.append(data[offset+nameoff:offset+size].split(b"\0",1)[0].decode("utf-8","replace")[:1024])
            elif command==0x8000001c:
                nameoff=struct.unpack_from(endian+"I",data,offset+8)[0]
                if nameoff<size: rpaths.append(data[offset+nameoff:offset+size].split(b"\0",1)[0].decode("utf-8","replace")[:1024])
            elif command==0x1b and size>=24: uuid=data[offset+8:offset+24].hex()
            elif command==0x80000028 and size>=24: entry=struct.unpack_from(endian+"Q",data,offset+8)[0]
            elif command==0x1d: signed=True
            offset+=size
        return {"status":"success","format":"macho","variant":f"Mach-O {bits}","architecture":CPUS.get(cpu,f"cpu_{cpu}"),"bits":bits,"endianness":"little" if endian=="<" else "big","file_type":filetype,"entry_point":entry,"load_command_count":ncmds,"segments":segments,"dylibs":dylibs[:limits.max_imports],"rpaths":rpaths,"uuid":uuid,"code_signature_present":signed}
    except (ValueError,struct.error,OverflowError): return {"status":"failed","format":"macho","reason":"malformed_macho"}
