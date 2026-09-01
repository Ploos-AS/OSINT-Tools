from __future__ import annotations

import struct
from .binary_common import BinaryLimits, entropy

NAMES={1000:"name",1001:"code",1002:"data",1003:"bss",1004:"reloc32",1005:"reloc16",1006:"reloc8",1007:"ext",1008:"symbol",1009:"debug",1010:"end",1011:"header"}

def parse_hunk(data: bytes, limits: BinaryLimits) -> dict:
    offset=0; hunks=[]; symbols=[]; externals=[]; relocations=0; debug=False
    def long():
        nonlocal offset
        if offset+4>len(data): raise ValueError
        value=struct.unpack_from(">I",data,offset)[0]; offset+=4; return value
    def block(count):
        nonlocal offset
        if count>limits.max_scan_bytes//4 or offset+count*4>len(data): raise ValueError
        value=data[offset:offset+count*4]; offset+=count*4; return value
    try:
        if long()!=1011: raise ValueError
        while True:
            count=long()
            if count==0: break
            block(count)
        table_size,first,last=long(),long(),long()
        if table_size>limits.max_sections or last<first or last-first+1>limits.max_sections: raise ValueError
        sizes=[long() for _ in range(last-first+1)]
        while offset<len(data):
            raw_type=long(); kind=raw_type&0x3fffffff; name=NAMES.get(kind,f"unknown_{kind}")
            if kind in (1001,1002):
                count=long(); body=block(count); hunks.append({"type":name,"size":len(body),"entropy":entropy(body)})
            elif kind==1003:
                count=long()
                if count>limits.max_scan_bytes//4: raise ValueError
                hunks.append({"type":"bss","size":count*4})
            elif kind in (1004,1005,1006):
                total=0
                while True:
                    count=long()
                    if count==0: break
                    if count>limits.max_symbols: raise ValueError
                    long(); block(count); total+=count
                    if total>limits.max_symbols: raise ValueError
                relocations+=total; hunks.append({"type":name,"count":total})
            elif kind==1008:
                count_symbols=0
                while True:
                    count=long()
                    if count==0: break
                    text=block(count).rstrip(b"\0").decode("latin-1","replace")[:1024]; value=long()
                    if count_symbols<limits.max_symbols: symbols.append({"name":text,"value":value})
                    count_symbols+=1
                    if count_symbols>limits.max_symbols: raise ValueError
                hunks.append({"type":"symbol","count":count_symbols})
            elif kind==1007:
                count_entries=0
                while True:
                    descriptor=long()
                    if descriptor==0: break
                    ext_type=descriptor>>24; name_count=descriptor&0xffffff
                    name=block(name_count).rstrip(b"\0").decode("latin-1","replace")[:1024]
                    entry={"type":ext_type,"name":name}
                    if ext_type in (0,1,2,3):
                        entry["value"]=long()
                    elif ext_type==130:
                        entry["common_size"]=long(); refs=long()
                        if refs>limits.max_symbols: raise ValueError
                        block(refs); entry["reference_count"]=refs; relocations+=refs
                    elif ext_type>=128:
                        refs=long()
                        if refs>limits.max_symbols: raise ValueError
                        block(refs); entry["reference_count"]=refs; relocations+=refs
                    else:
                        raise ValueError
                    externals.append(entry); count_entries+=1
                    if count_entries>limits.max_symbols: raise ValueError
                hunks.append({"type":"ext","count":count_entries})
            elif kind in (1000,1009):
                count=long(); body=block(count); debug=debug or kind==1009
                hunks.append({"type":name,"size":len(body),"name":body.rstrip(b"\0").decode("latin-1","replace")[:1024] if kind==1000 else None})
            elif kind==1010: hunks.append({"type":"end"})
            else:
                return {"status":"failed","format":"amiga_hunk","reason":"unsupported_hunk","hunk_type":kind,"hunks":hunks}
            if len(hunks)>limits.max_sections*8: raise ValueError
        declared=[{"size_longs":value&0x3fffffff,"memory":"chip" if value&0x40000000 else "fast" if value&0x80000000 else "any"} for value in sizes]
        return {"status":"success","format":"amiga_hunk","variant":"classic","architecture":"m68k","bits":32,"endianness":"big","declared_hunk_count":table_size,"first_hunk":first,"last_hunk":last,"declared_hunks":declared,"hunks":hunks,"relocation_count":relocations,"symbols":symbols,"externals":externals,"debug_present":debug}
    except (ValueError,struct.error,OverflowError): return {"status":"failed","format":"amiga_hunk","reason":"malformed_hunk"}
