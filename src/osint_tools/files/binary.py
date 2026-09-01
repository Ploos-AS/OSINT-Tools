from __future__ import annotations

from .amiga_hunk import parse_hunk
from .binary_common import BinaryLimits, entropy, extract_strings
from .elf import parse_elf
from .indicators import extract_candidates
from .macho import parse_macho
from .pe import parse_pe


def analyze_binary(path, detected_type: str, limits: BinaryLimits):
    with open(path,"rb") as stream: data=stream.read(limits.max_scan_bytes+1)
    truncated=len(data)>limits.max_scan_bytes; data=data[:limits.max_scan_bytes]
    parser={"pe":parse_pe,"elf":parse_elf,"macho":parse_macho,"amiga_hunk":parse_hunk}.get(detected_type)
    if parser is None: return None,[]
    structure=parser(data,limits)
    strings,strings_truncated=extract_strings(data,limits)
    candidates,candidates_truncated=extract_candidates(strings,limits.max_candidates)
    result={"status":structure.get("status","failed"),"parser":"internal-bounded-v1","format":detected_type,"structure":structure,"scanned_bytes":len(data),"scan_truncated":truncated,"entropy":entropy(data),"high_entropy":entropy(data)>=7.2,"strings":{"count":len(strings),"truncated":strings_truncated,"items":strings},"candidate_summary":{"count":len(candidates),"truncated":candidates_truncated}}
    return result,candidates
