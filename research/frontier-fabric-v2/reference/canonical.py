#!/usr/bin/env python3
"""Canonical JSON subset, digests, and content identifiers."""
from __future__ import annotations
import hashlib, json, unicodedata
from typing import Any

CANON_DOMAIN=b"vela.scientific-state-fabric.canonical.v1\x00"

def _normalize(value:Any,path:str='$')->Any:
    if value is None or isinstance(value,bool): return value
    if isinstance(value,int) and not isinstance(value,bool): return value
    if isinstance(value,float): raise TypeError(f'floating-point value forbidden at {path}')
    if isinstance(value,str): return unicodedata.normalize('NFC',value)
    if isinstance(value,list): return [_normalize(v,f'{path}[{i}]') for i,v in enumerate(value)]
    if isinstance(value,dict):
        out={}
        for k,v in value.items():
            if not isinstance(k,str): raise TypeError(f'non-string key at {path}')
            nk=unicodedata.normalize('NFC',k)
            if nk in out: raise ValueError(f'duplicate normalized key at {path}: {nk}')
            out[nk]=_normalize(v,f'{path}.{nk}')
        return out
    raise TypeError(f'unsupported canonical value at {path}: {type(value).__name__}')

def canonical_bytes(value:Any)->bytes:
    return json.dumps(_normalize(value),sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()

def sha256_bytes(data:bytes)->str: return hashlib.sha256(data).hexdigest()
def digest(value:Any)->str: return 'sha256:'+sha256_bytes(CANON_DOMAIN+canonical_bytes(value))
def content_id(prefix:str,value:Any)->str:
    if not prefix.endswith('_'): raise ValueError('prefix must end in _')
    return prefix+sha256_bytes(CANON_DOMAIN+canonical_bytes(value))
