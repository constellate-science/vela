#!/usr/bin/env python3
from __future__ import annotations
import math
from typing import Any
def verify_sidon(points:list[list[int]])->tuple[bool,str]:
    seen=set()
    for i in range(len(points)):
        for j in range(i,len(points)):
            s=tuple(a+b for a,b in zip(points[i],points[j]))
            if s in seen:return False,f'duplicate pair sum at ({i},{j})'
            seen.add(s)
    return True,f'{len(seen)} pair sums distinct'
def translate_points(points:list[list[int]],offset:list[int])->list[list[int]]:return [[x+d for x,d in zip(p,offset)] for p in points]
def verify_translation_preserves_sidon(points:list[list[int]],offset:list[int])->dict[str,Any]:
    a,ad=verify_sidon(points);translated=translate_points(points,offset);b,bd=verify_sidon(translated)
    return {'passed':a and b,'verifier_preserving':True,'map':'componentwise_translation','source_detail':ad,'target_detail':bd,'offset':offset,'translated_points':translated}
def heat_solution(alpha:float,x:float,t:float)->float:return math.exp(-alpha*math.pi*math.pi*t)*math.sin(math.pi*x)
def verify_heat_candidate(alpha:float,samples:list[dict[str,str]],tolerance:float)->dict[str,Any]:
    max_error=0.0
    for row in samples:
        x=float(row['x']);t=float(row['t']);u=float(row['u']);max_error=max(max_error,abs(u-heat_solution(alpha,x,t)))
    return {'passed':max_error<=tolerance,'receipt_kind':'semantic_replay','alpha':format(alpha,'.12g'),'sample_count':len(samples),'max_abs_error':format(max_error,'.12g'),'tolerance':format(tolerance,'.12g')}
