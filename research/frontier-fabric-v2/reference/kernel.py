#!/usr/bin/env python3
"""Finite, positive, ranked Scientific State Kernel reference semantics."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Any,Iterable
from canonical import content_id

Monomial=tuple[str,...]
Polynomial=dict[Monomial,int]

def poly_zero()->Polynomial:return {}
def poly_one()->Polynomial:return {():1}
def poly_add(a:Polynomial,b:Polynomial)->Polynomial:
    out=dict(a)
    for m,c in b.items(): out[m]=out.get(m,0)+c
    return {m:c for m,c in out.items() if c}
def poly_mul(a:Polynomial,b:Polynomial)->Polynomial:
    if not a or not b:return {}
    out={}
    for am,ac in a.items():
        for bm,bc in b.items():
            m=tuple(sorted(am+bm));out[m]=out.get(m,0)+ac*bc
    return out
def poly_product(ps:Iterable[Polynomial])->Polynomial:
    out=poly_one()
    for p in ps:out=poly_mul(out,p)
    return out
def poly_to_json(p:Polynomial)->list[dict[str,Any]]:
    return [{'atoms':list(m),'coefficient':c} for m,c in sorted(p.items(),key=lambda x:(len(x[0]),x[0],x[1]))]

@dataclass(frozen=True)
class Clause:
    clause_id:str;head:str;head_rank:int;body:tuple[str,...];atoms:tuple[str,...];accepted_event_id:str;profile_id:str
    @staticmethod
    def make(*,head:str,head_rank:int,body:Iterable[str],atoms:Iterable[str],accepted_event_id:str,profile_id:str)->'Clause':
        body_t=tuple(sorted(set(body)));atoms_t=tuple(sorted(atoms))
        core={'head':head,'head_rank':head_rank,'body':list(body_t),'atoms':list(atoms_t),'accepted_event_id':accepted_event_id,'profile_id':profile_id}
        return Clause(content_id('vlc_',core),head,head_rank,body_t,atoms_t,accepted_event_id,profile_id)
    def to_json(self)->dict[str,Any]:
        return {'clause_id':self.clause_id,'head':self.head,'head_rank':self.head_rank,'body':list(self.body),'atoms':list(self.atoms),'accepted_event_id':self.accepted_event_id,'profile_id':self.profile_id}

@dataclass
class Presentation:
    cell_ranks:dict[str,int]
    clauses:list[Clause]
    accepted_events:list[str]
    cell_metadata:dict[str,dict[str,Any]]
    admitted_profiles:list[str]
    def validate(self)->None:
        if len(set(self.accepted_events))!=len(self.accepted_events):raise ValueError('duplicate accepted event')
        if len(set(self.admitted_profiles))!=len(self.admitted_profiles):raise ValueError('duplicate admitted profile')
        seen=set()
        for c in self.clauses:
            if c.clause_id in seen:raise ValueError('duplicate clause')
            seen.add(c.clause_id)
            if c.profile_id not in self.admitted_profiles:raise ValueError('clause uses unadmitted profile')
            if self.cell_ranks.get(c.head)!=c.head_rank:raise ValueError('head rank mismatch')
            if c.accepted_event_id not in self.accepted_events:raise ValueError('clause references unaccepted event')
            for b in c.body:
                if b not in self.cell_ranks:raise ValueError(f'unknown body cell {b}')
                if self.cell_ranks[b]>=c.head_rank:raise ValueError('presentation is not strictly ranked')
    def canonical_clauses(self)->list[dict[str,Any]]:
        return [c.to_json() for c in sorted(self.clauses,key=lambda c:(c.head_rank,c.head,c.clause_id))]
    def presentation_root(self)->str:
        self.validate();return content_id('vpr_',self.to_json())
    def circuit_root(self)->str:
        self.validate();return content_id('vcr_',self.canonical_clauses())
    def to_json(self)->dict[str,Any]:
        return {'cell_ranks':dict(sorted(self.cell_ranks.items())),'cell_metadata':{k:self.cell_metadata[k] for k in sorted(self.cell_metadata)},'accepted_events':list(self.accepted_events),'admitted_profiles':sorted(self.admitted_profiles),'clauses':self.canonical_clauses()}
    @staticmethod
    def empty()->'Presentation': return Presentation({},[],[],{},[])
    @staticmethod
    def from_json(v:dict[str,Any])->'Presentation':
        p=Presentation({k:int(x) for k,x in v['cell_ranks'].items()},[Clause(row['clause_id'],row['head'],int(row['head_rank']),tuple(row['body']),tuple(row['atoms']),row['accepted_event_id'],row['profile_id']) for row in v['clauses']],list(v['accepted_events']),dict(v.get('cell_metadata',{})),list(v.get('admitted_profiles',[])))
        p.validate();return p

def compile_gamma(p:Presentation)->dict[str,Polynomial]:
    p.validate();g={c:poly_zero() for c in p.cell_ranks}
    for clause in sorted(p.clauses,key=lambda c:(c.head_rank,c.head,c.clause_id)):
        atom={tuple(clause.atoms):1};body=poly_product(g[b] for b in clause.body);g[clause.head]=poly_add(g[clause.head],poly_mul(atom,body))
    return g

def lineage_root(g:dict[str,Polynomial])->str:return content_id('vlr_',{c:poly_to_json(p) for c,p in sorted(g.items())})
def minimal_environments(p:Polynomial)->list[list[str]]:
    envs=sorted({tuple(sorted(set(m))) for m in p},key=lambda e:(len(e),e));out=[]
    for e in envs:
        s=set(e)
        if any(set(x).issubset(s) for x in out):continue
        out.append(e)
    return [list(e) for e in out]
def active_environments(p:Polynomial,disabled:Iterable[str])->list[list[str]]:
    d=set(disabled);return [e for e in minimal_environments(p) if d.isdisjoint(e)]
def supported(p:Polynomial,disabled:Iterable[str])->bool:return bool(active_environments(p,disabled))
def active_view_root(disabled:Iterable[str],policy_id:str)->str:return content_id('vav_',{'policy_id':policy_id,'disabled_atoms':sorted(set(disabled))})
def is_hitting_set(envs:Iterable[Iterable[str]],atoms:Iterable[str])->bool:
    es=[set(e) for e in envs];a=set(atoms);return bool(es) and all(bool(e&a) for e in es)
def repair_completes_environment(historical:Iterable[Iterable[str]],disabled:Iterable[str],newly_active:Iterable[str])->bool:
    d=set(disabled)-set(newly_active);return any(d.isdisjoint(set(e)) for e in historical)
def cell_id(*,profile_id:str,claim:dict[str,Any],context:dict[str,Any],polarity:str,cell_kind:str)->str:
    return content_id('vcell_',{'profile_id':profile_id,'claim':claim,'context':context,'polarity':polarity,'cell_kind':cell_kind})
