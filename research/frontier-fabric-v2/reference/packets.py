#!/usr/bin/env python3
from __future__ import annotations
import base64, hashlib
from typing import Any
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from canonical import canonical_bytes, content_id
SCHEMA_VERSION='vela.constellate.frontier-fabric.v2'
PACKET_ID_DOMAIN=b'vela.frontier-fabric.packet-id.v2\x00'
SIGNATURE_DOMAIN=b'vela.frontier-fabric.packet-signature.v2\x00'
PREFIX={'obligation':'vobl_','candidate':'vcand_','model_receipt':'vmr_','target_receipt':'vtrc_','transfer':'vtx_','acceptance':'vac_','observation':'vop_','support_function':'vsf_','challenge':'vch_','view_decision':'vvd_','repair':'vrp_','failure':'vfail_'}
def packet_body(p:dict[str,Any])->dict[str,Any]: return {k:v for k,v in p.items() if k not in {'packet_id','signature'}}
def packet_id(t:str,body:dict[str,Any])->str:
    if t not in PREFIX: raise ValueError(f'unknown packet type {t}')
    return content_id(PREFIX[t],{'domain':PACKET_ID_DOMAIN.decode('latin1'),'packet_type':t,'body':body})
def signing_preimage(pid:str,body:dict[str,Any])->bytes: return SIGNATURE_DOMAIN+pid.encode()+b'\x00'+canonical_bytes(body)
def public_key_b64(key:Ed25519PrivateKey)->str: return base64.b64encode(key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)).decode()
def signed_packet(t:str,fields:dict[str,Any],key:Ed25519PrivateKey,actor:str,actor_kind:str)->dict[str,Any]:
    reserved={'packet_id','signature','schema_version','packet_type','signer_actor','signer_public_key','signer_kind'}
    if reserved & fields.keys(): raise ValueError('reserved packet field supplied')
    body={'schema_version':SCHEMA_VERSION,'packet_type':t,'signer_actor':actor,'signer_kind':actor_kind,'signer_public_key':public_key_b64(key),**fields}
    pid=packet_id(t,body); sig=key.sign(signing_preimage(pid,body))
    return {**body,'packet_id':pid,'signature':{'algorithm':'ed25519','value':base64.b64encode(sig).decode()}}
def verify_signed_packet(p:dict[str,Any])->None:
    if p.get('schema_version')!=SCHEMA_VERSION: raise AssertionError('schema version mismatch')
    body=packet_body(p); expected=packet_id(p.get('packet_type'),body)
    if p.get('packet_id')!=expected: raise AssertionError('packet id mismatch')
    sig=p.get('signature',{})
    if sig.get('algorithm')!='ed25519': raise AssertionError('signature algorithm')
    pk=base64.b64decode(p['signer_public_key'],validate=True); raw=base64.b64decode(sig['value'],validate=True)
    if len(pk)!=32 or len(raw)!=64: raise AssertionError('invalid key/signature length')
    Ed25519PublicKey.from_public_bytes(pk).verify(raw,signing_preimage(expected,body))
def deterministic_private_key(label:str)->Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(('vela-frontier-v2:'+label).encode()).digest())
