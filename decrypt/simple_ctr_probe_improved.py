import argparse, base64, os, re
from typing import Iterable, List, Tuple

def readb(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()

def printable_ratio(b: bytes) -> float:
    if not b: return 0.0
    pr = sum(1 for x in b if x in (9, 10, 13) or 32 <= x <= 126)
    return pr / len(b)

def looks_good(b: bytes) -> bool:
    if not b: return False
    if b.startswith((b"%PDF-", b"PK\x03\x04", b"\x89PNG\r\n\x1a\n")): return True
    s = b.lower()
    if b"ctf{" in s or b"flag" in s: return True
    return printable_ratio(b) > 0.90

def save_hit(outdir: str, tag: str, data: bytes, hits: List[Tuple[str,str]]) -> None:
    os.makedirs(outdir, exist_ok=True)
    path = os.path.join(outdir, f"hit_{len(hits)+1:02d}_{tag}.bin")
    with open(path, "wb") as f: f.write(data)
    hits.append((tag, path))
    print(f"[+] {tag} -> {path}")

def load_keys(cand_path: str) -> List[bytes]:
    keys: List[bytes] = []
    if not cand_path or not os.path.exists(cand_path): return keys
    with open(cand_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith("#"): continue
            try:
                if re.fullmatch(r"[0-9A-Fa-f]{32,64}", s):
                    raw = bytes.fromhex(s)
                    if len(raw) in (16,24,32): keys.append(raw); continue
                raw = base64.b64decode(s)
                if len(raw) in (16,24,32): keys.append(raw); continue
            except: pass
            bs = s.encode()
            if len(bs) in (16,24,32): keys.append(bs)
    uniq, seen = [], set()
    for k in keys:
        if k not in seen:
            uniq.append(k); seen.add(k)
    return uniq

# --- AES primitives (FIPS-197 기반) ---
Sbox=[0x63,0x7C,0x77,0x7B,0xF2,0x6B,0x6F,0xC5,0x30,0x01,0x67,0x2B,0xFE,0xD7,0xAB,0x76,
0xCA,0x82,0xC9,0x7D,0xFA,0x59,0x47,0xF0,0xAD,0xD4,0xA2,0xAF,0x9C,0xA4,0x72,0xC0,
0xB7,0xFD,0x93,0x26,0x36,0x3F,0xF7,0xCC,0x34,0xA5,0xE5,0xF1,0x71,0xD8,0x31,0x15,
0x04,0xC7,0x23,0xC3,0x18,0x96,0x05,0x9A,0x07,0x12,0x80,0xE2,0xEB,0x27,0xB2,0x75,
0x09,0x83,0x2C,0x1A,0x1B,0x6E,0x5A,0xA0,0x52,0x3B,0xD6,0xB3,0x29,0xE3,0x2F,0x84,
0x53,0xD1,0x00,0xED,0x20,0xFC,0xB1,0x5B,0x6A,0xCB,0xBE,0x39,0x4A,0x4C,0x58,0xCF,
0xD0,0xEF,0xAA,0xFB,0x43,0x4D,0x33,0x85,0x45,0xF9,0x02,0x7F,0x50,0x3C,0x9F,0xA8,
0x51,0xA3,0x40,0x8F,0x92,0x9D,0x38,0xF5,0xBC,0xB6,0xDA,0x21,0x10,0xFF,0xF3,0xD2,
0xCD,0x0C,0x13,0xEC,0x5F,0x97,0x44,0x17,0xC4,0xA7,0x7E,0x3D,0x64,0x5D,0x19,0x73,
0x60,0x81,0x4F,0xDC,0x22,0x2A,0x90,0x88,0x46,0xEE,0xB8,0x14,0xDE,0x5E,0x0B,0xDB,
0xE0,0x32,0x3A,0x0A,0x49,0x06,0x24,0x5C,0xC2,0xD3,0xAC,0x62,0x91,0x95,0xE4,0x79,
0xE7,0xC8,0x37,0x6D,0x8D,0xD5,0x4E,0xA9,0x6C,0x56,0xF4,0xEA,0x65,0x7A,0xAE,0x08,
0xBA,0x78,0x25,0x2E,0x1C,0xA6,0xB4,0xC6,0xE8,0xDD,0x74,0x1F,0x4B,0xBD,0x8B,0x8A,
0x70,0x3E,0xB5,0x66,0x48,0x03,0xF6,0x0E,0x61,0x35,0x57,0xB9,0x86,0xC1,0x1D,0x9E,
0xE1,0xF8,0x98,0x11,0x69,0xD9,0x8E,0x94,0x9B,0x1E,0x87,0xE9,0xCE,0x55,0x28,0xDF,
0x8C,0xA1,0x89,0x0D,0xBF,0xE6,0x42,0x68,0x41,0x99,0x2D,0x0F,0xB0,0x54,0xBB,0x16]
Rcon=[0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36]

def xtime(a:int)->int: return ((a<<1)&0xFF)^(0x1B if a&0x80 else 0)
def mix_single_col(a:List[int])->None:
    t=a[0]^a[1]^a[2]^a[3];u=a[0]
    a[0]^=t^xtime(a[0]^a[1]);a[1]^=t^xtime(a[1]^a[2]);a[2]^=t^xtime(a[2]^a[3]);a[3]^=t^xtime(a[3]^u)
def sub_bytes(s:bytearray)->None: 
    for i in range(16): s[i]=Sbox[s[i]]
def shift_rows(s:bytearray)->None:
    s[1],s[5],s[9],s[13]=s[5],s[9],s[13],s[1]
    s[2],s[6],s[10],s[14]=s[10],s[14],s[2],s[6]
    s[3],s[7],s[11],s[15]=s[15],s[3],s[7],s[11]
def mix_columns(s:bytearray)->None:
    for c in range(0,16,4):
        col=list(s[c:c+4]);mix_single_col(col);s[c:c+4]=bytes(col)
def add_round_key(s:bytearray,w:bytearray,r:int)->None:
    for i in range(16): s[i]^=w[r*16+i]
def rot_word(w:bytes)->bytes: return w[1:]+w[:1]
def sub_word(w:bytes)->bytes: return bytes(Sbox[b] for b in w)

def key_expansion(key:bytes)->Tuple[bytearray,int]:
    Nk=len(key)//4;Nr={4:10,6:12,8:14}[Nk]
    w=bytearray(16*(Nr+1));w[:len(key)]=key;i=Nk;tmp=bytearray(4)
    while i<4*(Nr+1):
        tmp[:]=w[(i-1)*4:i*4]
        if i%Nk==0: tmp=bytearray(sub_word(rot_word(tmp)));tmp[0]^=Rcon[i//Nk]
        elif Nk>6 and i%Nk==4: tmp=bytearray(sub_word(tmp))
        for j in range(4): w[i*4+j]=w[(i-Nk)*4+j]^tmp[j]
        i+=1
    return w,Nr

def aes_encrypt_block(inp:bytes,w:bytearray,Nr:int)->bytes:
    s=bytearray(inp);add_round_key(s,w,0)
    for rnd in range(1,Nr): sub_bytes(s);shift_rows(s);mix_columns(s);add_round_key(s,w,rnd)
    sub_bytes(s);shift_rows(s);add_round_key(s,w,Nr);return bytes(s)

def ctr_decrypt(ct:bytes,key:bytes,nonce:bytes,ctr_bytes:int=4,big_endian:bool=True,ctr_start:int=1)->bytes:
    w,Nr=key_expansion(key);out=bytearray(len(ct));off=0;ctr=ctr_start
    while off<len(ct):
        block=bytearray(16);block[:min(len(nonce),16)]=nonce[:min(len(nonce),16)]
        ctr_arr=ctr.to_bytes(ctr_bytes,"big" if big_endian else "little")
        pos=min(16-ctr_bytes,len(nonce));block[pos:pos+ctr_bytes]=ctr_arr
        ks=aes_encrypt_block(block,w,Nr);take=min(16,len(ct)-off)
        for i in range(take): out[off+i]=ct[off+i]^ks[i]
        off+=take;ctr+=1
    return bytes(out)

def probe(enc:bytes,keys:Iterable[bytes],outdir:str)->None:
    hits:List[Tuple[str,str]]=[];offs=(0,4,8,12,16);nlens=(12,16,8,10,14);tlens=(16,12)
    ctrb_opts=(4,8);endian_opts=(True,False);cstart_opts=(1,0)
    for off in offs:
        if off>=len(enc): break
        buf=enc[off:]
        # GCM-like
        for tl in tlens:
            if len(buf)<=tl: continue
            body,tag=buf[:-tl],buf[-tl:]
            for nl in nlens:
                if len(body)<=nl: continue
                nonce,ct=body[:nl],body[nl:]
                for k in keys:
                    for cb in ctrb_opts:
                        for be in endian_opts:
                            for cs in cstart_opts:
                                pt=ctr_decrypt(ct,k,nonce,ctr_bytes=cb,big_endian=be,ctr_start=cs)
                                if looks_good(pt):
                                    print("[KEY]",k.hex());save_hit(outdir,f"GCM_off{off}_nl{nl}_tl{tl}_ctr{cb}_{'BE' if be else 'LE'}_cs{cs}_k{len(k)}",pt,hits)
                                    if len(hits)>=3:return
        # CTR-only
        for nl in nlens:
            if len(buf)<=nl: continue
            nonce,ct=buf[:nl],buf[nl:]
            for k in keys:
                for cb in ctrb_opts:
                    for be in endian_opts:
                        for cs in cstart_opts:
                            pt=ctr_decrypt(ct,k,nonce,ctr_bytes=cb,big_endian=be,ctr_start=cs)
                            if looks_good(pt):
                                print("[KEY]",k.hex());save_hit(outdir,f"CTR_off{off}_nl{nl}_ctr{cb}_{'BE' if be else 'LE'}_cs{cs}_k{len(k)}",pt,hits)
                                if len(hits)>=3:return

def main()->None:
    p=argparse.ArgumentParser(description="AES-CTR/GCM brute probe")
    p.add_argument("encrypted");p.add_argument("candidates");p.add_argument("-o","--outdir",default="out")
    a=p.parse_args()
    enc_data=readb(a.encrypted);key_candidates=load_keys(a.candidates)
    if not key_candidates: print("[!] no key candidates");return
    print(f"[*] data={len(enc_data)} bytes, keys={len(key_candidates)}")
    probe(enc_data,key_candidates,a.outdir)

if __name__=="__main__": main()
