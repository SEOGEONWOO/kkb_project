from simple_ctr_probe_improved import ctr_decrypt, readb

def decrypt_file(enc_path:str,out_path:str,key_hex:str,offset:int,nonce_len:int,tag_len:int,
                 ctr_bytes:int=4,big_endian:bool=True,ctr_start:int=0)->bytes:
    key=bytes.fromhex(key_hex);data=readb(enc_path)
    body=data[offset:len(data)-tag_len if tag_len else len(data)]
    nonce,ct=body[:nonce_len],body[nonce_len:]
    pt=ctr_decrypt(ct,key,nonce,ctr_bytes=ctr_bytes,big_endian=big_endian,ctr_start=ctr_start)
    with open(out_path,"wb") as f:f.write(pt)
    return pt

def main()->None:
    ENC_PATH=r"C:\kkb\Desktop\FLAG.txt.ryk"
    OUT_PATH=r"C:\kkb\sample\Decrypt_\Flag.txt"
    KEY_HEX="b40b41b42b43b44b45b46b47b48b49b5"
    OFFSET,NONCE_LEN,TAG_LEN=12,16,16
    CTR_BYTES,BIG_ENDIAN,CTR_START=4,True,0
    pt=decrypt_file(ENC_PATH,OUT_PATH,KEY_HEX,OFFSET,NONCE_LEN,TAG_LEN,
                    ctr_bytes=CTR_BYTES,big_endian=BIG_ENDIAN,ctr_start=CTR_START)
    try: print("복호화된 평문:",pt.decode(errors="ignore"))
    except: print("복호화된 데이터는 바이너리")

if __name__=="__main__": main()
