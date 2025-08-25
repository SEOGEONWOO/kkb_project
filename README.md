# kkb-project
Malware analysis — YARA rules & AES-CTR decryption PoC.

- [yara/](yara/): YARA rules (`YARArule.yar`) + runner (`run_yara.py`)
- [decrypt/](decrypt/): AES-CTR decryption scripts (`run_decrypt.py`, `simple_ctr_probe_improved.py`, `Decrypt_flag.py`, `candidates.txt`)

## Quick start

### 1. YARA (정적 분석)
```bash
pip install yara-python
python yara/run_yara.py yara/YARArule.yar <target_file>

# (1) 파일 특성 확인 (길이/엔트로피/base64 여부 등)
python decrypt/run_decrypt.py <encrypted_file>

# (2) 키 후보 기반 브루트 탐색
python decrypt/simple_ctr_probe_improved.py <encrypted_file> decrypt/candidates.txt -o out

# (3) 특정 키/파라미터로 복호화
python decrypt/Decrypt_flag.py
---
