# kkb-project

Malware analysis — YARA rules & AES-CTR decryption PoC.

- [yara/](yara/): YARA rules (`YARArule.yar`) + runner (`run_yara.py`)
- [decrypt/](decrypt/): AES-CTR decryption scripts (`run_decrypt.py`, `simple_ctr_probe_improved.py`, `Decrypt_flag.py`, `candidates.txt`)

---

## Quick start

### 1. YARA (정적 분석)

YARA를 통해 악성코드/문서의 포맷 및 의심 패턴을 탐지합니다.

```bash
pip install yara-python
python yara/run_yara.py yara/YARArule.yar <target_file>

### 2. AES-CTR 복호화

AES-CTR 방식으로 암호화된 파일을 복구하기 위한 단계별 절차입니다.

python decrypt/run_decrypt.py <encrypted_file>
python decrypt/simple_ctr_probe_improved.py <encrypted_file> decrypt/candidates.txt -o out
python decrypt/Decrypt_flag.py
