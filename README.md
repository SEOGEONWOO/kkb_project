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


