# kkb-project
Malware analysis — YARA rules & AES-CTR decryption PoC.

- [yara/](yara/): YARA rules (`YARArule.yar`) + runner (`run_yara.py`)
- [decrypt/](decrypt/): (추가 예정)

## Quick start
```bash
pip install yara-python
python yara/run_yara.py yara/YARArule.yar <target_file>
