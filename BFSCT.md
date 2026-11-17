# BFSTC

BFSTC is a layered text-cipher tool written in Python. It combines
AES-256-GCM, ChaCha20-Poly1305, HMAC-SHA256 integrity wrapping, and
Scrypt + HKDF-SHA256 key derivation into a single authenticated
pipeline.

**Author:** n0pew.cs
**TikTok:** [@n0pew.cs](https://www.tiktok.com/@n0pew.cs)
**Copyright:** (c) 2026 n0pew.cs. All rights reserved.
**License:** BFSTC Source-Available License 1.0 (see [`LICENSE`](LICENSE)).
**Signature:** N0pew My Owner

## Status

Source-available. Not open source. Redistribution, modification,
sublicensing, and commercial use are prohibited without prior written
permission from the copyright holder.

## What it does

- Encrypts UTF-8 text or files with a password.
- Three independent cryptographic layers, each with its own subkey.
- Three independent integrity tags. Any tampering aborts decryption.
- Single self-contained token format (`BFSTC1` magic + JSON body,
  base64-encoded).
- Zero plaintext on authentication failure.

## Install

```bash
pip install cryptography

usage
```python
python bfsct.py info
python bfsct.py encrypt -p "your-password" -t "secret text" --stdout
python bfsct.py decrypt -p "your-password" -t "<token>" --stdout
python bfsct.py encrypt -p "your-password" -i plain.txt -o cipher.txt
python bfsct.py decrypt -p "your-password" -i cipher.txt -o plain.txt
