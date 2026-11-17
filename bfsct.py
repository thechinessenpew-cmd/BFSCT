#!/usr/bin/env python3
# BFSTC - N0pew My Owner
# Copyright (c) 2026 n0pew.cs (TikTok: @n0pew.cs)
# All rights reserved.

import os
import sys
import json
import base64
import hashlib
import hmac
import argparse
from typing import Tuple, Dict, Any

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
except ImportError:
    sys.stderr.write("BFSTC requires the 'cryptography' package.\n")
    sys.stderr.write("Install: pip install cryptography\n")
    sys.exit(1)


MAGIC = b"BFSTC1"
VERSION = 1
NONCE_LEN = 12
SALT_LEN = 16
KEY_LEN = 32
TAG_LEN = 16


def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def _derive_master_key(password: str, salt: bytes) -> bytes:
    kdf = Scrypt(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=salt,
        n=2**15,
        r=8,
        p=1,
        backend=default_backend(),
    )
    return kdf.derive(password.encode("utf-8"))


def _derive_layered_keys(master: bytes, salt: bytes) -> Tuple[bytes, bytes, bytes]:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_LEN * 3,
        salt=salt,
        info=b"BFSTC-layer-keys-v1",
        backend=default_backend(),
    )
    okm = hkdf.derive(master)
    return okm[:KEY_LEN], okm[KEY_LEN:2 * KEY_LEN], okm[2 * KEY_LEN:]


def _layer_aes_gcm_encrypt(key: bytes, nonce: bytes, data: bytes) -> bytes:
    return AESGCM(key).encrypt(nonce, data, b"BFSTC-L1")


def _layer_aes_gcm_decrypt(key: bytes, nonce: bytes, data: bytes) -> bytes:
    return AESGCM(key).decrypt(nonce, data, b"BFSTC-L1")


def _layer_chacha20_encrypt(key: bytes, nonce: bytes, data: bytes) -> bytes:
    return ChaCha20Poly1305(key).encrypt(nonce, data, b"BFSTC-L2")


def _layer_chacha20_decrypt(key: bytes, nonce: bytes, data: bytes) -> bytes:
    return ChaCha20Poly1305(key).decrypt(nonce, data, b"BFSTC-L2")


def _layer_hmac_wrap(key: bytes, data: bytes) -> bytes:
    mac = hmac.new(key, data, hashlib.sha256).digest()
    return mac + data


def _layer_hmac_unwrap(key: bytes, data: bytes) -> bytes:
    if len(data) < 32:
        raise ValueError("truncated")
    mac, body = data[:32], data[32:]
    expect = hmac.new(key, body, hashlib.sha256).digest()
    if not hmac.compare_digest(mac, expect):
        raise ValueError("integrity failure")
    return body


def encrypt_text(plaintext: str, password: str) -> str:
    if not isinstance(plaintext, str) or not isinstance(password, str):
        raise TypeError("plaintext and password must be str")
    if password == "":
        raise ValueError("password must not be empty")

    salt = os.urandom(SALT_LEN)
    nonce_a = os.urandom(NONCE_LEN)
    nonce_b = os.urandom(NONCE_LEN)

    master = _derive_master_key(password, salt)
    k_aes, k_cha, k_mac = _derive_layered_keys(master, salt)

    pt = plaintext.encode("utf-8")
    l1 = _layer_aes_gcm_encrypt(k_aes, nonce_a, pt)
    l2 = _layer_chacha20_encrypt(k_cha, nonce_b, l1)
    l3 = _layer_hmac_wrap(k_mac, l2)

    payload: Dict[str, Any] = {
        "v": VERSION,
        "salt": _b64e(salt),
        "na": _b64e(nonce_a),
        "nb": _b64e(nonce_b),
        "ct": _b64e(l3),
    }
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    blob = MAGIC + body
    return _b64e(blob)


def decrypt_text(token: str, password: str) -> str:
    if not isinstance(token, str) or not isinstance(password, str):
        raise TypeError("token and password must be str")
    if password == "":
        raise ValueError("password must not be empty")

    try:
        blob = _b64d(token)
    except Exception as e:
        raise ValueError(f"invalid token encoding: {e}")

    if not blob.startswith(MAGIC):
        raise ValueError("invalid magic")
    body = blob[len(MAGIC):]
    try:
        payload = json.loads(body.decode("utf-8"))
    except Exception as e:
        raise ValueError(f"invalid payload: {e}")

    if payload.get("v") != VERSION:
        raise ValueError("unsupported version")

    try:
        salt = _b64d(payload["salt"])
        nonce_a = _b64d(payload["na"])
        nonce_b = _b64d(payload["nb"])
        l3 = _b64d(payload["ct"])
    except Exception as e:
        raise ValueError(f"invalid field: {e}")

    if len(salt) != SALT_LEN or len(nonce_a) != NONCE_LEN or len(nonce_b) != NONCE_LEN:
        raise ValueError("invalid lengths")

    master = _derive_master_key(password, salt)
    k_aes, k_cha, k_mac = _derive_layered_keys(master, salt)

    try:
        l2 = _layer_hmac_unwrap(k_mac, l3)
        l1 = _layer_chacha20_decrypt(k_cha, nonce_b, l2)
        pt = _layer_aes_gcm_decrypt(k_aes, nonce_a, l1)
    except Exception:
        raise ValueError("authentication failed")

    return pt.decode("utf-8")


def encrypt_file(in_path: str, out_path: str, password: str) -> None:
    with open(in_path, "rb") as f:
        data = f.read()
    text = data.decode("utf-8")
    token = encrypt_text(text, password)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(token)


def decrypt_file(in_path: str, out_path: str, password: str) -> None:
    with open(in_path, "r", encoding="utf-8") as f:
        token = f.read().strip()
    text = decrypt_text(token, password)
    with open(out_path, "wb") as f:
        f.write(text.encode("utf-8"))


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="bfsct",
        description="BFSTC layered text cipher. Copyright (c) 2026 n0pew.cs (TikTok: @n0pew.cs). N0pew My Owner.",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    enc = sub.add_parser("encrypt", help="encrypt text or file")
    enc.add_argument("-p", "--password", required=True)
    enc.add_argument("-t", "--text", help="plaintext to encrypt")
    enc.add_argument("-i", "--input", help="input file (UTF-8)")
    enc.add_argument("-o", "--output", help="output file (ciphertext)")
    enc.add_argument("--stdout", action="store_true")

    dec = sub.add_parser("decrypt", help="decrypt text or file")
    dec.add_argument("-p", "--password", required=True)
    dec.add_argument("-t", "--token", help="ciphertext token")
    dec.add_argument("-i", "--input", help="input file (ciphertext)")
    dec.add_argument("-o", "--output", help="output file (plaintext)")
    dec.add_argument("--stdout", action="store_true")

    info = sub.add_parser("info", help="show build metadata")
    return p


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        if args.cmd == "info":
            print("BFSTC v1")
            print("layers: AES-256-GCM -> ChaCha20-Poly1305 -> HMAC-SHA256")
            print("kdf: Scrypt(N=2^15,r=8,p=1) -> HKDF-SHA256")
            print("copyright: (c) 2026 n0pew.cs (TikTok: @n0pew.cs)")
            print("signature: N0pew My Owner")
            return 0

        if args.cmd == "encrypt":
            if args.text is not None:
                token = encrypt_text(args.text, args.password)
                if args.stdout or not args.output:
                    print(token)
                else:
                    with open(args.output, "w", encoding="utf-8") as f:
                        f.write(token)
                return 0
            if args.input:
                if not args.output:
                    sys.stderr.write("encrypt: --output required with --input\n")
                    return 2
                encrypt_file(args.input, args.output, args.password)
                return 0
            sys.stderr.write("encrypt: provide --text or --input\n")
            return 2

        if args.cmd == "decrypt":
            if args.token is not None:
                pt = decrypt_text(args.token, args.password)
                if args.stdout or not args.output:
                    print(pt)
                else:
                    with open(args.output, "w", encoding="utf-8") as f:
                        f.write(pt)
                return 0
            if args.input:
                if not args.output:
                    sys.stderr.write("decrypt: --output required with --input\n")
                    return 2
                decrypt_file(args.input, args.output, args.password)
                return 0
            sys.stderr.write("decrypt: provide --token or --input\n")
            return 2

        parser.print_help()
        return 2
    except ValueError as e:
        sys.stderr.write(f"bfsct: {e}\n")
        return 3
    except FileNotFoundError as e:
        sys.stderr.write(f"bfsct: file not found: {e.filename}\n")
        return 4
    except PermissionError as e:
        sys.stderr.write(f"bfsct: permission denied: {e.filename}\n")
        return 5


if __name__ == "__main__":
    raise SystemExit(main())
