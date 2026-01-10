#!/usr/bin/env python3
"""
Cybersecurity Toolkit – Single-File Python CLI

Features (subcommands):
  crypto:
    - aes-enc, aes-dec  (AES-256-GCM with PBKDF2 key derivation)
    - rsa-gen, rsa-enc, rsa-dec (RSA 2048, OAEP)
    - classical: caesar, vigenere
    - encode: base64/hex encode/decode
    - hash: md5/sha256/sha512 single file or text
  stego:
    - img-hide, img-reveal (LSB steganography on PNG)
  forensics:
    - exif-show, exif-strip (image metadata)
    - integrity-make, integrity-verify (directory/file hash manifest JSON)
  net:
    - port-scan (TCP connect scan)
  util:
    - passgen (secure password)
    - keygen (random key bytes / RSA pair)
    - totp (generate TOTP code)
    - qrcode-make (generate QR PNG)

Usage examples:
  python cyber_toolkit.py crypto aes-enc -i secret.txt -o secret.enc
  python cyber_toolkit.py crypto aes-dec -i secret.enc -o secret.out
  python cyber_toolkit.py crypto rsa-gen --out-dir keys
  python cyber_toolkit.py stego img-hide -i cover.png -m "Hello" -o stego.png
  python cyber_toolkit.py stego img-reveal -i stego.png
  python cyber_toolkit.py forensics exif-strip -i photo.jpg -o clean.jpg
  python cyber_toolkit.py forensics integrity-make -p mydir -o manifest.json
  python cyber_toolkit.py forensics integrity-verify -m manifest.json
  python cyber_toolkit.py net port-scan -H 192.168.1.1 -p 1-1024
  python cyber_toolkit.py util passgen -l 16 -s
  python cyber_toolkit.py util totp --secret JBSWY3DPEHPK3PXP
  python cyber_toolkit.py util qrcode-make -t "https://example.com" -o code.png

Dependencies (install with pip):
  pip install pycryptodome pillow qrcode
  # optional (if you later add QR decode): pip install pyzbar

Security notes:
  - AES uses PBKDF2-HMAC-SHA256 with random salt, AES-256-GCM (authenticated).
  - RSA uses 2048-bit keys with OAEP (SHA-256).
  - LSB stego is for learning only; not secure against steganalysis.
"""

import argparse
import base64
import getpass
import hashlib
import hmac
import json
import math
import os
import secrets
import socket
import string
import struct
import sys
import time
from dataclasses import dataclass
from pathlib import Path

# --- Optional/soft deps ---
try:
    from Crypto.Cipher import AES
    from Crypto.Protocol.KDF import PBKDF2
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_OAEP
except Exception:
    AES = PBKDF2 = RSA = PKCS1_OAEP = None

try:
    from PIL import Image, PngImagePlugin
except Exception:
    Image = None

try:
    import qrcode
except Exception:
    qrcode = None

# ===================== Utility helpers =====================

def read_file_bytes(path: Path) -> bytes:
    with open(path, 'rb') as f:
        return f.read()

def write_file_bytes(path: Path, data: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, 'wb') as f:
        f.write(data)

# ===================== CRYPTO =====================
# AES-256-GCM with PBKDF2

AES_SALT_LEN = 16
AES_IV_LEN = 12
AES_TAG_LEN = 16
AES_PBKDF2_ITERS = 200_000


def ensure_crypto_available():
    if AES is None or PBKDF2 is None:
        sys.exit("PyCryptodome not installed. Run: pip install pycryptodome")


def derive_key_from_password(password: str, salt: bytes, length: int = 32) -> bytes:
    return PBKDF2(password, salt, dkLen=length, count=AES_PBKDF2_ITERS, hmac_hash_module=hashlib.sha256)


def aes_encrypt_file(in_path: Path, out_path: Path, password: str):
    ensure_crypto_available()
    plaintext = read_file_bytes(in_path)
    salt = secrets.token_bytes(AES_SALT_LEN)
    key = derive_key_from_password(password, salt)
    iv = secrets.token_bytes(AES_IV_LEN)
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    # file format: b'CTK1' | salt | iv | tag | ciphertext
    blob = b'CTK1' + salt + iv + tag + ciphertext
    write_file_bytes(out_path, blob)


def aes_decrypt_file(in_path: Path, out_path: Path, password: str):
    ensure_crypto_available()
    blob = read_file_bytes(in_path)
    if not blob.startswith(b'CTK1'):
        sys.exit('Invalid file header; not an AES-GCM blob from this tool.')
    _, rest = blob[:4], blob[4:]
    salt = rest[:AES_SALT_LEN]
    iv = rest[AES_SALT_LEN:AES_SALT_LEN+AES_IV_LEN]
    tag = rest[AES_SALT_LEN+AES_IV_LEN:AES_SALT_LEN+AES_IV_LEN+AES_TAG_LEN]
    ciphertext = rest[AES_SALT_LEN+AES_IV_LEN+AES_TAG_LEN:]
    key = derive_key_from_password(password, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    except Exception:
        sys.exit('Decryption failed: wrong password or corrupted file.')
    write_file_bytes(out_path, plaintext)

# RSA (OAEP)

def rsa_generate(out_dir: Path, bits: int = 2048):
    ensure_crypto_available()
    out_dir.mkdir(parents=True, exist_ok=True)
    key = RSA.generate(bits)
    private_pem = key.export_key()
    public_pem = key.publickey().export_key()
    write_file_bytes(out_dir / 'rsa_private.pem', private_pem)
    write_file_bytes(out_dir / 'rsa_public.pem', public_pem)


def rsa_encrypt(in_path: Path, out_path: Path, public_key_path: Path):
    ensure_crypto_available()
    data = read_file_bytes(in_path)
    key = RSA.import_key(read_file_bytes(public_key_path))
    cipher = PKCS1_OAEP.new(key, hashAlgo=hashlib.sha256())
    # RSA can only encrypt small chunks. We'll do hybrid: generate AES key and wrap it.
    aes_key = secrets.token_bytes(32)
    iv = secrets.token_bytes(AES_IV_LEN)
    cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=iv)
    ct, tag = cipher_aes.encrypt_and_digest(data)
    wrapped_key = cipher.encrypt(aes_key)
    # format: b'CRSA' | len_wrapped(2) | wrapped | iv | tag | ct
    blob = b'CRSA' + struct.pack('>H', len(wrapped_key)) + wrapped_key + iv + tag + ct
    write_file_bytes(out_path, blob)


def rsa_decrypt(in_path: Path, out_path: Path, private_key_path: Path):
    ensure_crypto_available()
    blob = read_file_bytes(in_path)
    if not blob.startswith(b'CRSA'):
        sys.exit('Invalid RSA hybrid blob.')
    idx = 4
    lw = struct.unpack('>H', blob[idx:idx+2])[0]; idx += 2
    wrapped_key = blob[idx:idx+lw]; idx += lw
    iv = blob[idx:idx+AES_IV_LEN]; idx += AES_IV_LEN
    tag = blob[idx:idx+AES_TAG_LEN]; idx += AES_TAG_LEN
    ct = blob[idx:]
    key = RSA.import_key(read_file_bytes(private_key_path))
    cipher_rsa = PKCS1_OAEP.new(key, hashAlgo=hashlib.sha256())
    try:
        aes_key = cipher_rsa.decrypt(wrapped_key)
    except Exception:
        sys.exit('RSA unwrap failed: wrong key.')
    cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=iv)
    try:
        pt = cipher_aes.decrypt_and_verify(ct, tag)
    except Exception:
        sys.exit('AES decrypt failed: corrupted ciphertext.')
    write_file_bytes(out_path, pt)

# Classical ciphers

def caesar(text: str, shift: int, decrypt=False) -> str:
    if decrypt:
        shift = -shift
    out = []
    for ch in text:
        if 'a' <= ch <= 'z':
            base = ord('a')
            out.append(chr((ord(ch)-base+shift)%26 + base))
        elif 'A' <= ch <= 'Z':
            base = ord('A')
            out.append(chr((ord(ch)-base+shift)%26 + base))
        else:
            out.append(ch)
    return ''.join(out)


def vigenere(text: str, key: str, decrypt=False) -> str:
    key_filtered = [ord(c.lower()) - ord('a') for c in key if c.isalpha()]
    if not key_filtered:
        raise ValueError('Key must contain letters')
    out = []
    j = 0
    for ch in text:
        if ch.isalpha():
            k = key_filtered[j % len(key_filtered)]
            if decrypt:
                k = -k
            if ch.islower():
                base = ord('a')
            else:
                base = ord('A')
            out.append(chr((ord(ch)-base+k)%26 + base))
            j += 1
        else:
            out.append(ch)
    return ''.join(out)

# Encoders / Decoders

def do_encode(data: bytes, mode: str, decode: bool) -> bytes:
    if mode == 'base64':
        return base64.b64decode(data) if decode else base64.b64encode(data)
    elif mode == 'hex':
        return bytes.fromhex(data.decode()) if decode else data.hex().encode()
    else:
        raise ValueError('Unknown mode')

# Hashing

def compute_hash(data: bytes, algo: str) -> str:
    h = hashlib.new(algo)
    h.update(data)
    return h.hexdigest()

# ===================== STEGANOGRAPHY (Image & Audio LSB) =====================
# Simple PNG LSB already implemented below; now add WAV (16-bit PCM) LSB hide/reveal.

@dataclass
class StegoConfig:
    channel: int = 0  # 0=R,1=G,2=B for image


def img_hide(input_png: Path, message: bytes, output_png: Path, cfg: StegoConfig = StegoConfig()):
    if Image is None:
        sys.exit('Pillow not installed. Run: pip install pillow')
    img = Image.open(input_png).convert('RGB')
    pixels = img.load()
    w, h = img.size
    capacity_bits = w*h  # using 1 bit per pixel (R/G/B LSB)
    total_bits = 32 + len(message)*8
    if total_bits > capacity_bits:
        sys.exit(f'Message too long. Capacity ~{capacity_bits//8} bytes, need {len(message)} bytes.')
    bitstream = list(format(len(message), '032b')) + [b for byte in message for b in format(byte, '08b')]
    idx = 0
    for y in range(h):
        for x in range(w):
            if idx >= total_bits:
                break
            r,g,b = pixels[x,y]
            bit = int(bitstream[idx]); idx += 1
            if cfg.channel == 0:
                r = (r & 0b11111110) | bit
            elif cfg.channel == 1:
                g = (g & 0b11111110) | bit
            else:
                b = (b & 0b11111110) | bit
            pixels[x,y] = (r,g,b)
        if idx >= total_bits:
            break
    meta = PngImagePlugin.PngInfo()
    meta.add_text('stego', 'lsb-1bit')
    img.save(output_png, pnginfo=meta)


def img_reveal(input_png: Path, cfg: StegoConfig = StegoConfig()) -> bytes:
    if Image is None:
        sys.exit('Pillow not installed. Run: pip install pillow')
    img = Image.open(input_png).convert('RGB')
    pixels = img.load()
    w, h = img.size
    def read_bits(n):
        bits = []
        idx = 0
        for y in range(h):
            for x in range(w):
                r,g,b = pixels[x,y]
                if cfg.channel == 0:
                    bits.append(r & 1)
                elif cfg.channel == 1:
                    bits.append(g & 1)
                else:
                    bits.append(b & 1)
                idx += 1
                if idx >= n:
                    return bits
        return bits
    len_bits = read_bits(32)
    msg_len = int(''.join(str(b) for b in len_bits), 2)
    msg_bits = read_bits(32 + msg_len*8)[32:]
    out = bytearray()
    for i in range(0, len(msg_bits), 8):
        byte = 0
        for b in msg_bits[i:i+8]:
            byte = (byte<<1) | b
        out.append(byte)
    return bytes(out)

# ---- WAV (16-bit PCM) LSB stego ----
import wave

def wav_hide(input_wav: Path, message: bytes, output_wav: Path):
    with wave.open(str(input_wav), 'rb') as w:
        params = w.getparams()
        if params.sampwidth != 2:
            sys.exit('Only 16-bit PCM WAV supported')
        frames = bytearray(w.readframes(params.nframes))
    total_samples = len(frames)//2
    capacity_bits = total_samples  # 1 bit per sample (LSB of little-endian 16-bit)
    total_bits = 32 + len(message)*8
    if total_bits > capacity_bits:
        sys.exit(f'Message too long. Capacity ~{capacity_bits//8} bytes, need {len(message)} bytes.')
    bitstream = list(format(len(message), '032b')) + [b for byte in message for b in format(byte, '08b')]
    bi = 0
    for i in range(0, len(frames), 2):
        if bi >= total_bits:
            break
        # little-endian sample
        lo = frames[i]
        hi = frames[i+1]
        sample = lo | (hi<<8)
        bit = int(bitstream[bi]); bi += 1
        sample = (sample & 0xFFFE) | bit
        frames[i] = sample & 0xFF
        frames[i+1] = (sample >> 8) & 0xFF
    with wave.open(str(output_wav), 'wb') as wout:
        wout.setparams(params)
        wout.writeframes(bytes(frames))


def wav_reveal(input_wav: Path) -> bytes:
    with wave.open(str(input_wav), 'rb') as w:
        params = w.getparams()
        if params.sampwidth != 2:
            sys.exit('Only 16-bit PCM WAV supported')
        frames = w.readframes(params.nframes)
    samples = memoryview(frames)
    def read_bits(n):
        bits = []
        bi = 0
        for i in range(0, len(samples), 2):
            lo = samples[i]
            hi = samples[i+1]
            sample = lo | (hi<<8)
            bits.append(sample & 1)
            bi += 1
            if bi >= n:
                return bits
        return bits
    len_bits = read_bits(32)
    msg_len = int(''.join(str(b) for b in len_bits), 2)
    msg_bits = read_bits(32 + msg_len*8)[32:]
    out = bytearray()
    for i in range(0, len(msg_bits), 8):
        byte = 0
        for b in msg_bits[i:i+8]:
            byte = (byte<<1) | b
        out.append(byte)
    return bytes(out)

# ===================== FORENSICS =====================

# EXIF show/strip

def exif_show(input_img: Path):
    if Image is None:
        sys.exit('Pillow not installed. Run: pip install pillow')
    img = Image.open(input_img)
    info = getattr(img, 'info', {})
    exif = img.getexif()
    exif_dict = {str(tag): str(value) for tag, value in exif.items()} if exif else {}
    out = {"info": {k: str(v) for k,v in info.items()}, "exif": exif_dict}
    print(json.dumps(out, indent=2))


def exif_strip(input_img: Path, output_img: Path):
    if Image is None:
        sys.exit('Pillow not installed. Run: pip install pillow')
    img = Image.open(input_img)
    data = list(img.getdata())
    clean = Image.new(img.mode, img.size)
    clean.putdata(data)
    clean.save(output_img)

# Integrity manifest

def manifest_make(path: Path, out_manifest: Path, algo: str = 'sha256'):
    entries = []
    base = path.resolve()
    if path.is_file():
        files = [path]
    else:
        files = [p for p in path.rglob('*') if p.is_file()]
    for f in files:
        try:
            digest = compute_hash(read_file_bytes(f), algo)
        except Exception as e:
            digest = f"ERROR: {e}"
        entries.append({
            'path': str(f.resolve().relative_to(base if path.is_dir() else f.parent.resolve())),
            'algo': algo,
            'hash': digest
        })
    manifest = {'base': str(base), 'algo': algo, 'entries': entries}
    write_file_bytes(out_manifest, json.dumps(manifest, indent=2).encode())


def manifest_verify(manifest_path: Path) -> int:
    manifest = json.loads(read_file_bytes(manifest_path).decode())
    base = Path(manifest['base'])
    algo = manifest['algo']
    failures = 0
    for e in manifest['entries']:
        fpath = base / e['path']
        if not fpath.exists():
            print(f"MISSING: {fpath}")
            failures += 1
            continue
        digest = compute_hash(read_file_bytes(fpath), algo)
        if digest != e['hash']:
            print(f"MISMATCH: {fpath} expected {e['hash']} got {digest}")
            failures += 1
    if failures == 0:
        print('All files OK')
    else:
        print(f'{failures} problems found')
    return failures

# ===================== NETWORKING =====================

def port_scan(host: str, ports: str, timeout: float = 0.5):
    rng = []
    for part in ports.split(','):
        part = part.strip()
        if '-' in part:
            a,b = part.split('-')
            rng.extend(range(int(a), int(b)+1))
        else:
            if part:
                rng.append(int(part))
    open_ports = []
    for p in sorted(set(rng)):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            try:
                if s.connect_ex((host, p)) == 0:
                    print(f"OPEN {p}")
                    open_ports.append(p)
            except Exception:
                pass
    if not open_ports:
        print('No open ports found (within provided range).')

# ---- Packet sniffer (requires scapy) ----
try:
    from scapy.all import sniff, IP, TCP, UDP
except Exception:
    sniff = IP = TCP = UDP = None


def packet_sniff(count: int = 0, iface: str | None = None, bpf: str | None = None):
    if sniff is None:
        sys.exit('Scapy not installed. Run: pip install scapy')
    def cb(pkt):
        line = 'PKT'
        if IP in pkt:
            ip = pkt[IP]
            line += f" {ip.src}->{ip.dst}"
            if TCP in pkt:
                tcp = pkt[TCP]
                line += f" TCP {tcp.sport}->{tcp.dport}"
            elif UDP in pkt:
                udp = pkt[UDP]
                line += f" UDP {udp.sport}->{udp.dport}"
        print(line)
    sniff(prn=cb, count=count if count>0 else 0, iface=iface, filter=bpf, store=False)

# ---- Encrypted chat (password-derived AES-GCM) ----
import threading

class SecureChannel:
    def __init__(self, password: str):
        ensure_crypto_available()
        self.salt = b'CHATv1__fixed'  # fixed salt for session derivation (for demo); change per deployment
        self.key = derive_key_from_password(password, self.salt)

    def encrypt(self, plaintext: bytes) -> bytes:
        iv = secrets.token_bytes(AES_IV_LEN)
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=iv)
        ct, tag = cipher.encrypt_and_digest(plaintext)
        return iv + tag + ct  # [12|16|N]

    def decrypt(self, blob: bytes) -> bytes:
        iv = blob[:AES_IV_LEN]
        tag = blob[AES_IV_LEN:AES_IV_LEN+AES_TAG_LEN]
        ct = blob[AES_IV_LEN+AES_TAG_LEN:]
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=iv)
        return cipher.decrypt_and_verify(ct, tag)


def _send_loop(sock: socket.socket, sc: SecureChannel):
    for line in sys.stdin:
        msg = line.rstrip("\n")
        blob = sc.encrypt(msg)
        sock.sendall(struct.pack('>I', len(blob)) + blob)


def _recv_loop(sock: socket.socket, sc: SecureChannel):
    while True:
        hdr = sock.recv(4)
        if not hdr:
            break
        (n,) = struct.unpack('>I', hdr)
        blob = b''
        while len(blob) < n:
            chunk = sock.recv(n - len(blob))
            if not chunk:
                break
            blob += chunk
        try:
            msg = sc.decrypt(blob)
            print(f"[peer] {msg.decode(errors='replace')}")
        except Exception:
            print('[peer] <decrypt error>')


def chat_server(host: str, port: int, password: str):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port))
        s.listen(1)
        print(f'Listening on {host}:{port} ...')
        conn, addr = s.accept()
        print('Client connected from', addr)
        sc = SecureChannel(password)
        t = threading.Thread(target=_recv_loop, args=(conn, sc), daemon=True)
        t.start()
        try:
            _send_loop(conn, sc)
        finally:
            conn.close()


def chat_client(host: str, port: int, password: str):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        sc = SecureChannel(password)
        t = threading.Thread(target=_recv_loop, args=(s, sc), daemon=True)
        t.start()
        try:
            _send_loop(s, sc)
        finally:
            s.close()

# ===================== UTILITIES =====================

def password_generate(length: int = 16, symbols: bool = False) -> str:
    alphabet = string.ascii_letters + string.digits
    if symbols:
        alphabet += "!@#$%^&*()-_=+[]{};:,.?/"
    # Ensure at least one of each category if possible
    while True:
        pwd = ''.join(secrets.choice(alphabet) for _ in range(length))
        if (any(c.islower() for c in pwd) and any(c.isupper() for c in pwd)
            and any(c.isdigit() for c in pwd) and ((not symbols) or any(c in "!@#$%^&*()-_=+[]{};:,.?/" for c in pwd))):
            return pwd


def keygen_random(length: int = 32) -> str:
    return secrets.token_hex(length)

# TOTP (RFC 6238) with Base32 secret

def base32_decode(s: str) -> bytes:
    s = s.strip().replace(' ', '').upper()
    padding = '=' * ((8 - len(s) % 8) % 8)
    return base64.b32decode(s + padding)


def totp_now(secret_b32: str, period: int = 30, digits: int = 6, algo: str = 'sha1') -> str:
    secret = base32_decode(secret_b32)
    t = int(time.time()) // period
    msg = struct.pack('>Q', t)
    hm = hmac.new(secret, msg, getattr(hashlib, algo)).digest()
    o = hm[-1] & 0x0F
    code = (struct.unpack('>I', hm[o:o+4])[0] & 0x7fffffff) % (10**digits)
    return str(code).zfill(digits)

# QR code generation

def qrcode_make(text: str, out_path: Path):
    if qrcode is None:
        sys.exit('qrcode not installed. Run: pip install qrcode')
    img = qrcode.make(text)
    img.save(out_path)

# ===================== CLI wiring =====================

def main():
    parser = argparse.ArgumentParser(prog='cyber_toolkit', description='Cybersecurity Toolkit CLI')
    sub = parser.add_subparsers(dest='cmd')

    # crypto group
    p_crypto = sub.add_parser('crypto', help='Cryptography tools')
    subc = p_crypto.add_subparsers(dest='c_cmd')

    # AES
    p_aes_enc = subc.add_parser('aes-enc', help='AES-256-GCM encrypt file (password)')
    p_aes_enc.add_argument('-i','--input', required=True, type=Path)
    p_aes_enc.add_argument('-o','--output', required=True, type=Path)

    p_aes_dec = subc.add_parser('aes-dec', help='AES-256-GCM decrypt file (password)')
    p_aes_dec.add_argument('-i','--input', required=True, type=Path)
    p_aes_dec.add_argument('-o','--output', required=True, type=Path)

    # RSA
    p_rsa_gen = subc.add_parser('rsa-gen', help='Generate RSA keypair')
    p_rsa_gen.add_argument('--out-dir', required=True, type=Path)
    p_rsa_gen.add_argument('--bits', type=int, default=2048)

    p_rsa_enc = subc.add_parser('rsa-enc', help='Encrypt file (RSA hybrid, public key)')
    p_rsa_enc.add_argument('-i','--input', required=True, type=Path)
    p_rsa_enc.add_argument('-o','--output', required=True, type=Path)
    p_rsa_enc.add_argument('--pub', required=True, type=Path)

    p_rsa_dec = subc.add_parser('rsa-dec', help='Decrypt file (RSA hybrid, private key)')
    p_rsa_dec.add_argument('-i','--input', required=True, type=Path)
    p_rsa_dec.add_argument('-o','--output', required=True, type=Path)
    p_rsa_dec.add_argument('--priv', required=True, type=Path)

    # Classical
    p_caesar = subc.add_parser('caesar', help='Caesar cipher (text)')
    p_caesar.add_argument('-t','--text', required=True)
    p_caesar.add_argument('-s','--shift', type=int, required=True)
    p_caesar.add_argument('--dec', action='store_true')

    p_vig = subc.add_parser('vigenere', help='Vigenere cipher (text)')
    p_vig.add_argument('-t','--text', required=True)
    p_vig.add_argument('-k','--key', required=True)
    p_vig.add_argument('--dec', action='store_true')

    # Encode
    p_enc = subc.add_parser('encode', help='Base64/Hex encode/decode')
    p_enc.add_argument('-m','--mode', choices=['base64','hex'], required=True)
    p_enc.add_argument('-t','--text')
    p_enc.add_argument('-i','--input', type=Path)
    p_enc.add_argument('--dec', action='store_true')

    # Hash
    p_hash = subc.add_parser('hash', help='Hash text or file')
    p_hash.add_argument('-a','--algo', choices=['md5','sha1','sha256','sha512'], default='sha256')
    p_hash.add_argument('-t','--text')
    p_hash.add_argument('-i','--input', type=Path)

    # stego group
    p_stego = sub.add_parser('stego', help='Steganography tools')
    sub_s = p_stego.add_subparsers(dest='s_cmd')

    p_hide = sub_s.add_parser('img-hide', help='Hide text into PNG (LSB)')
    p_hide.add_argument('-i','--input', required=True, type=Path)
    p_hide.add_argument('-m','--message', required=True)
    p_hide.add_argument('-o','--output', required=True, type=Path)

    p_rev = sub_s.add_parser('img-reveal', help='Extract hidden text from PNG')
    p_rev.add_argument('-i','--input', required=True, type=Path)

    p_wav_h = sub_s.add_parser('wav-hide', help='Hide text into WAV (16-bit PCM)')
    p_wav_h.add_argument('-i','--input', required=True, type=Path)
    p_wav_h.add_argument('-m','--message', required=True)
    p_wav_h.add_argument('-o','--output', required=True, type=Path)

    p_wav_r = sub_s.add_parser('wav-reveal', help='Extract hidden text from WAV')
    p_wav_r.add_argument('-i','--input', required=True, type=Path)

    # forensics group
    p_for = sub.add_parser('forensics', help='Forensics tools')
    sub_f = p_for.add_subparsers(dest='f_cmd')

    p_exif_show = sub_f.add_parser('exif-show', help='Show EXIF/metadata of image')
    p_exif_show.add_argument('-i','--input', required=True, type=Path)

    p_exif_strip = sub_f.add_parser('exif-strip', help='Strip EXIF/metadata from image')
    p_exif_strip.add_argument('-i','--input', required=True, type=Path)
    p_exif_strip.add_argument('-o','--output', required=True, type=Path)

    p_mk = sub_f.add_parser('integrity-make', help='Make hash manifest for file/dir')
    p_mk.add_argument('-p','--path', required=True, type=Path)
    p_mk.add_argument('-o','--output', required=True, type=Path)
    p_mk.add_argument('-a','--algo', choices=['md5','sha1','sha256','sha512'], default='sha256')

    p_vf = sub_f.add_parser('integrity-verify', help='Verify hash manifest')
    p_vf.add_argument('-m','--manifest', required=True, type=Path)

    # net group
    p_net = sub.add_parser('net', help='Networking tools')
    sub_n = p_net.add_subparsers(dest='n_cmd')

    p_scan = sub_n.add_parser('port-scan', help='TCP port scanner')
    p_scan.add_argument('-H','--host', required=True)
    p_scan.add_argument('-p','--ports', required=True, help='e.g., 22,80,443,8000-8100')
    p_scan.add_argument('-t','--timeout', type=float, default=0.5)

    p_sniff = sub_n.add_parser('sniff', help='Packet sniffer (requires scapy)')
    p_sniff.add_argument('-c','--count', type=int, default=0, help='0 = infinite')
    p_sniff.add_argument('-i','--iface')
    p_sniff.add_argument('-f','--filter', help='BPF filter, e.g. "tcp port 80"')

    p_srv = sub_n.add_parser('chat-server', help='Encrypted chat server (password AES-GCM)')
    p_srv.add_argument('-H','--host', default='0.0.0.0')
    p_srv.add_argument('-P','--port', type=int, default=9009)
    p_srv.add_argument('--password')

    p_cli = sub_n.add_parser('chat-client', help='Encrypted chat client (password AES-GCM)')
    p_cli.add_argument('-H','--host', required=True)
    p_cli.add_argument('-P','--port', type=int, default=9009)
    p_cli.add_argument('--password')

    # util group
    p_util = sub.add_parser('util', help='Utility tools')
    sub_u = p_util.add_subparsers(dest='u_cmd')

    p_pass = sub_u.add_parser('passgen', help='Secure password generator')
    p_pass.add_argument('-l','--length', type=int, default=16)
    p_pass.add_argument('-s','--symbols', action='store_true')

    p_key = sub_u.add_parser('keygen', help='Random key bytes or RSA pair')
    p_key.add_argument('--length', type=int, default=32, help='bytes for random key (ignored for RSA)')
    p_key.add_argument('--rsa', action='store_true')
    p_key.add_argument('--out-dir', type=Path, help='Required if --rsa')

    p_totp = sub_u.add_parser('totp', help='Generate current TOTP code (Base32 secret)')
    p_totp.add_argument('--secret', required=True)
    p_totp.add_argument('--period', type=int, default=30)
    p_totp.add_argument('--digits', type=int, default=6)

    p_qr = sub_u.add_parser('qrcode-make', help='Generate QR code PNG for text/URL')
    p_qr.add_argument('-t','--text', required=True)
    p_qr.add_argument('-o','--output', required=True, type=Path)

    args = parser.parse_args()
    if not args.cmd:
        parser.print_help(); return

    if args.cmd == 'crypto':
        if args.c_cmd == 'aes-enc':
            pwd = getpass.getpass('Password: ')
            aes_encrypt_file(args.input, args.output, pwd)
            print('Encrypted ->', args.output)
        elif args.c_cmd == 'aes-dec':
            pwd = getpass.getpass('Password: ')
            aes_decrypt_file(args.input, args.output, pwd)
            print('Decrypted ->', args.output)
        elif args.c_cmd == 'rsa-gen':
            rsa_generate(args.out_dir, args.bits)
            print('Keys written to', args.out_dir)
        elif args.c_cmd == 'rsa-enc':
            rsa_encrypt(args.input, args.output, args.pub)
            print('Encrypted ->', args.output)
        elif args.c_cmd == 'rsa-dec':
            rsa_decrypt(args.input, args.output, args.priv)
            print('Decrypted ->', args.output)
        elif args.c_cmd == 'caesar':
            print(caesar(args.text, args.shift, decrypt=args.dec))
        elif args.c_cmd == 'vigenere':
            print(vigenere(args.text, args.key, decrypt=args.dec))
        elif args.c_cmd == 'encode':
            if not args.text and not args.input:
                sys.exit('Provide --text or --input')
            data = args.text.encode() if args.text else read_file_bytes(args.input)
            out = do_encode(data, args.mode, args.dec)
            if args.input:
                sys.stdout.buffer.write(out)
            else:
                print(out.decode(errors='ignore'))
        elif args.c_cmd == 'hash':
            if not args.text and not args.input:
                sys.exit('Provide --text or --input')
            data = args.text.encode() if args.text else read_file_bytes(args.input)
            print(compute_hash(data, args.algo))
        else:
            p_crypto.print_help()

    elif args.cmd == 'stego':
        if args.s_cmd == 'img-hide':
            img_hide(args.input, args.message.encode(), args.output)
            print('Wrote', args.output)
        elif args.s_cmd == 'img-reveal':
            msg = img_reveal(args.input)
            try:
                print(msg.decode())
            except Exception:
                sys.stdout.buffer.write(msg)
        elif args.s_cmd == 'wav-hide':
            wav_hide(args.input, args.message.encode(), args.output)
            print('Wrote', args.output)
        elif args.s_cmd == 'wav-reveal':
            msg = wav_reveal(args.input)
            try:
                print(msg.decode())
            except Exception:
                sys.stdout.buffer.write(msg)
        else:
            p_stego.print_help()

    elif args.cmd == 'forensics':
        if args.f_cmd == 'exif-show':
            exif_show(args.input)
        elif args.f_cmd == 'exif-strip':
            exif_strip(args.input, args.output)
            print('Saved', args.output)
        elif args.f_cmd == 'integrity-make':
            manifest_make(args.path, args.output, args.algo)
            print('Manifest ->', args.output)
        elif args.f_cmd == 'integrity-verify':
            rc = manifest_verify(args.manifest)
            sys.exit(rc)
        else:
            p_for.print_help()

    elif args.cmd == 'net':
        if args.n_cmd == 'port-scan':
            port_scan(args.host, args.ports, args.timeout)
        elif args.n_cmd == 'sniff':
            packet_sniff(args.count, args.iface, args.filter)
        elif args.n_cmd == 'chat-server':
            pwd = args.password or getpass.getpass('Chat password: ')
            chat_server(args.host, args.port, pwd)
        elif args.n_cmd == 'chat-client':
            pwd = args.password or getpass.getpass('Chat password: ')
            chat_client(args.host, args.port, pwd)
        else:
            p_net.print_help()

    elif args.cmd == 'util':
        if args.u_cmd == 'passgen':
            print(password_generate(args.length, args.symbols))
        elif args.u_cmd == 'keygen':
            if args.rsa:
                if not args.out_dir:
                    sys.exit('--out-dir required for --rsa')
                rsa_generate(args.out_dir)
                print('RSA keys written to', args.out_dir)
            else:
                print(keygen_random(args.length))
        elif args.u_cmd == 'totp':
            print(totp_now(args.secret, args.period, args.digits))
        elif args.u_cmd == 'qrcode-make':
            qrcode_make(args.text, args.output)
            print('QR saved ->', args.output)
        else:
            p_util.print_help()

if __name__ == '__main__':
    main()