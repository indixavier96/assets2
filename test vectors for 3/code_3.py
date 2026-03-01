import os
import hashlib

# -------- Base58Check (P2SH) --------
BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def base58_encode(data):
    num = int.from_bytes(data, "big")
    enc = ""
    while num > 0:
        num, rem = divmod(num, 58)
        enc = BASE58[rem] + enc
    pad = len(data) - len(data.lstrip(b"\x00"))
    return "1" * pad + enc

def generate_p2sh():
    redeem_hash = os.urandom(20)
    payload = b"\x05" + redeem_hash
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return redeem_hash.hex(), base58_encode(payload + checksum)

# -------- Generate file --------
with open("p2sh_3_test_vectors.txt", "w") as f:
    for i in range(1, 1001):
        h, addr = generate_p2sh()
        f.write(f"{i:04d}: ({h}, {addr})\n")

print("P2SH test vectors written to p2sh_3_test_vectors.txt")