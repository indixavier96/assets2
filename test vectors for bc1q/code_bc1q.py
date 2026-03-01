import os

# -------- Bech32 (SegWit v0) --------
CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BECH32_CONST = 1

def bech32_polymod(values):
    GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1ffffff) << 5) ^ v
        for i in range(5):
            chk ^= GEN[i] if ((b >> i) & 1) else 0
    return chk

def bech32_hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]

def bech32_create_checksum(hrp, data):
    values = bech32_hrp_expand(hrp) + data
    polymod = bech32_polymod(values + [0]*6) ^ BECH32_CONST
    return [(polymod >> (5 * (5 - i))) & 31 for i in range(6)]

def bech32_encode(hrp, data):
    return hrp + "1" + "".join(
        CHARSET[d] for d in (data + bech32_create_checksum(hrp, data))
    )

def convertbits(data, from_bits, to_bits):
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << to_bits) - 1
    for v in data:
        acc = (acc << from_bits) | v
        bits += from_bits
        while bits >= to_bits:
            bits -= to_bits
            ret.append((acc >> bits) & maxv)
    if bits:
        ret.append((acc << (to_bits - bits)) & maxv)
    return ret

def generate_bc1q():
    length = 20 if os.urandom(1)[0] % 2 == 0 else 32
    program = os.urandom(length)
    data = [0] + convertbits(program, 8, 5)
    return program.hex(), bech32_encode("bc", data)

# -------- Generate file --------
with open("bc1q_test_vectors.txt", "w") as f:
    for i in range(1, 1001):
        h, addr = generate_bc1q()
        f.write(f"{i:04d}: ({h}, {addr})\n")

print("bc1q test vectors written to bc1q_test_vectors.txt")