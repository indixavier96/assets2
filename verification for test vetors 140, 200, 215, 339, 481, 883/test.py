import hashlib
import base58
from ecdsa import SigningKey, SECP256k1

def privkey_to_address(priv_hex):
    priv = bytes.fromhex(priv_hex)

    sk = SigningKey.from_string(priv, curve=SECP256k1)
    vk = sk.get_verifying_key()

    # compressed public key
    x = vk.pubkey.point.x()
    y = vk.pubkey.point.y()
    prefix = b'\x02' if y % 2 == 0 else b'\x03'
    pubkey = prefix + x.to_bytes(32, 'big')

    sha = hashlib.sha256(pubkey).digest()
    ripe = hashlib.new('ripemd160', sha).digest()

    payload = b'\x00' + ripe
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]

    return base58.b58encode(payload + checksum).decode()

pairs = [
	("cf51b80725e6ace21579746a1b643ebad1fbfae4b075d655b4d8a037e59d891d",
	 "1DzSWsvayuavQ2Fs7FXhiqifdm4YXW3on7"),
	
    ("c4eb116ef0c090166ca87b3bff6b748c9a82ee8d6fe1beb0d517f7627ca73611",
     "19gyTkLDE6j9KRHkTBTAfq1iH3Txnep4K5"),

    ("a466e4d05b55b8a95abe54e7651b4a657053369d07ea318ad73373505b81ab50",
     "17yNxG1vCQX6fRaiWiQzGM77xVGyMhAFX"),

    ("cb68dd62c257057f66489d593d4a4ddb5777267bad9e5c9e928d9541d8785d3f",
     "1AYw4WDVbTuWHfsPGiVeHUnXZynNyS6mxN"),

    ("c4cee0494034f5a0df65e095d3e74b6a63bd0e6cbc070f1155f7c6b2b073784d",
     "1DnRJxt2m1fwF8a3W1tXwp14YaHkMYXm6q"),

    ("8f3c86467ec46b59a813ea04a514a54d2fa9a14fe6cbeb88a95598f7af2813aa",
     "1ND9kT9wLh6Je9Hud3PaHjyos2sMThd1Js"),
]

for priv, addr in pairs:
    derived = privkey_to_address(priv)
    print(priv, derived == addr, derived)