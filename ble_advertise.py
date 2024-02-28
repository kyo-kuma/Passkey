import hashlib
import hmac
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import sys
import threading
from bluepy.btle import Scanner, DefaultDelegate

def save_advert_plaintxt(advert_plaintxt, advert_plaintxt_path):
    with open("tmp/" + advert_plaintxt_path, "w") as plain_file:
        plain_file.write(advert_plaintxt)

def load_qr_secret(qr_secret_path):
    # QRシークレットをバイナリで読み込む
    with open("tmp/" + qr_secret_path, "rb") as secret_file:
        qr_secret = secret_file.read()

    return qr_secret

class ScanDelegate(DefaultDelegate):
    def __init__(self):
        DefaultDelegate.__init__(self)

# 特定のUUIDを持つデバイスを探す関数
def scan_for_device(target_uuid):
    count = 0
    scanner = Scanner().withDelegate(ScanDelegate())
    print(f"Scanning for UUID: {target_uuid}")

    while True:
        devices = scanner.scan(0.1)  # xx秒間スキャンする

        for dev in devices:
            is_target_device = False
            for (adtype, desc, value) in dev.getScanData():
                if target_uuid in value:
                    is_target_device = True

            if is_target_device:
                print(f"Found target device with UUID {target_uuid}!")
                print(f"Device Address: {dev.addr}")
                print("Device Data:")
                for (adtype, desc, value) in dev.getScanData():
                    print(f"  desc = {desc}")
                    print(f"  value = {value}")
                    print(f"  adtype = {adtype}")
                print("")
                return dev
        count+=1
        if count > 60:
            return None 

def await_advert(eid_key):
    target_uuid = '0000fff9-0000-1000-8000-00805f9b34fb'
    dev = scan_for_device(target_uuid)
    if dev is None:
        return None

    for (adtype, desc, cable_data) in dev.getScanData():
        print(f"  {desc} = {cable_data}")
        if len(cable_data) == 44:
            cable_data = bytes.fromhex(cable_data[4:])
            print(f"  cable_data = {cable_data}")

            if cable_data:
                payload, ok = trial_decrypt(eid_key, cable_data)
                if ok:
                    return payload

    raise RuntimeError("UUID channel closed")

class KeyPurpose:
    EID_KEY = 1
    TUNNEL_ID = 2
    PSK = 3

def derive(output, secret, salt, purpose):
    if purpose >= 0x100:
        raise ValueError("unsupported purpose")

    purpose_bytes = purpose.to_bytes(4, 'little')
    hkdf_extractor = HKDF(
        algorithm=hashes.SHA256(),
        length=len(output),
        salt=salt,
        info=purpose_bytes,
        backend=None
    )
    output[:] = hkdf_extractor.derive(secret)

def trial_decrypt(eid_key, candidate_advert):
    if len(candidate_advert) != 20:
        return (bytearray(16), False)

    hmac_key = eid_key[32:]
    h = hmac.new(hmac_key, candidate_advert[:16], hashlib.sha256)
    expected_tag = h.digest()

    if not hmac.compare_digest(expected_tag[:4], candidate_advert[16:]):
        return (bytearray(16), False)

    cipher = Cipher(algorithms.AES(eid_key[:32]), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(candidate_advert[:16]) + decryptor.finalize()

    if not reserved_bits_are_zero(plaintext):
        return (bytearray(16), False)

    return (plaintext, True)

def reserved_bits_are_zero(plaintext):
    return plaintext[0] == 0

def unpack_decrypted_advert(plaintext):
    nonce = plaintext[1:11]
    routing_id = plaintext[11:14]
    encoded_tunnel_server_domain = int.from_bytes(plaintext[14:16], 'little')
    return (nonce, routing_id, encoded_tunnel_server_domain)

def await_qr_advert(qr_secret):
    eid_key = bytearray(32 + 32)
    derive(eid_key, qr_secret, None, KeyPurpose.EID_KEY)
    return await_advert(eid_key)

def advertise(qr_secret):
    res = await_qr_advert(qr_secret)
    if res is None:
        return None
    return res.hex()

#qr_secret = load_qr_secret("qr_secret.bin")
#print(f"qr_secret: {qr_secret.hex()}")
#data = await_qr_advert()
#print(f"save_advert_plaintxt: {data.hex()}")
#save_advert_plaintxt(data.hex(), 'advert_plaintxt.txt')


