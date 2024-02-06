from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.ec import generate_private_key, SECP256R1
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import os

class Noise:
    def __init__(self):
        self.chaining_key = None
        self.h = None
        self.symmetric_key = None
        self.symmetric_nonce = 0
        self.aead = AESGCM

    def hkdf2(self, ck, ikm):
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=ck,
            info=None
        )
        output = hkdf.derive(ikm)
        return output[:32], output[32:64]

    def init(self, handshake_type):
        KN_PROTOCOL_NAME = b"Noise_KNpsk0_P256_AESGCM_SHA256\x00"
        NK_PROTOCOL_NAME = b"Noise_NKpsk0_P256_AESGCM_SHA256\x00"
        NK_NO_PSK_PROTOCOL_NAME = b"Noise_NK_P256_AESGCM_SHA256\x00"

        if handshake_type == "NKpsk0":
            self.chaining_key = NK_PROTOCOL_NAME
        elif handshake_type == "KNpsk0":
            self.chaining_key = KN_PROTOCOL_NAME
        elif handshake_type == "NK":
            self.chaining_key = NK_NO_PSK_PROTOCOL_NAME

        self.h = self.chaining_key

    def mix_hash(self, data):
        digest = hashes.Hash(hashes.SHA256())
        digest.update(self.h)
        digest.update(data)
        self.h = digest.finalize()
        #print("mix_hash")
        #print(self.h)

    def mix_key(self, ikm):
        self.chaining_key, temp_k = self.hkdf2(self.chaining_key, ikm)
        self.initialize_key(temp_k)

    def mix_key_and_hash(self, ikm):
        output = HKDF(
            algorithm=hashes.SHA256(),
            length=96,
            salt=self.chaining_key,
            info=None
        ).derive(ikm)
        self.chaining_key = output[:32]
        self.mix_hash(output[32:64])
        self.initialize_key(output[64:96])

    def encrypt_and_hash(self, plaintext):
        nonce = int.to_bytes(self.symmetric_nonce, 12, 'little')
        self.symmetric_nonce += 1
        aead = self.aead(self.symmetric_key)
        ciphertext = aead.encrypt(nonce, plaintext, self.h)
        self.mix_hash(ciphertext)
        return ciphertext

    def decrypt_and_hash(self, ciphertext):
        nonce = int.to_bytes(self.symmetric_nonce, 12, 'little')
        self.symmetric_nonce += 1
        aead = self.aead(self.symmetric_key)
        try:
            plaintext = aead.decrypt(nonce, ciphertext, self.h)
            self.mix_hash(ciphertext)
            return plaintext
        except Exception:
            return None

    def handshake_hash(self):
        return self.h

    def mix_hash_point(self, point):
        x962 = point.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
        self.mix_hash(x962)
        #print("mix_hash_point")

    def traffic_keys(self):
        return self.hkdf2(self.chaining_key, b'')

    def initialize_key(self, key):
        self.symmetric_key = key
        self.symmetric_nonce = 0

    def split(self):
        sending_key, receiving_key = self.traffic_keys()
        return sending_key, receiving_key


