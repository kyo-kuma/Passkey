import os
import time
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
import cbor2
import struct

def generate_key_pair():
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    return private_key

def compress_ec_key(public_key):
    # This function should compress the EC public key, but since the
    # original code doesn't provide the implementation, here's a placeholder.
    # Replace this with actual compression logic as required.
    return public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.CompressedPoint
    )

def cbor_encode_int64(value):
    # This function should CBOR-encode an integer, but since the
    # original code doesn't provide the implementation, here's a placeholder.
    # Replace this with actual CBOR encoding logic as required.
    return cbor2.dumps(value)

def digit_encode(d):
    chunk_size = 7
    chunk_digits = 17
    zeros = "00000000000000000"
    ret = ""
    
    while len(d) >= chunk_size:
        chunk = d[:chunk_size] + b'\x00'  # Add zero byte to make it 8 bytes for unpacking
        v = struct.unpack('<Q', chunk)[0]  # Unpack as little-endian unsigned long long (64 bits)
        v_str = str(v)
        ret += zeros[:chunk_digits - len(v_str)]
        ret += v_str
        d = d[chunk_size:]
    
    if len(d) != 0:
        # partialChunkDigits is the number of digits needed to encode
        # each length of trailing data from 6 bytes down to zero. I.e.
        # 15, 13, 10, 8, 5, 3, 0 written in hex.
        partial_chunk_digits = 0x0fda8530
        digits = 15 & (partial_chunk_digits >> (4 * len(d)))
        chunk = d + b'\x00' * (8 - len(d))  # Pad with zero bytes to make it 8 bytes
        v = struct.unpack('<Q', chunk)[0]
        v_str = str(v)
        ret += zeros[:digits - len(v_str)]
        ret += v_str
    
    return ret

def save_identity_key_and_qr_secret(identity_key, qr_secret, identity_key_path, qr_secret_path):
    # 秘密鍵をPEM形式で保存
    os.makedirs("tmp", exist_ok=True)
    with open("tmp/" + identity_key_path, "wb") as key_file:
        key_file.write(identity_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open("tmp/" + 'public_key.pem', 'wb') as pem_out:
        # 公開鍵を取得
        public_key = identity_key.public_key()
        # 公開鍵をPEM形式でエンコード
        pem_public_key = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        # ファイルに公開鍵を書き込む
        pem_out.write(pem_public_key)

    # QRシークレットをバイナリで保存
    with open("tmp/" + qr_secret_path, "wb") as secret_file:
        secret_file.write(qr_secret)

def encode_qr_contents(compressed_public_key, qr_secret):
    num_map_elements = 6
    rand_byte = os.urandom(1)
    extra_key = ord(rand_byte) & 3 == 0
    if extra_key:
        num_map_elements += 1

    cbor_data = cbor2.dumps({
        0: compressed_public_key,
        1: qr_secret,
        #2: len("assignedTunnelServerDomains"),  # Placeholder for actual value
        2: 2,  # Placeholder for actual value
        3: int(time.time()),
        4: True,
        #4: False,
        5: 'ga',
    })

    # Add the extra key if needed
    if extra_key:
        cbor_data += cbor2.dumps({65535: 0})

    print(cbor_data.hex())
    qr_encode = digit_encode(cbor_data)
    print("------")
    print(decode_digit(qr_encode).hex())
    qr_code = "FIDO:/" + digit_encode(cbor_data)
    print(qr_code)
    return qr_code

def decode_digit(encoded_str):
    chunk_size = 7
    chunk_digits = 17
    ret = b''

    def get_chunk_size(n):
        # Decode the length of the chunk based on the number of remaining digits
        partial_chunk_digits = 0x0fda8530
        return 15 & (partial_chunk_digits >> (4 * n))

    # Calculate how many full chunks there are
    full_chunks = len(encoded_str) // chunk_digits

    # Process full chunks
    for i in range(full_chunks):
        start_index = i * chunk_digits
        end_index = start_index + chunk_digits
        chunk_str = encoded_str[start_index:end_index]
        v = int(chunk_str)
        chunk_data = struct.pack('<Q', v)[:chunk_size]
        ret += chunk_data

    # Process the remaining digits, if any
    remaining_digits = len(encoded_str) % chunk_digits
    if remaining_digits > 0:
        remaining_str = encoded_str[-remaining_digits:]
        remaining_size = get_chunk_size(remaining_digits // 3)
        v = int(remaining_str)
        chunk_data = struct.pack('<Q', v)[:remaining_size]
        ret += chunk_data

    return ret.rstrip(b'\x00')

def show_qr_code():
    qr_secret = os.urandom(16)
    identity_key = generate_key_pair()
    compressed_public_key = compress_ec_key(identity_key.public_key())
    save_identity_key_and_qr_secret(identity_key, qr_secret, "identity_key.pem", "qr_secret.bin")

    qr_contents = encode_qr_contents(compressed_public_key, qr_secret)
    # Replace the following line with a call to an actual QR code printing function.
    print(qr_contents)
    return qr_contents, qr_secret, identity_key


# Example usage:
#show_qr_code()


