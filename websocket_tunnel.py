import hashlib
import base64
import websocket
import ssl
import json
import cbor2
import hmac
import requests

from typing import Tuple
from noise_lib import Noise
from struct import pack

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from urllib3.exceptions import InsecureRequestWarning

identity_key = None

assigned_tunnel_server_domains = ["cable.ua5v.com", "cable.auth.com"]
tunnel_server_domain = ""
subprotocol = "fido.cable"

def load_identity_key_and_qr_secret_and_advert_plaintxt(identity_key_path, qr_secret_path, advert_plaintxt_path):
    with open(identity_key_path, "rb") as key_file:
        identity_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=None
        )

    with open(qr_secret_path, "rb") as secret_file:
        qr_secret = secret_file.read()

    with open(advert_plaintxt_path, "r") as plain_file:
        advert_plaintxt = plain_file.read()

    return identity_key, qr_secret, advert_plaintxt

class KeyPurpose:
    EID_KEY = 1
    TUNNEL_ID = 2
    PSK = 3

def reserved_bits_are_zero(plaintext):
    return plaintext[0] == 0

def unpack_decrypted_advert(plaintext):
    print(f"plaintext = {plaintext.hex()}")
    nonce = plaintext[1:11]
    print(f"nonce = {nonce.hex()}")
    routing_id = plaintext[11:14]
    print(f"routing_id = {routing_id.hex()}")
    encoded_tunnel_server_domain = plaintext[14] | (plaintext[15] << 8)
    return nonce, routing_id, encoded_tunnel_server_domain


def decode_tunnel_server_domain(encoded: int) -> Tuple[str, bool]:
    if encoded < 256:
        if encoded >= len(assigned_tunnel_server_domains):
            return "", False
        return assigned_tunnel_server_domains[encoded], True

    sha_input = bytearray([
        0x63, 0x61, 0x42, 0x4c, 0x45, 0x76, 0x32, 0x20,
        0x74, 0x75, 0x6e, 0x6e, 0x65, 0x6c, 0x20, 0x73,
        0x65, 0x72, 0x76, 0x65, 0x72, 0x20, 0x64, 0x6f,
        0x6d, 0x61, 0x69, 0x6e,
    ])
    sha_input += bytearray([encoded & 0xFF, (encoded >> 8) & 0xFF, 0])
    digest = hashlib.sha256(sha_input).digest()

    v = int.from_bytes(digest[:8], 'little')
    tld_index = v & 3
    v >>= 2

    ret = "cable."
    base32_chars = "abcdefghijklmnopqrstuvwxyz234567"
    while v != 0:
        ret += base32_chars[v & 31]
        v >>= 5

    tlds = [".com", ".org", ".net", ".info"]
    ret += tlds[tld_index]

    return ret, True

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

def connect_to_phone(advert_plaintext, qr_secret):
    global tunnel_server_domain
    nonce, routing_id, encoded_tunnel_server_domain = unpack_decrypted_advert(advert_plaintext)

    tunnel_server_domain, ok = decode_tunnel_server_domain(encoded_tunnel_server_domain)
    if not ok:
        raise Exception("unknown tunnel server domain")

    tunnel_id = bytearray(16)
    derive(tunnel_id, qr_secret, None, KeyPurpose.TUNNEL_ID)

    connect_url = "wss://" + tunnel_server_domain + "/cable/connect/" + routing_id.hex() + "/" + tunnel_id.hex()
    print(f"connect_url = {connect_url}")

    ws = websocket.WebSocket()
    ws.connect(connect_url, subprotocols=[subprotocol], sslopt={"cert_reqs": ssl.CERT_NONE})

    if ws.subprotocol != subprotocol:
        raise Exception("tunnel service picked wrong subprotocol")

    do_qr_handshake(ws, advert_plaintext, qr_secret)

    return ws

def do_qr_handshake(websocket_conn, advert_plaintext, qr_secret):
    psk = bytearray(32)
    derive(psk, qr_secret, advert_plaintext, KeyPurpose.PSK)
    conn, handshake_hash = do_handshake(websocket_conn, psk, identity_key, None)
    read_post_handshake_message(conn, handshake_hash)


def do_handshake(websocket_conn, psk, identity_key, peer_identity=None):
    msg, ephemeral_key, noise_state = initial_handshake_message(psk, identity_key, peer_identity)
    
    # メッセージをWebSocketを通じて送信
    websocket_conn.send_binary(msg)

    # WebSocketからバイナリメッセージを受信
    handshake_message_from_phone = websocket_conn.recv()

    # バイナリメッセージでなければエラー
    if not isinstance(handshake_message_from_phone, bytes):
        raise ValueError("Non-binary message received on WebSocket")

    # ハンドシェイクの応答を処理
    sending_key, receiving_key, handshake_hash = process_handshake_response(
        handshake_message_from_phone, ephemeral_key, identity_key, noise_state)

    # 暗号化された接続を作成
    conn = CableConn(websocket_conn, sending_key, receiving_key)

    return conn, handshake_hash


# initial_handshake_message.py
P256_X962_LENGTH = 1 + 32 + 32

def ecdh(local_private_key, peer_public_key):
    return local_private_key.exchange(ec.ECDH(), peer_public_key)

def initial_handshake_message(psk, priv=None, peer_pub=None):
    if (priv is None) == (peer_pub is None):
        raise ValueError("Exactly one of priv and peer_pub must be given")

    ns = Noise()
    if peer_pub is not None:
        print("NKpsk0")
        ns.init("NKpsk0")
        ns.mix_hash(b"\x00")
        ns.mix_hash_point(peer_pub)
    else:
        print("KNpsk0")
        ns.init("KNpsk0")
        ns.mix_hash(b"\x01")
        ns.mix_hash_point(priv.public_key())

    ns.mix_key_and_hash(psk)

    ephemeral_key = ec.generate_private_key(ec.SECP256R1())
    ephemeral_key_bytes = ephemeral_key.public_key().public_bytes(
        Encoding.X962, PublicFormat.UncompressedPoint
    )
    ns.mix_hash(ephemeral_key_bytes)
    ns.mix_key(ephemeral_key_bytes)

    if peer_pub is not None:
        shared_key = ecdh(ephemeral_key, peer_pub)
        ns.mix_key(shared_key)

    msg = ephemeral_key_bytes + ns.encrypt_and_hash(b"")

    return msg, ephemeral_key, ns

# process_handshake_response.py
def process_handshake_response(peer_handshake_message, ephemeral_key, priv, ns):
    if len(peer_handshake_message) < P256_X962_LENGTH:
        raise ValueError("Handshake message too short")

    peer_point_bytes = peer_handshake_message[:P256_X962_LENGTH]
    ciphertext = peer_handshake_message[P256_X962_LENGTH:]

    ns.mix_hash(peer_point_bytes)
    ns.mix_key(peer_point_bytes)

    peer_public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), peer_point_bytes)
    shared_key = ecdh(ephemeral_key, peer_public_key)
    ns.mix_key(shared_key)

    if priv is not None:
        shared_key = ecdh(priv, peer_public_key)
        ns.mix_key(shared_key)

    plaintext = ns.decrypt_and_hash(ciphertext)
    if plaintext is None or len(plaintext) != 0:
        raise ValueError("Bad handshake")

    sending_key, receiving_key = ns.split()

    return sending_key, receiving_key, ns.handshake_hash()

class CableConn:
    def __init__(self, conn, read_key, write_key):
        self.conn = conn
        self.read_key = read_key
        self.write_key = write_key
        self.read_seq = 0
        self.write_seq = 0

additional_data = None

def setup_aead(counter, key):
    if counter > (1 << 24):
        raise ValueError("too many messages")

    nonce = bytearray(12)
    nonce[8:] = pack('>I', counter)

    aead = AESGCM(key)
    return nonce, aead

class CableConn:
    def __init__(self, conn, write_key, read_key):
        self.conn = conn
        self.read_key = read_key
        self.write_key = write_key
        self.read_seq = 0
        self.write_seq = 0

    def write(self, msg):
        padding_granularity = 32
        if len(msg) > (1 << 20):
            raise ValueError("plaintext too large")

        extra_bytes = padding_granularity - (len(msg) % padding_granularity)
        padded_msg = msg.ljust(len(msg) + extra_bytes, b'\x00')
        padded_msg = bytearray(padded_msg)
        padded_msg[-1] = extra_bytes - 1
        padded_msg = bytes(padded_msg)

        nonce, aead = setup_aead(self.write_seq, self.write_key)
        self.write_seq += 1
        ciphertext = aead.encrypt(nonce, padded_msg, additional_data)
        self.conn.send_binary(ciphertext)
        return len(msg)

    def read(self):
        ciphertext = self.conn.recv()
        nonce, aead = setup_aead(self.read_seq, self.read_key)
        self.read_seq += 1
        plaintext = aead.decrypt(nonce, ciphertext, additional_data)

        if not plaintext:
            raise ValueError("invalid message")

        padding_bytes = plaintext[-1]
        if padding_bytes + 1 > len(plaintext):
            raise ValueError("invalid message")

        plaintext = plaintext[:-1 - padding_bytes]
        return bytes(plaintext)


def read_post_handshake_message(conn, handshake_hash):
    msg_bytes = conn.read()
    if not msg_bytes:
        raise Exception("Read failure")

    msg = cbor2.loads(msg_bytes)

    send_ctap2_request(conn, handshake_hash)


def parse_update_message(payload, handshake_hash):
    msg = cbor2.loads(payload)
    # Linking data is optional.
    if 1 not in msg:
        return

    linking_data = msg[1]
    initial_link_data = {
        'contact_id': linking_data[1],
        'link_id': linking_data[2],
        'link_secret': linking_data[3],
        'authenticator_public_key': linking_data[4],
        'authenticator_name': linking_data[5],
        'signature': linking_data[6],
    }
    print("initial_link_data")
    print(initial_link_data)

    pub_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), initial_link_data['authenticator_public_key'])

    if not verify_signature(initial_link_data['signature'], handshake_hash, pub_key):
        raise Exception("Invalid link signature")

    initial_link_data['tunnel_server_domain'] = tunnel_server_domain
    initial_link_data['auth_public_key'] = pub_key


def verify_signature(sig, handshake_hash, pub_key):
    shared_key = ecdh(identity_key, pub_key)
    h = hmac.new(shared_key, handshake_hash, hashlib.sha256)
    expected_signature = h.digest()
    return hmac.compare_digest(expected_signature, sig)

TYPE_SHUTDOWN = 0
TYPE_CTAP = 1
TYPE_UPDATE = 2

def send_ctap2_request(conn, handshake_hash):
    authenticator_get_info_request = bytes([TYPE_CTAP, 4])
    options, client_data_json, session = get_authentication_options()
    body = bytes([TYPE_CTAP])+options
    try:
        conn.write(body)
    except OSError:
        raise Exception("write failed")

    while True:
        reply = conn.read()
        if not reply:
            print("WebSocket closed")
            return

        if len(reply) == 0:
            raise Exception("invalid empty message received")

        msg_type = reply[0]
        reply = reply[1:]

        if msg_type == TYPE_SHUTDOWN:
            raise Exception("shutdown message received from authenticator")

        elif msg_type == TYPE_CTAP:
            print("CTAP reply:", reply.hex())
            response = decode_data(reply.hex(), client_data_json)
            if response is not None:
                send_authentication_results(response, session)
                break
            try:
                conn.write(bytes([TYPE_SHUTDOWN]))
            except OSError:
                raise Exception("write failed")

        elif msg_type == TYPE_UPDATE:
            print("CTAP Update!!!") 
            #parse_update_message(reply, handshake_hash)

        else:
            raise Exception("invalid message type received")


def get_authentication_options():
    requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

    initial_url = 'https://webauthn.io/'
    post_url = 'https://webauthn.io/authentication/options'
    post_data = {"username": "", "user_verification": "preferred"}

    session = requests.Session()
    response = session.get(initial_url, verify=False)  # 証明書検証を無視 

    headers = {'Content-Type': 'application/json'}
    response_post = session.post(post_url, json=post_data, headers=headers, verify=False)  # 証明書検証を無視

    print("HTTP Status:", response_post.status_code)
    print("Response Body:", response_post.text)

    options, client_data_json = webauthn_options_to_cbor(response_post.text)
    return options, client_data_json, session

def send_authentication_results(datajson, session):
    requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

    post_url = "https://webauthn.io/authentication/verification"
    post_data = datajson
    print(datajson)

    headers = {'Content-Type': 'application/json'}
    response_post = session.post(post_url, json=post_data, headers=headers, verify=False)  # 証明書検証を無視

    cookies = session.cookies
    print("HTTP Status:", response_post.status_code)
    print("Response Body:", response_post.text)

    return

def webauthn_options_to_cbor(options_response):
    # options_responseを辞書に変換する
    options = json.loads(options_response)
    client_data = {
        'type': 'webauthn.get',
        'challenge': options['challenge'],
        'origin': "https://"+options['rpId'],
        'crossOrigin': False
    }
    client_data_json = json.dumps(client_data)
    client_data_hash = hashlib.sha256(client_data_json.encode()).hexdigest()
    
    # WebAuthnのパラメータを取得
    rp = options['rpId']
    allow_credential = options['allowCredentials']
    uv = '{"uv": true}'
    
    # CTAP2 authenticatorMakeCredentialに必要なパラメータを構築
    cbor_params = {
        1: rp,               # Relying Party Identifier (RP ID)
        2: bytes.fromhex(client_data_hash),             # User ID
        5: json.loads(uv),   # User Name
    }
    
    return bytes([2])+(cbor2.dumps(cbor_params)), client_data_json

def decode_data(cbor, client_data_json):
    msg = cbor2.loads(bytes.fromhex(cbor[2:]))

    response_data = {
        'username': '',
        'response': {
            'id': base64.b64encode(msg[1]['id']).decode().replace('=', '').replace('/', '_'),
            'rawId': base64.b64encode(msg[1]['id']).decode().replace('=', '').replace('/', '_'),
            'response': {
                "authenticatorData": base64.b64encode(msg[2]).decode().replace('=', ''),
                "clientDataJSON": base64.b64encode(client_data_json.encode()).decode().replace('=', ''),
                "signature": base64.b64encode(msg[3]).decode().replace('=', ''),
                "userHandle": "bW9yaWtoMw"
            },
            "type": "public-key",
            "clientExtensionResults": {},
            "authenticatorAttachment": "cross-platform"
        }
    }
    response_json = json.dumps(response_data)
    return response_data

def connect(_identity_key, qr_secret, advert_plaintxt):
    global identity_key
    identity_key = _identity_key
    connect_to_phone(bytes.fromhex(advert_plaintxt), qr_secret)
    return

#identity_key, qr_secret, advert_plaintxt = load_identity_key_and_qr_secret_and_advert_plaintxt("identity_key.pem", "qr_secret.bin", "advert_plaintxt.txt")
#peer_public_key = None
#
#connect_to_phone(bytes.fromhex(advert_plaintxt))


