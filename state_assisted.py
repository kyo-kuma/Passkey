import base64
import os
import ssl
import websocket
import cbor2
from cbor2 import dumps
import binascii
import ble_advertise
from cryptography.hazmat.primitives.asymmetric import ec
import websocket_tunnel


subprotocol = "fido.cable" 
class KeyPurpose:
    EID_KEY = 1
    TUNNEL_ID = 2
    PSK = 3

def perform_state_assisted_connection(link_data):
    contact_url = "wss://" + link_data['tunnelServerDomain'] + \
                  "/cable/contact/" + \
                  base64.urlsafe_b64encode(link_data['ContactId']).decode('utf-8').replace('=', '')

    print(contact_url)
    client_nonce, client_payload = construct_client_payload(link_data)
    headers = {"X-caBLE-Client-Payload": binascii.hexlify(client_payload).decode('utf-8')}

    ws = websocket.WebSocket()
    ws.connect(contact_url, subprotocols=[subprotocol], sslopt={"cert_reqs": ssl.CERT_NONE}, header=headers) 

    if ws.subprotocol != subprotocol:
        raise Exception("tunnel service picked wrong subprotocol")
    
    eid_key = bytearray(32 + 32)
    ble_advertise.derive(eid_key, link_data['LinkSecret'], client_nonce, KeyPurpose.EID_KEY)

    print("waiting for advert")
    advert_plaintext = ble_advertise.await_advert(eid_key)
    print("have advert")
    if not ble_advertise.reserved_bits_are_zero(advert_plaintext):
        raise Exception("bad link advert")

    psk = bytearray(32)
    websocket_tunnel.derive(psk, link_data['LinkSecret'], advert_plaintext, KeyPurpose.PSK)

    conn, handshake_hash = websocket_tunnel.do_handshake(ws, psk, None, link_data['authPublicKey'])
    websocket_tunnel.read_post_handshake_message(conn, handshake_hash)
    print("State-assisted connection complete")

def construct_client_payload(link_data):
    nonce = os.urandom(16)

    payload = dumps({
        1: link_data['LinkId'],
        2: nonce,
        3: "ga"
    })

    return nonce, payload

with open("tmp/" + "linkdata.bin", "rb") as plain_file:
    cbor_data = plain_file.read()

with open("tmp/" + "tunnel_server_domain.txt", "r") as plain_file:
    tunnel_server_domain = plain_file.read()

msg = cbor2.loads(cbor_data)
linking_data = msg[1]
pub_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), linking_data[4])
link_data = {
    'tunnelServerDomain': tunnel_server_domain,
    'ContactId': linking_data[1],
    'LinkId': linking_data[2],
    'LinkSecret': linking_data[3],
    'authPublicKey': pub_key
}
print(link_data)
print(base64.urlsafe_b64encode(link_data['ContactId']).decode('utf-8'))


perform_state_assisted_connection(link_data)

