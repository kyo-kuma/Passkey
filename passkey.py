import qr
import ble_advertise
import websocket_tunnel
import qrcode


def main():
    qr_contents, qr_secret, identity_key = qr.show_qr_code()
    #img = qrcode.make(qr_contents)
    #img.show()
    advert_txt = ble_advertise.advertise(qr_secret)
    if advert_txt is None:
        print("advert error")
        return
    websocket_tunnel.connect(identity_key, qr_secret, advert_txt)



if __name__ == "__main__":
    main()
