import sys
import qr
import ble_advertise
import websocket_tunnel
import qrcode
import urllib.parse
import xml.etree.ElementTree as ET
from http.server import HTTPServer, SimpleHTTPRequestHandler

class RequestHandler(SimpleHTTPRequestHandler, object):
    def print_info(self):
        self.log_message("%s %s\n%s", self.command, self.path, self.headers)

    def do_GET(self):
        print(self.path)

        if "xml" in self.path:
            with open(self.path[1:], "r") as plain_file:
                data = plain_file.read()
                if "QR.xml" in self.path:
                    qr_contents, qr_secret, identity_key = qr.show_qr_code()
                    data = data.replace("XXX", qr_contents)
                data = data.encode()
        else:
            with open(self.path[1:], "rb") as file:
                data = file.read()

        self.send_response(200)
        self.send_header("Content-length", len(data))
        self.end_headers()

        self.wfile.write(data)

       # if "QR.xml" in self.path:
           # advert_txt = ble_advertise.advertise(qr_secret)
           # websocket_tunnel.connect(identity_key, qr_secret, advert_txt)

    def do_POST(self):
        enc = sys.getfilesystemencoding()
        length = self.headers.get('content-length')
        nbytes = int(length)
        rawPostData = self.rfile.read(nbytes)
        decodedPostData = rawPostData.decode(enc)
        if "KeyValueData" in decodedPostData:
            body = decodedPostData.replace('\r\n', '')
            idx = body.find("<")
            body = body[idx:]
            idx = body.rfind(">")
            body = body[:idx+1]

            print(body)

            root = ET.fromstring(body)
            key = root.find("UserInput").find("UserInputValues").find("KeyValueData").find("Value")
            print(key.text)

        self.do_GET()

httpd = HTTPServer(("", 80), RequestHandler)
httpd.serve_forever()

