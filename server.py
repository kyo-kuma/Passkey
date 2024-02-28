import qr
import ble_advertise
import websocket_tunnel
import qrcode
from http.server import HTTPServer, SimpleHTTPRequestHandler

class RequestHandler(SimpleHTTPRequestHandler, object):
    def print_info(self):
        self.log_message("%s %s\n%s", self.command, self.path, self.headers)

    def do_GET(self):
        print(self.path)
        with open(self.path[1:], "r") as plain_file:
            xml_txt = plain_file.read()
            if "QR.xml" in self.path:
                qr_contents, qr_secret, identity_key = qr.show_qr_code()
                xml_txt = xml_txt.replace("XXX", qr_contents)

        xml_binary = xml_txt.encode()

        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.send_header("Content-length", len(xml_binary))
        self.end_headers()

        self.wfile.write(xml_binary)

        if "QR.xml" in self.path:
            advert_txt = ble_advertise.advertise(qr_secret)
            websocket_tunnel.connect(identity_key, qr_secret, advert_txt)

    def do_POST(self):
        self.do_GET()

httpd = HTTPServer(("", 80), RequestHandler)
httpd.serve_forever()

