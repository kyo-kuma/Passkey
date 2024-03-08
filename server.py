import sys
import qr
import ble_advertise
import websocket_tunnel
import qrcode
import urllib.parse
import xml.etree.ElementTree as ET
from http.server import HTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urlparse
from urllib.parse import parse_qs
import requests
import lib.phoenix_push_button
import threading

dl_url = ""
is_error = False

ip = ""
password = "5VXUsWAa"
job_dict = {
        "IMAGE.jpg": "http://10.150.1.26/contents/IMAGE.jpg", 
        "test.pdf": "http://10.150.1.148:10090/test.pdf", 
        "3.pdf": "http://3.pdf",
        }
item_placeholder = "%%ITEMS%%"
item_base = '''
<Item selected="false" value="%%VALUE%%">
 <Label>%%LABEL%%</Label>
</Item>
''' + item_placeholder

class RequestHandler(SimpleHTTPRequestHandler, object):
    def print_info(self):
        self.log_message("%s %s\n%s", self.command, self.path, self.headers)

    def do_GET(self):
        global is_error
        global ip
        if "?" in self.path:
            parsed = urlparse(self.path)
            params = parse_qs(parsed.query)
            idx = parsed.query.find("=")
            ip = parsed.query[idx+1:]
            print(ip)
            path = parsed.path
        else:
            path = self.path

        if is_error == True:
            is_error = False
            path = '/contents/error.xml'

        if "list.xml" in path:
            if(len(job_dict) == 0):
                path = '/contents/end.xml'

        if "xml" in path:
            with open(path[1:], "r") as plain_file:
                data = plain_file.read()
                if "QR.xml" in path:
                    qr_contents, qr_secret, identity_key = qr.show_qr_code()
                    data = data.replace("XXX", qr_contents)
                if "list.xml" in path:
                    for job_key, job_value in job_dict.items():
                        item = item_base.replace("%%VALUE%%", job_value).replace("%%LABEL%%", job_key)
                        data = data.replace(item_placeholder, item)
                    data = data.replace(item_placeholder, "")
                if "print.xml" in path:
                    data = data.replace("%%FILEPATH%%", dl_url)
                data = data.encode()

        else:
            with open(path[1:], "rb") as file:
                data = file.read()

        self.send_response(200)
        self.send_header("Content-length", len(data))
        self.end_headers()
        self.wfile.write(data)

        if "QR.xml" in path:
            token_list = [None] * 1
            thread_token = threading.Thread(target=get_token, args=(ip, password, token_list))
            thread_token.start()

            try:
                advert_txt = ble_advertise.advertise(qr_secret)
                thread_token.join()
                print("token!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
                token = token_list[0]
                print(token)
                thread = threading.Thread(target=lib.phoenix_push_button.up, args=(ip, password, token))
                thread.start()
                if advert_txt is not None:
                    result = websocket_tunnel.connect(identity_key, qr_secret, advert_txt)
                    if result == False:
                        is_error = True
                else:
                    is_error = True
                print("complete!!!!!!!!!!!!!")
            except:
                lib.phoenix_push_button.up(ip, password, token)

    def do_POST(self):
        enc = sys.getfilesystemencoding()
        length = self.headers.get('content-length')
        nbytes = int(length)
        rawPostData = self.rfile.read(nbytes)
        decodedPostData = rawPostData.decode(enc)
        print(decodedPostData)
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
            global dl_url
            dl_url = key.text
            for job_key, job_value in job_dict.items():
                if dl_url == job_value:
                    break
            job_dict.pop(job_key)

        self.do_GET()

def get_token(ip, password, token):
    token[0] = lib.phoenix_push_button.get_token(ip, password)
    lib.phoenix_push_button.down(ip, password, token[0])



httpd = HTTPServer(("", 80), RequestHandler)
httpd.serve_forever()

#ip = '10.150.1.27'
#password = '5VXUsWAa'
#token = lib.phoenix_push_button.get_token(ip, password)
#print(token)
#lib.phoenix_push_button.down(ip, password, token)
#lib.phoenix_push_button.up(ip, password, token)
