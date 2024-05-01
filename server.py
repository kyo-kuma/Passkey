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
import lib.dns
import threading
import json

dl_url = ""
is_error = False

ip = ""
password = "5VXUsWAa"
job_dict = {
#        "IMAGE.jpg": "http://10.150.1.26/contents/IMAGE.jpg", 
#        "Test2.pdf": "http://10.150.1.26/contents/Test2.pdf", 
#        "3.pdf": "http://3.pdf",
        }
item_placeholder = "%%ITEMS%%"
item_base = '''
<Item selected="false" value="%%VALUE%%">
 <Label>%%LABEL%%</Label>
</Item>
''' + item_placeholder

class RequestHandler(SimpleHTTPRequestHandler, object):
    def do_GET(self):
        global is_error
        global ip
        if "?" in self.path:
            parsed = urlparse(self.path)
            params = parse_qs(parsed.query)
            idx = parsed.query.find("=")
            ip = parsed.query[idx+1:]
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
            thread_token = threading.Thread(target=get_phoenix_token, args=(ip, password, token_list))
            thread_token.start()

            try:
                # BLE advertise 開始
                advert_txt = ble_advertise.advertise(qr_secret)
                thread_token.join()
                token = token_list[0]
                thread = threading.Thread(target=lib.phoenix_push_button.up, args=(ip, password, token))
                thread.start()
                if advert_txt is not None:
                    # Websocketトンネリング開始
                    response, username = websocket_tunnel.connect(identity_key, qr_secret, advert_txt)
                    if response == "":
                        is_error = True
                        return
                    # JobList取得
                    token, username = get_username_token(response)
                    print(username)
                    print(token)
                    get_job_list(username, token)
                else:
                    is_error = True
                print("complete!!!!!!!!!!!!!")
            except:
                is_error = True
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

def get_phoenix_token(ip, password, token):
    token[0] = lib.phoenix_push_button.get_token(ip, password)
    lib.phoenix_push_button.down(ip, password, token[0])

def get_job_list(username, token):
    #url='https://apbil2022000.ap.brothergroup.net:3443/print/jobs?username=' + username
    url='https://apbil1236762:3443/print/jobs?username=' + username
    headers = {
        'Authorization': 'Bearer '+token,
    }
    print("url:")
    print(url)
    print("headers:")
    print(headers)
    try:
        # 証明書検証をオフにしてリクエストを送信
        session = requests.Session()
        session.proxies = {
#          'https': '10.150.1.211:10090',
#          'http': '10.150.1.211:10090',
        }
        response = session.get(url, headers=headers, verify=False)
        
        # レスポンスを確認
        if response.status_code == 200:
            print("Success!")
            response_json = json.loads(response.text)
            print(response_json)
            if response_json["job_info"]["jobs"] is not None:
                for job in response_json["job_info"]["jobs"]:
                    print(job)
                    job_dict[job["job_name"]] = urllib.parse.quote(job["job_url"], safe=':/')

            print(job_dict)
            return
    except requests.exceptions.RequestException as e:
        print("Request failed:", e)

def get_username_token(response):
    response_json = json.loads(response)
    username = ""
    if "username"  in response_json:
        username = response_json["username"]
    if "token"  in response_json:
        token = response_json["token"]
    return token, username

thread_dns = threading.Thread(target=lib.dns.start)
thread_dns.start()

httpd = HTTPServer(("", 80), RequestHandler)
httpd.serve_forever()

#ip = '10.150.1.27'
#password = '5VXUsWAa'
#token = lib.phoenix_push_button.get_token(ip, password)
#print(token)
#lib.phoenix_push_button.down(ip, password, token)
#lib.phoenix_push_button.up(ip, password, token)




 

