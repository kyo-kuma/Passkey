import sys
import json
import base64
import requests
from requests.auth import HTTPDigestAuth

#args = sys.argv
#ipstring = args[1]
#password = args[2]

# リクエストするURLとパラメータ

# Digest認証のユーザー名とパスワード
username = 'admin'
#password = 'initpass'

def get_token(ip, password):
    token_url='https://'+ip+'/phoenix/approval/token?application=remotepanel'
    # POSTリクエストの送信
    try:
        # 証明書検証をオフにしてリクエストを送信
        response = requests.post(token_url, data=None, auth=HTTPDigestAuth(username, password), verify=False)
        
        # レスポンスを確認
        if response.status_code == 200:
            print("Success!")
            response_json = json.loads(response.text)
            token = response_json["approval_token"]
            print(token)
            return token
    except requests.exceptions.RequestException as e:
        print("Request failed:", e)

def down(ip, password, token):
    down_url='https://'+ip+'/phoenix/approval/remote_panel?lcd_x=725&lcd_y=441&direction=down'
    # POSTリクエストの送信
    headers = {
        'X-Mfp-Approval-Token': token,
    }
    try:
        # 証明書検証をオフにしてリクエストを送信
        response = requests.post(down_url, headers=headers, data=None, auth=HTTPDigestAuth(username, password), verify=False)
        
        # レスポンスを確認
        if response.status_code == 200:
            print("Success!")
    except requests.exceptions.RequestException as e:
        print("Request failed:", e)

def up(ip, password, token):
    up_url='https://'+ip+'/phoenix/approval/remote_panel?lcd_x=725&lcd_y=441&direction=up'
    # POSTリクエストの送信
    headers = {
        'X-Mfp-Approval-Token': token,
    }
    try:
        # 証明書検証をオフにしてリクエストを送信
        response = requests.post(up_url, headers=headers, data=None, auth=HTTPDigestAuth(username, password), verify=False)
        
        # レスポンスを確認
        if response.status_code == 200:
            print("Success!")
    except requests.exceptions.RequestException as e:
        print("Request failed:", e)

def down_and_up(ip, password, token):
    down_url='https://'+ip+'/phoenix/approval/remote_panel?lcd_x=725&lcd_y=441&direction=down'
    up_url='https://'+ip+'/phoenix/approval/remote_panel?lcd_x=725&lcd_y=441&direction=up'
    # POSTリクエストの送信
    headers = {
        'X-Mfp-Approval-Token': token,
    }
    try:
        # 証明書検証をオフにしてリクエストを送信
        response = requests.post(down_url, headers=headers, data=None, auth=HTTPDigestAuth(username, password), verify=False)
        response = requests.post(up_url, headers=headers, data=None, auth=HTTPDigestAuth(username, password), verify=False)
        
        # レスポンスを確認
        if response.status_code == 200:
            print("Success!")
    except requests.exceptions.RequestException as e:
        print("Request failed:", e)

#token = get_token()
#down_and_up(token)

