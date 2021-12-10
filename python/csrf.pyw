import requests
from urllib.parse import unquote
import method
import time
import json
from sys import argv

# プロキシ設定
proxies = {"http":"http://127.0.0.1:8888"}

# POSTの場合
def POST_request(request_list):
    #url設定
    url = method.url(request_list[0])

    #headerを設定
    headers = method.headers(request_list)

    # cookies設定
    cookies = method.cookies(request_list[11])

    # request_bodyの設定
    request_body = method.request_body(request_list[12])
    body_list = request_body[0]
    payload = request_body[1]

    #requestbodyが診断できる値か判定
    if(len(body_list)%2!=0):
        return

    # ContentTypeがjsonの場合、型を変更する
    if(request_list[6]=='application/json'):
        payload = json.dumps(payload)

    # 正規のrequest送信
    try:
        if(cookies!={}):
            # cookie有
            response = requests.post(url,payload,headers=headers,cookies=cookies,proxies=proxies)
        else:
            # cookie無
            response = requests.post(url,payload,headers=headers,proxies=proxies)
    except Exception:
        return
    time.sleep(1)

    # 診断開始

    # headersからRefererを削除
    headers.pop('Referer')

    # cookieを含めないでrequest送信
    try:
        response1 = requests.post(url,payload,headers=headers,proxies=proxies)
    except Exception:
        return
    time.sleep(1)

    # ContentTypeがjsonの場合、型を変更する
    if(request_list[6]=='application/json'):
        payload = json.loads(payload)

    # 正規の通信とレスポンスのurlが同じ場合、脆弱性ありと判定
    if(response1.url == response.url):
        # logファイルからrequestheader取得
        f = open(r"C:\VulnDiag\nginx\nginx-1.20.1\logs\http.log", 'r+', encoding='UTF-8')
        log = f.readlines()
        f.truncate(0)
        f.close

        # logファイルのリストを降順にする
        log.reverse()

        # logを降順で読み込む
        for line in log:
            # lineの改行コード削除
            onelog = line.strip()

            # log_listを作成
            log_list = onelog.split('%log%')

            #HTTPメソッドの確認
            if("POST" not in log_list[0]):
                continue

            # log_payloadの設定
            request_body = method.request_body(log_list[12])
            log_payload = request_body[1]

            # 対象logか判定
            if(request_list[0]==log_list[0] and payload==log_payload):
                break

        # report書き込み準備
        response_list = dict(response1.headers)
        name = "CSRF（トークン等を削除しても特定副作用が実行される）"
        explanation = "発生しうる脅威：不正な送金、利用者が意図しない商品購入・退会処理、各種設定の不正な変更等\n解決法：IPA 安全なウェブサイトの作り方{https://www.ipa.go.jp/files/000017316.pdf}[6-(ⅰ)-a][6-(ⅰ)b][6-(ⅰ)-c]"

        # レポート出力
        method.report(url,'-',list(log_list),response_list,str(log_list[14]),response1.text,name,explanation)


# GETの関数
def GET_request(request_list):
    #url設定
    url = method.url(request_list[0])

    #headerを設定
    headers = method.headers(request_list)

    # cookies設定
    cookies = method.cookies(request_list[11])

    # 正規のrequest送信
    try:
        if(cookies!={}):
            # cookie有
            response = requests.get(url,headers=headers,cookies=cookies,proxies=proxies)
        else:
            # cookie無
            response = requests.get(url,headers=headers,proxies=proxies)
    except Exception:
        return
    time.sleep(1)

    # 診断開始

    # headersからRefererを削除
    headers.pop('Referer')

    # cookieを含めないでrequest送信
    try:
        response1 = requests.get(url,headers=headers,proxies=proxies)
    except Exception:
        return
    time.sleep(1)

    # 正規の通信とレスポンスのurlが同じ場合、脆弱性ありと判定
    if(response1.url == response.url):
        # logファイルからrequestheader取得
        f = open(r"C:\VulnDiag\nginx\nginx-1.20.1\logs\http.log", 'r+', encoding='UTF-8')
        log = f.readlines()
        f.truncate(0)
        f.close

        # logファイルのリストを降順にする
        log.reverse()

        # logを降順で読み込む
        for line in log:
            # lineの改行コード削除
            onelog = line.strip()

            # log_listを作成
            log_list = onelog.split('%log%')

            # 対象logか判定
            if(request_list[0]==log_list[0]):
                break

        # report書き込み準備
        response_list = dict(response1.headers)
        name = "CSRF（トークン等を削除しても特定副作用が実行される）"
        explanation = "発生しうる脅威：不正な送金、利用者が意図しない商品購入・退会処理、各種設定の不正な変更等\n解決法：IPA 安全なウェブサイトの作り方{https://www.ipa.go.jp/files/000017316.pdf}[6-(ⅰ)-a][6-(ⅰ)b][6-(ⅰ)-c]"

        # レポート出力
        method.report(url,'-',list(log_list),response_list,str(log_list[14]),response1.text,name,explanation)


# メイン
def main():
    # ユーザが選択した値を受け取る
    org_request = argv[1]
    str1 = org_request.replace("None","\'None\'")
    str2 = str1.replace("None\')","None")
    str3 = str2.replace("(\'","")
    str4 = str3.replace("\')","")
    request_list = str4.split("\', \'")

    if("POST" in request_list[0]):
        POST_request(request_list)
    else:
        GET_request(request_list)

if __name__ == "__main__":
    main()