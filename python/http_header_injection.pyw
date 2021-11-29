import requests
import sqlite3
from urllib.parse import unquote
import method
from time import sleep
import json

# プロキシ設定
proxies = {"http":"http://127.0.0.1:8888"}

# 診断プログラム
def request(request_list):
    # url設定
    url = method.url(request_list[0])

    # header設定
    headers = method.headers(request_list)

    # cookies設定
    cookies = method.cookies(request_list[11])

    # 診断開始

    # getmethod改ざん
    defacing_url = url+"%0d%0aSet-Cookie:xxxtest%3Dxxxxtest%3B"

    # request送信
    if("POST" in request_list[0]):
        # request_bodyの設定
        request_body = method.request_body(request_list[12])
        body_list = request_body[0]
        payload = request_body[1]

        # ContentTypeがjsonの場合、型を変更する
        if(request_list[6]=='application/json'):
            payload = json.dumps(payload)

        try:
            if(cookies!={}):
                # cookie有
                response1 = requests.post(defacing_url,payload,headers=headers,cookies=cookies,proxies=proxies)
            else:
                # cookie無
                response1 = requests.post(defacing_url,payload,headers=headers,proxies=proxies)
        except Exception:
            return
        sleep(1)
        
    else:
        try:
            if(cookies!={}):
                #cookie有
                response1 = requests.get(defacing_url,headers=headers,cookies=cookies,proxies=proxies)
            else:
                #cookie無
                response1 = requests.get(defacing_url,headers=headers,proxies=proxies)
        except Exception:
            return
        sleep(1)

    # レスポンスヘッダに、xxxtest=xxxxtestが含まれていた場合、脆弱性ありと判定
    if("xxxtest=xxxxtest" in str(response1.headers)):
        # logファイルからrequestheader取得
        f = open(r"C:\VulnDiag\nginx\nginx-1.20.1\logs\http.log", 'r+', encoding='UTF-8')
        log = f.readlines()

        # logファイルのリストを降順にする
        log.reverse()

        # logを降順で読み込む
        for line in log:
            # lineから改行コードを取り除く
            onelog = line.strip()

            # log_listを作成
            log_list = onelog.split('%log%')

            # log_url設定
            log_url = method.url(log_list[0])

            # cookie_listの設定
            log_cookie_list = log_list[13].replace('; ','%cookie%').split('%cookie%')
            request_cookie_list = request_list[11].replace('; ','%cookie%').split('%cookie%')

            # 対象logか判定
            if(unquote(defacing_url)==unquote(log_url) and request_cookie_list.sort()==log_cookie_list.sort()):
                f.truncate(0)
                break

        # report書き込み準備
        response_list = dict(response1.headers)
        if(response1.history==[]):
            name = "HTTPヘッダー・インジェクション1"
        else:
            name = "HTTPヘッダー・インジェクション2"

        # レポート出力
        method.report(str(log_url),'-',list(log_list),response_list,str(log_list[14]),response1.text,name)


# メイン
def main():
    # データベース名を設定
    db_name = 'C:/VulnDiag/pg/db_http.db'

    # db_nameのデータベースがなければ作成してから接続する
    con = sqlite3.connect(db_name)

    # sqliteを操作するカーソルオブジェクトを作成
    cur = con.cursor()

    # scかredirectにフラグを持つデータを取り出す
    cur.execute('SELECT DISTINCT First_Row,Host,User_Agent,Accept,Accept_Language,Accept_Encoding,Content_Type,Origin,Connection,Referer,Upgrade_Insecure_Requests,Cookies,Request_Body FROM http WHERE redirect = 1 OR sc = 1')
    request_list = cur.fetchall()

    # DB接続終了
    cur.close()
    con.close()

    # リストをwhile
    for n in range(len(request_list)):
        request(request_list[n])


if __name__ == "__main__":
    main()