from requests_html import HTMLSession
from urllib.parse import unquote
import sqlite3
import method
from time import sleep
import json

# request_htmlの設定
session = HTMLSession()

# プロキシ設定
proxies = {"http":"http://127.0.0.1:8888"}

# クローリングしたurlの場合の関数
def crawling_request(url_list):
    # 初期設定
    headers = {"User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:94.0) Gecko/20100101 Firefox/94.0"}

    # url_list分のrequest
    for url in url_list:
        # urlの改ざん
        splite_url = url[0].split('/')
        defacing_url = '/'.join(splite_url[0:-1])

        # 攻撃開始
        try:
            response1 = session.get(defacing_url,headers=headers,proxies=proxies)
        except Exception:
            continue
        sleep(1)

        # レスポンスにsplite_url[-1]が含まれている場合、脆弱性ありと判定
        if(response1.html.search(splite_url[-1])!=None):
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
                if("GET" not in log_list[0]):
                    continue

                # url設定
                log_url = method.url(log_list[0])

                # 対象logか判定
                if(defacing_url==log_url and "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:94.0) Gecko/20100101 Firefox/94.0"==log_list[2]):
                    break

            # report書き込み準備
            response_list = dict(response1.headers)
            name = "ディレクトリ・リスティング"
            explanation = "発生しうる脅威：ディレクトリ一覧の表示\n解決法：ディレクトリブラウジングを無効にします。必要な場合は、リストされたファイルがリスクを引き起こさないことを確認してください。"

            # レポート出力
            method.report(str(log_url),'-',list(log_list),response_list,str(log_list[14]),response1.text,name,explanation)


# logのurlの場合
def request(request_list):
    # url設定
    url = method.url(request_list[0])

    # header設定
    headers = method.headers(request_list)

    # cookies設定
    cookies = method.cookies(request_list[11])

    # 攻撃開始

    # urlの改ざん
    splite_url = url.split('/')
    defacing_url = '/'.join(splite_url[0:-1])

    # request送信
    if("POST" in request_list[0]):
        # request_bodyの設定
        request_body = method.request_body(request_list[12])
        body_list = request_body[0]
        payload = request_body[1]

        # ContentTypeがjsonの場合、型を変更する
        if(request_list[6]=='application/json'):
            payload = json.dumps(payload)

        # request送信
        try:
            if(cookies!={}):
                # cookie有
                response1 = session.post(defacing_url,payload,headers=headers,cookies=cookies,proxies=proxies)
            else:
                # cookie無
                response1 = session.post(defacing_url,payload,headers=headers,proxies=proxies)
        except Exception:
            return
        sleep(1)

        # ContentTypeがjsonの場合、型を変更する
        if(request_list[6]=='application/json'):
            payload = json.loads(payload)
    else:
        try:
            # request送信
            if(cookies!={}):
                # cookie有
                response1 = session.get(defacing_url,headers=headers,cookies=cookies,proxies=proxies)
            else:
                # cookie無
                response1 = session.get(defacing_url,headers=headers,proxies=proxies)
        except Exception:
            return

    # レスポンスにsplite_url[-1]が含まれている場合、脆弱性ありと判定
    if(response1.html.search(splite_url[-1])!=None):
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

            # log_url設定
            log_url = method.url(log_list[0])

            # cookie_listの設定
            log_cookie_list = log_list[13].replace('; ','%cookie%').split('%cookie%')
            request_cookie_list = request_list[11].replace('; ','%cookie%').split('%cookie%')

            # 対象logか判定
            if(defacing_url==log_url and request_cookie_list.sort()==log_cookie_list.sort()):
                break

        # report書き込み準備
        response_list = dict(response1.headers)
        name = "ディレクトリ・リスティング"
        explanation = "発生しうる脅威：ディレクトリの内容の一覧を表示\n解決法：Webサーバーの設定で、ディレクトリの閲覧を禁止してください。引用{https://www.zaproxy.org/docs/alerts/10033/}"

        # レポート出力
        method.report(str(log_url),'-',list(log_list),response_list,str(log_list[14]),response1.text,name,explanation)


# メイン
def main():
    # データベース名を設定
    db_name = 'C:/VulnDiag/pg/db_http.db'

    # db_nameのデータベースがなければ作成してから接続する
    con = sqlite3.connect(db_name)

    # sqliteを操作するカーソルオブジェクトを作成
    cur = con.cursor()

    # crawlingにアクセス
    cur.execute('SELECT url FROM crawling WHERE flag = 1')
    url_list = cur.fetchall()

    # httpにアクセス
    cur.execute('SELECT DISTINCT First_Row,Host,User_Agent,Accept,Accept_Language,Accept_Encoding,Content_Type,Origin,Connection,Referer,Upgrade_Insecure_Requests,Cookies,Request_Body FROM http')
    request_list = cur.fetchall()

    # データベースclose
    cur.close()
    con.close()

    # crawlingしたurlで診断
    crawling_request(url_list)

    # request_listをwhile
    for n in range(len(request_list)):
        # urlの抜き出し
        url = request_list[n][0].split(' ')[1]
        final_path = url.split('/')[-1]
        if('.' in final_path and '?' not in final_path):
            request(request_list[n])


if __name__ == "__main__":
    main()