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
                #検出パターン4の追加診断
                if(cssp_n==2):
                    #cssセレクターのリスト
                    sel_list = ["[href*='javascript:alert(document.cookie);']","[src*='javascript:alert(document.cookie);']"]

                    #cssセレクターの数だけ診断
                    for sel_n in range(len(sel_list)):
                        #cssセレクターで値を取得できるか判定
                        if(response1.html.find(sel_list[sel_n],first=True)!=None):
                            break
                    else:
                        #cssセレクターをすべて実行して値を取得出来なかった場合、脆弱性なしと判断
                        break

                # logファイルからrequestheader取得
                f = open(r"C:\VulnDiag\nginx\nginx-1.20.1\logs\http.log", 'r+', encoding='UTF-8')
                log = f.readlines()
                f.truncate(0)
                f.close

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
                        break

                # report書き込み準備
                response_list = dict(response1.headers)
                if(cssp_n<2):
                    name = "クロスサイトスクリプティング"+str(cssp_n+1)
                else:
                    name = "クロスサイトスクリプティング"+str(cssp_n+2)
                explanation = "発生しうる脅威：フィッシング詐欺等による重要情報の漏えい、ブラウザが保存しているCookieを取得される、任意のCookieをブラウザに保存させられる等\n解決法：IPA 安全なウェブサイトの作り方{https://www.ipa.go.jp/files/000017316.pdf}[5-(ⅰ)][5-(ⅱ)]、[5-(ⅲ)]、[5-(ⅳ)]、[5-(ⅵ)][5-(ⅷ)]等"

                # レポート出力
                method.report(url,body_list[n],list(log_list),response_list,str(log_list[14]),response1.text,name,explanation)

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
                    response1 = session.get(url[:idx]+defacing_getmethod,proxies=proxies)
            except Exception:
                continue
            sleep(1)

            # レスポンスにcssp_list[cssp_n]が含まれている場合、脆弱性ありと判定
            if(response1.html.search(cssp_list[cssp_n])!=None):
                #検出パターン4の追加診断
                if(cssp_n==2):
                    #cssセレクターのリスト
                    sel_list = ["[href*='javascript:alert(document.cookie);']","[src*='javascript:alert(document.cookie);']"]

                    #cssセレクターの数だけ診断
                    for sel_n in range(len(sel_list)):
                        #cssセレクターで値を取得できるか判定
                        if(response1.html.find(sel_list[sel_n],first=True)!=None):
                            break
                    else:
                        #cssセレクターをすべて実行して値を取得出来なかった場合、脆弱性なしと判断
                        break

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

                    # log_url設定
                    log_url = method.url(log_list[0])

                    # cookie_listの設定
                    log_cookie_list = log_list[13].replace('; ','%cookie%').split('%cookie%')
                    request_cookie_list = request_list[11].replace('; ','%cookie%').split('%cookie%')

                    # 対象logか判定
                    if(unquote(url[:idx]+defacing_getmethod)==unquote(log_url) and request_cookie_list.sort()==log_cookie_list.sort()):
                        break

                # report書き込み準備
                response_list = dict(response1.headers)
                if(cssp_n<2):
                    name = "クロスサイトスクリプティング"+str(cssp_n+1)
                else:
                    name = "クロスサイトスクリプティング"+str(cssp_n+2)
                explanation = "発生しうる脅威：フィッシング詐欺等による重要情報の漏えい、ブラウザが保存しているCookieを取得される、任意のCookieをブラウザに保存させられる等\n解決法：IPA 安全なウェブサイトの作り方{https://www.ipa.go.jp/files/000017316.pdf}[5-(ⅰ)][5-(ⅱ)]、[5-(ⅲ)]、[5-(ⅳ)]、[5-(ⅵ)][5-(ⅷ)]等"

                # レポート出力
                method.report(str(log_url),getmethod_list[n],list(log_list),response_list,str(log_list[14]),response1.text,name,explanation)

        # 変数nをwhileが周るごとに+2する
        n = n+2


#検出パターン３の診断（crawring用）
def p3_request_crw(url_list):
    # 初期設定
    headers = {"User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:94.0) Gecko/20100101 Firefox/94.0"}

    # url_list分のrequest
    for url in url_list:
        # urlの改ざん
        splite_url = url[0].split('/')
        splite_url[-1] = "<script>alert(document.cookie)</script>"
        defacing_url = '/'.join(splite_url)

        # 攻撃開始
        try:
            response1 = session.get(defacing_url,headers=headers,proxies=proxies)
        except Exception:
            continue
        sleep(1)

        # レスポンスにsplite_url[-1]が含まれている場合、脆弱性ありと判定
        if(response1.html.search("<script>alert(document.cookie)</script>")!=None):
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
            name = "クロスサイト・スクリプティング3"
            explanation = "発生しうる脅威：フィッシング詐欺等による重要情報の漏えい、ブラウザが保存しているCookieを取得される、任意のCookieをブラウザに保存させられる等\n解決法：IPA 安全なウェブサイトの作り方{https://www.ipa.go.jp/files/000017316.pdf}[5-(ⅰ)][5-(ⅱ)]、[5-(ⅲ)]、[5-(ⅳ)]、[5-(ⅵ)][5-(ⅷ)]等"

            # レポート出力
            method.report(str(log_url),'-',list(log_list),response_list,str(log_list[14]),response1.text,name,explanation)


#検出パターン３の診断
def p3_request(request_list):
    # url設定
    url = method.url(request_list[0])

    # header設定
    headers = method.headers(request_list)

    # cookies設定
    cookies = method.cookies(request_list[11])

    # 攻撃開始

    # urlの改ざん
    splite_url = url[0].split('/')
    splite_url[-1] = "<script>alert(document.cookie)</script>"
    defacing_url = '/'.join(splite_url)

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
    if(response1.html.search("<script>alert(document.cookie)</script>")!=None):
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
        name = "クロスサイト・スクリプティング3"
        explanation = "発生しうる脅威：フィッシング詐欺等による重要情報の漏えい、ブラウザが保存しているCookieを取得される、任意のCookieをブラウザに保存させられる等\n解決法：IPA 安全なウェブサイトの作り方{https://www.ipa.go.jp/files/000017316.pdf}[5-(ⅰ)][5-(ⅱ)]、[5-(ⅲ)]、[5-(ⅳ)]、[5-(ⅵ)][5-(ⅷ)]等"

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

    # DB接続終了
    cur.close()
    con.close()

    # リストをwhile
    for n in range(len(request_list)):
        #検出パターン1,2,4
        if("POST" in request_list[n][0]):
            POST_request(request_list[n])
        elif("?" in request_list[n][0]):
            GET_request(request_list[n])

        #検出パターン3
        url = request_list[n][0].split(' ')[1]
        final_path = url.split('/')[-1]
        if('.' in final_path and '?' not in final_path):
            p3_request(request_list[n])

    # crawlingしたurlで診断
    p3_request_crw(url_list)


if __name__ == "__main__":
    main()