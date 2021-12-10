import requests
import sqlite3
from urllib.parse import unquote
import method
from time import sleep

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

    # GETmethod_list設定
    getmethod = method.getmethod(url)
    idx = getmethod[0]
    getmethod_list = getmethod[1]

    #getmethodが診断できる値か判定
    if(len(getmethod_list)%2!=0):
        return

    # 変数nを設定
    n = 0

    # 診断開始
    while(n<len(getmethod_list)):
        # 正規のgetmethod_listをコピー
        defacing_getmethod_list = getmethod_list.copy()

        # getmethod改ざん
        defacing_getmethod_list[n+1] += "%0d%0aSet-Cookie:xxxtest%3Dxxxxtest%3B"
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
                response1 = requests.get(url[:idx]+defacing_getmethod,headers=headers,cookies=cookies,proxies=proxies)
            else:
                # cookie無
                response1 = requests.get(url[:idx]+defacing_getmethod,headers=headers,proxies=proxies)
        except Exception:
            n = n+2
            continue
        sleep(1)

        #リダイレクトか判定
        if(response1.history==[]):
            response_headers = response1.headers
        else:
            response_headers = response1.history[0].headers

        # レスポンスヘッダに、xxxtest=xxxxtestが含まれていた場合、脆弱性ありと判定
        if("xxxtest=xxxxtest" in str(response_headers)):
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

                # log_url設定
                log_url = method.url(log_list[0])

                # cookie_listの設定
                log_cookie_list = log_list[13].replace('; ','%cookie%').split('%cookie%')
                request_cookie_list = request_list[11].replace('; ','%cookie%').split('%cookie%')

                # 対象logか判定
                if(unquote(url[:idx]+defacing_getmethod)==unquote(log_url) and request_cookie_list.sort()==log_cookie_list.sort()):
                    break

            # report書き込み準備
            response_list = dict(response_headers)
            if(response1.history==[]):
                name = "HTTPヘッダー・インジェクション1"
                text = response1.text
            else:
                name = "HTTPヘッダー・インジェクション2"
                text = '-'
            explanation = "発生しうる脅威：フィッシング詐欺等による重要情報の漏えい、ブラウザが保存しているCookieを取得される、任意のCookieをブラウザに保存させられる等\n解決法：IPA 安全なウェブサイトの作り方{https://www.ipa.go.jp/files/000017316.pdf}[7-(ⅰ)-a][ 7-(ⅱ)-a]等"

            # レポート出力
            method.report(str(log_url),'-',list(log_list),response_list,str(log_list[14]),text,name,explanation)

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