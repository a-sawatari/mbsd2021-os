import requests
import sqlite3
from urllib.parse import unquote
import method
from time import sleep

# プロキシ設定
proxies = {"http":"http://127.0.0.1:8888"}

# requestの関数
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

    #redirect用のurlを設定
    redirect_url = "https://www.ipa.go.jp/"

    # 診断開始
    while(n<len(getmethod_list)):
        # 正規のgetmethod_listをコピー
        defacing_getmethod_list = getmethod_list.copy()

        # getmethod改ざん
        defacing_getmethod_list[n+1] = redirect_url
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

        # リダイレクト後のurlがredirect_urlの場合、脆弱性有りと判定
        if(redirect_url==response1.url):
            # logファイルからrequestheader取得
            f = open(r"C:\VulnDiag\nginx\nginx-1.20.1\logs\http.log", 'r+', encoding='UTF-8')
            log = f.readlines()
            #f.truncate(0)
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
            response_list = dict(response1.history[0].headers)
            name = "意図しないリダイレクト"
            explanation = "発生しうる脅威：スパマーやフィッシング攻撃に悪用される\n解決法：相対的なURIや信頼できるドメインのリストにのみリダイレクトする安全なリダイレクト機能を実装する。引用{https://www.zaproxy.org/docs/alerts/10028/}"

            # レポート出力
            method.report(str(log_url),getmethod_list[n],list(log_list),response_list,str(log_list[14]),'-',name,explanation)

        # 変数nをwhileが周るごとに+2する
        n = n+2


#メイン
def main():
    # データベース名を設定
    db_name = 'C:/VulnDiag/pg/db_http.db'

    # db_nameのデータベースがなければ作成してから接続する
    con = sqlite3.connect(db_name)

    # sqliteを操作するカーソルオブジェクトを作成
    cur = con.cursor()

    # redirectにフラグを持つデータを取り出す
    cur.execute('SELECT DISTINCT First_Row,Host,User_Agent,Accept,Accept_Language,Accept_Encoding,Content_Type,Origin,Connection,Referer,Upgrade_Insecure_Requests,Cookies,Request_Body FROM http WHERE redirect = 1')
    request_list = cur.fetchall()

    # DB接続終了
    cur.close()
    con.close()

    # リストをwhile
    for n in range(len(request_list)):
        request(request_list[n])


if __name__ == "__main__":
    main()