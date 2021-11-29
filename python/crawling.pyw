import sqlite3
from time import sleep
from requests_html import HTMLSession
from sys import argv

# クローリング関数
def crawling(url):
    # requests_htmlの設定
    session = HTMLSession()
    # Hostを設定
    Host = url.split('/')[2]

    # file_url_list作成
    file_url_list = []

    #method_url_list作成
    method_url_list = []

    # url_list作成
    all_url_list = [url]

    # url_listの要素数だけurlを探索する
    n = 0
    while n<len(all_url_list):
        # request送信
        try:
            response = session.get(all_url_list[n])
        except Exception:
            all_url_list.pop(n)
            continue

        #ステータスコードが200番台か判定
        if(int(response.status_code)<300):
            #getmethodがあるか判定
            if('?' in all_url_list[n]):
                #getmethod部に'.'が含まれているか判定
                if('.' in all_url_list[n].split('?')[-1]):
                    #urlをmethod_url_listに追加
                    method_url_list.append(all_url_list[n])
            else:
                #urlの最後のpathに'.'がついているか判定
                if('.' in all_url_list[n].split('/')[-1]):
                    #urlをfile_url_listに追加
                    file_url_list.append(all_url_list[n])
            #js実行
            try:
                response.html.render(timeout=20)
            except Exception:
                n = n+1
                continue
        else:
            #ステータスコードが200番台じゃなかったurlを削除
            all_url_list.pop(n)
            continue

        # url_listに見つけたurlを追加
        all_url_list.extend(list(response.html.absolute_links))

        # url_listの重複を削除
        all_url_list = list(dict.fromkeys(all_url_list))

        # Hostのurl以外を除外
        all_url_list = [s for s in all_url_list if Host in s]
        n = n+1
        print(all_url_list)

    # file_url_listの重複を削除
    file_url_list = list(dict.fromkeys(file_url_list))

    # method_url_listの重複を削除
    method_url_list = list(dict.fromkeys(method_url_list))

    # リターン
    return(file_url_list,method_url_list,all_url_list)


# メイン
def main():
    # ユーザが設定したurl受け取り
    url = argv[1]

    # クローリング
    url_lists = crawling(url)

    # データベース名を設定
    db_name = 'C:/VulnDiag/pg/db_http.db'

    # db_nameのデータベースがなければ作成してから接続する
    con = sqlite3.connect(db_name)

    # sqliteを操作するカーソルオブジェクトを作成
    cur = con.cursor()

    # url_lists[0]の要素数分繰り返す
    for file_url in url_lists[0]:
        #file_urlを'/'で分割
        split_file_url = file_url.split('/')

        #file_urlのディレクトリを一つ上にあげたurlがurl_listにないか判定
        if('/'.join(split_file_url[0:-1]) not in url_lists[2]):
            url_flag = (file_url,1,)
        else:
            url_flag = (file_url,None,)

        # crawlingにfile_urlをinsert
        try:
            cur.execute("INSERT INTO crawling VALUES(?,?)",url_flag)
            con.commit()
        except sqlite3.IntegrityError:
            pass

    # url_lists[1]の要素数分繰り返す
    for method_url in url_lists[1]:
        #insertする値を設定
        url_flag = (method_url,2,)

        # crawlingにmethod_urlをinsert
        try:
            cur.execute("INSERT INTO crawling VALUES(?,?)",url_flag)
            con.commit()
        except sqlite3.IntegrityError:
            pass

    # DB接続終了
    con.close()


if __name__ == "__main__":
    main()