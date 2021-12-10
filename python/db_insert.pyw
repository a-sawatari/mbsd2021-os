import sqlite3
from sys import argv


# メイン
def main():
    # 指定サイトのhost
    host = argv[1]

    # データベース名を設定
    db_name = 'C:/VulnDiag/pg/db_http.db'

    # db_nameのデータベースがなければ作成してから接続する
    con = sqlite3.connect(db_name)

    # sqliteを操作するカーソルオブジェクトを作成
    cur = con.cursor()

    # ファイル読み込み
    f = open(r"C:\VulnDiag\nginx\nginx-1.20.1\logs\http.log", 'r', encoding='UTF-8')
    log = list(dict.fromkeys(f.readlines()))

    #データベースのid
    id = 1

    for line in log:
        # lineの改行コード削除及びデータベースでidとなる数値をlineに加えたonelogを設定
        onelog = line.strip()

        # log_listを作成
        log_list = onelog.split('%log%')

        # 指定サイトか判定
        if(host==log_list[1] and "socket.io" not in log_list[0] and "CONNECT" not in log_list[0]):
            # http_listを作成
            http_list = tuple(log_list[0:14])

            #フラグの設定
            #リダイレクトか判定
            if(300<int(log_list[14])<303):
                http_list = http_list+(1,)
            else:
                http_list = http_list+(None,)
            #Set-Cookieヘッダーがあるか判定
            if(log_list[15]!='-'):
                http_list = http_list+(1,)
            else:
                http_list = http_list+(None,)

            # loginsert
            cur.execute("INSERT INTO http VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",http_list)

            # Save (commit) the changes
            con.commit()
            id = id+1

    # ファイルを閉じる
    f.close()

    # DB接続終了
    con.close()


if __name__ == "__main__":
    main()