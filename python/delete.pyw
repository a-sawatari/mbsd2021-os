import sqlite3


# メイン
def main():
    # データベース名を設定
    db_name = 'C:/VulnDiag/pg/db_http.db'

    # db_nameのデータベースがなければ作成してから接続する
    con = sqlite3.connect(db_name)

    # sqliteを操作するカーソルオブジェクトを作成
    cur = con.cursor()

    #Delete http_table
    cur.execute("DELETE FROM http")

    #Delete crawling_table
    cur.execute("DELETE FROM crawling")

    # Save (commit) the changes
    con.commit()

    # DB接続終了
    con.close()

    #nginxlogの内容を削除
    f = open(r"C:\VulnDiag\nginx\nginx-1.20.1\logs\http.log", 'r+', encoding='UTF-8')
    f.truncate(0)
    f.close


if __name__ == "__main__":
    main()