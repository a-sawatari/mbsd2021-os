import sqlite3


# メイン
def main():
    # データベース名を設定
    db_name = 'C:/VulnDiag/pg/db_http.db'

    # db_nameのデータベースがなければ作成してから接続する
    con = sqlite3.connect(db_name)

    # sqliteを操作するカーソルオブジェクトを作成
    cur = con.cursor()

    # Create http_table
    cur.execute('''CREATE TABLE IF NOT EXISTS http
                (First_Row text , Host text , User_Agent text , Accept text , Accept_Language text , Accept_Encoding text , Content_Type int , Content_Length text ,
                Origin text , Connection text , Referer text , Upgrade_Insecure_Requests text , Request_Body text , Cookies text , redirect int , sc int)''')

    # Create crawling_table
    cur.execute('''CREATE TABLE IF NOT EXISTS crawling
                (url text unique , flag int)''')

    # Save (commit) the changes
    con.commit()
    con.close()


if __name__ == "__main__":
    main()