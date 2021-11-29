import sqlite3
db_name = 'C:/VulnDiag/pg/db_http.db'
con = sqlite3.connect(db_name)
cur = con.cursor()

# terminalで実行したSQL文と同じようにexecute()に書く
cur.execute('SELECT * FROM http')

# 中身を全て取得するfetchall()を使って、printする。
for row in cur:
    print(row)

cur.close()
con.close()