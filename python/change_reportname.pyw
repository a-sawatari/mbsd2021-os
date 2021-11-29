import datetime
import os

def main():
    # 現在日時を取得
    dt_now = datetime.datetime.now()

    # 日時を成形
    time = dt_now.strftime('%Y-%m-%d_%H-%M')

    # 変更前のファイル名
    before_filename = 'c:/VulnDiag/report/report.txt'

    # 変更後のファイル名
    after_filename = 'c:/Vulndiag/report/report_'+time+'.txt'

    # ファイル名変更
    os.rename(before_filename, after_filename)


if __name__ == "__main__":
    main()