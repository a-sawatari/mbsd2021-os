def url(first_row):
    # url設定
    url = first_row.split(' ')[1]
    return(url)


def headers(request_list):
    # header設定
    headers = {}

    # 各headerの追加
    if(request_list[1]!='-'):
        headers['Host'] = request_list[1]
    if(request_list[2]!='-'):
        headers['User-Agent'] = request_list[2]
    if(request_list[3]!='-'):
        headers['Accept'] = request_list[3]
    if(request_list[4]!='-'):
        headers['Accept-Language'] = request_list[4]
    if(request_list[5]!='-'):
        headers['Accept-Encoding'] = request_list[5]
    if(request_list[6]!='-'):
        headers['Content-Type'] = request_list[6]
    if(request_list[7]!='-'):
        headers['Origin'] = request_list[7]
    if(request_list[8]!='-'):
        headers['Connection'] = request_list[8]
    if(request_list[9]!='-'):
        headers['Referer'] = request_list[9]
    if(request_list[10]!='-'):
        headers['Upgrade-Insecure-Requests'] = request_list[10]
    return(headers)


def cookies(Cookie):
    cookies={}
    if(Cookie!='-'):
        # cookies設定
        cookie = Cookie.replace('; ','%cookie%')
        cookie_list = cookie.split('%cookie%')
        for cookie in cookie_list:
            separate_cookies = cookie.split('=',1)
            cookies[separate_cookies[0]]= separate_cookies[1]
    # 返り値
    return(cookies)


def request_body(Body):
    # request_bodyの設定
    payload={}
    if(Body.find('{')!=0):
        body = Body.replace('=','%body%').replace('&','%body%')
        body_list = body.split('%body%')
    else:
        Body = Body.replace('\\x22','"')
        body = Body[2:-2].replace('":"','%body%').replace('": "','%body%')
        body = body.replace('","','%body%').replace('", "','%body%')
        body_list = body.split('%body%')

    i=0
    # 辞書型のpayloadを作成
    while(i+1<len(body_list)):
        payload[body_list[i]] = body_list[i+1]

        i = i+2

    # 返り値
    return(body_list,payload)


def getmethod(url):
    # GETmethod設定
    idx = url.find('?')
    getmethod = url[idx+1:]
    getmethod = getmethod.replace('&','=')
    getmethod_list = getmethod.split('=')
    # 返り値
    return(idx,getmethod_list)


def report(url,parameter,log_list,response_list,status,text,name,explanation):
    from urllib.parse import unquote
    import os

    #os_systemディレクトリにreportディレクトリがない場合、新規作成
    os.makedirs('C:/VulnDiag/report',exist_ok=True)

    # report.txtがディレクトリにない場合は作成してから開く
    f = open('C:/VulnDiag/report/report.txt', 'a', encoding='UTF-8')

    # 変数reportにreport.txtに記述する内容を1行ごとにリスト型で格納
    report=['[URL]---------------------------------------------------------------------------\n',
            unquote(url)+'\n',
            '[パラメータ]--------------------------------------------------------------------\n',
            parameter+'\n',
            '[脆弱性名]----------------------------------------------------------------------\n',
            name+'\n',
            '[脆弱性の説明]----------------------------------------------------------------------\n',
            explanation+'\n',
            '[リクエストライン]---------------------------------------------------------------\n',
            unquote(log_list[0])+'\n',
            '[リクエストヘッダー]-------------------------------------------------------------\n',
            'Host: '+log_list[1]+'\n',
            'User-Agent: '+log_list[2]+'\n',
            'Accept: '+log_list[3]+'\n',
            'Accept-Language: '+log_list[4]+'\n',
            'Accept-Encoding: '+log_list[5]+'\n',
            'Content-Type: '+log_list[6]+'\n',
            'Content-Length: '+log_list[7]+'\n',
            'Origin: '+log_list[8]+'\n',
            'Connection: '+log_list[9]+'\n',
            'Referer: '+log_list[10]+'\n',
            'Upgrade-Insecure-Requests: '+log_list[11]+'\n',
            '[リクエストボディ]---------------------------------------------------------------\n',
            unquote(log_list[12])+'\n',
            '[レスポンスヘッダー]-------------------------------------------------------------\n',
            'status: '+status+'\n']
    try:
        report.append('Date: '+str(response_list['Date'])+'\n')
    except KeyError:
        report.append('Date: -\n')
    try:
        report.append('Content-Length: '+str(response_list['Content-Length'])+'\n')
    except KeyError:
        report.append('Content-Length: -\n')
    try:
        report.append('Connection: '+str(response_list['Connection'])+'\n')
    except KeyError:
        report.append('Connection: -\n')
    try:
        report.append('Content-Type: '+str(response_list['Content-Type'])+'\n')
    except KeyError:
        report.append('Content-Type: -\n')
    report.append('[レスポンスボディ]---------------------------------------------------------------\n')
    report.append("\n".join(text.splitlines()))
    report.append('\n\n')

    # report書き込み
    f.writelines(report)

    # ファイルを閉じる
    f.close()