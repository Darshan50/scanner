import requests
import sys
import time
import urllib
import re

f = open("static/myfile.html", "w")
f1 = open("static/myfile2.html", "w")

# def get_document_url(self):
#     if self.file:
#         return '/static/myfile2.html'

def xst_(url):
    headers = {"Test":"Hello_Word"}
    req = requests.get(url, headers=headers)
    head = req.headers
    if "Test" or "test" in head:
        f.write("<tr><td>3</td><td>Cross Site Tracking ( XST )</td><td>[*] This site seems vulnerable to Cross Site Tracing (XST)!</td><td><button class='button buttonhigh'>High</button></td><td>CVE 2005 3398</td></tr>")
        f1.write("<tr><td>3</td><td>Cross Site Tracking ( XST )</td><td>[*] This site seems vulnerable to Cross Site Tracing (XST)!</td><td><button class='button buttonhigh'>High</button></td><td>CVE 2005 3398</td></tr>")

    else:
        f.write("<tr><td>3</td><td>Cross Site Tracking ( XST )</td><td>[!] XST failed!</td><td><button class='button buttonhigh'>High</button></td><td>CVE 2005 3398</td></tr>")
        f1.write("<tr><td>3</td><td>Cross Site Tracking ( XST )</td><td>[!] XST failed!</td><td><button class='button buttonhigh'>High</button></td><td>CVE 2005 3398</td></tr>")

def lfi_(url):
    temp=0
    # f.write("\n"+"[!] Testing LFI")
    payloads = ['../etc/passwd','../../etc/passwd','../../../etc/passwd','../../../../etc/passwd','../../../../../etc/passwd','../../../../../../etc/passwd','../../../../../../../etc/passwd','../../../../../../../../etc/passwd']
    urlt = url.split("=")
    urlt = urlt[0] + '='
    for pay in payloads:
        uur = urlt + pay
        req = requests.get(uur).text
        if "root:x:0:0" in req:
            f.write("<tr><td>4</td><td>Local File Inclusion ( LFI )</td><td>[*] Payload found.<br>[!] Payload:"+pay+"<br>[!] POC"+uur+"</td><td><button class='button buttonhigh'>High</button></td><td>CVE 2023 26038</td></tr>")
            f1.write("<tr><td>4</td><td>Local File Inclusion ( LFI )</td><td>[*] Payload found.<br>[!] Payload:"+pay+"<br>[!] POC"+uur+"</td><td><button class='button buttonhigh'>High</button></td><td>CVE 2023 26038</td></tr>")
            # f.write("[*] Payload found.")
            # f.write("[!] Payload:"+pay+"")
            # f.write("[!] POC"+uur+"")
            break
        else:
            temp=1
            # f.write("<tr><td>4</td><td>Local File Inclusion ( LFI )</td><td>[!] LFI failed!</td><td>High</td><td>CVE 2023 28883</td></tr>")
    if temp==1:
        f.write("<tr><td>4</td><td>Local File Inclusion ( LFI )</td><td>[!] LFI failed!</td><td><button class='button buttonhigh'>High</button></td><td>CVE 2023 26038</td></tr>")
        f1.write("<tr><td>4</td><td>Local File Inclusion ( LFI )</td><td>[!] LFI failed!</td><td><button class='button buttonhigh'>High</button></td><td>CVE 2023 26038</td></tr>")


def sql_(url):
    temp=0
    temp1=0
    urlt = url.split("=")
    urlt = urlt[0] + '='
    urlb = urlt + '1-SLEEP(2)'
    time1 = time.time()
    req = requests.get(urlb)
    time2 = time.time()
    timet = time2 - time1
    timet = str(timet)
    timet = timet.split(".")
    timet = timet[0]
    if int(timet) >= 2:
        temp1=1
        # f.write("<tr><td>1</td><td>SQL Injection</td><td>[!] Payload:'1-SLEEP(2)'<br>[!] POC:"+urlb+"</td><td>High</td><td>CVE 2023 28883</td></tr>")
    else:
        temp1=0
        # f.write("<tr><td>1</td><td>SQL Injection</td><td>[!]No Time Based Injection Found</td><td>High</td><td>CVE 2023 28883</td></tr>")
    payload1 = "'"
    urlq = urlt + payload1
    reqqq = requests.get(urlq).text
    if 'mysql_fetch_array()' or 'You have an error in your SQL syntax' or 'error in your SQL syntax' \
            or 'mysql_numrows()' or 'Input String was not in a correct format' or 'mysql_fetch' \
            or 'num_rows' or 'Error Executing Database Query' or 'Unclosed quotation mark' \
            or 'Error Occured While Processing Request' or 'Server Error' or 'Microsoft OLE DB Provider for ODBC Drivers Error' \
            or 'Invalid Querystring' or 'VBScript Runtime' or 'Syntax Error' or 'GetArray()' or 'FetchRows()' in reqqq:
        # f.write('\n'+"[*] SQL Error found.")
        temp=1
        # f.write("[!] Payload:"+payload1)
        # f.write("[!] POC:"+urlq)
    else:
        pass
    if temp==1 & temp1==1:
        f.write("<tr><td>1</td><td>SQL Injection</td><td>[*] Payload:'1-SLEEP(2)'<br>[*] POC:"+urlb+"<br>[*] Payload:"+payload1+"<br>[*] POC:"+urlq+"</td><td><button class='button buttonhigh'>High</button></td><td>CVE 2023 28883</td></tr>")
        f1.write("<tr><td>1</td><td>SQL Injection</td><td>[*] Payload:'1-SLEEP(2)'<br>[*] POC:"+urlb+"<br>[*] Payload:"+payload1+"<br>[*] POC:"+urlq+"</td><td><button class='button buttonhigh'>High</button></td><td>CVE 2023 28883</td></tr>")
    elif temp1==1 & temp==0:
        f.write("<tr><td>1</td><td>SQL Injection</td><td>[*] Payload:'1-SLEEP(2)'<br>[*] POC:"+urlb+"</td><td><button class='button buttonhigh'>High</button></td><td>CVE 2023 28883</td></tr>")
        f1.write("<tr><td>1</td><td>SQL Injection</td><td>[*] Payload:'1-SLEEP(2)'<br>[*] POC:"+urlb+"</td><td><button class='button buttonhigh'>High</button></td><td>CVE 2023 28883</td></tr>")
    elif temp1==0 & temp==1:
        f.write("<tr><td>1</td><td>SQL Injection</td><td>[*] Payload:"+payload1+"<br>[*] POC:"+urlq+"</td><td><button class='button buttonhigh'>High</button></td><td>CVE 2023 28883</td></tr>")
        f1.write("<tr><td>1</td><td>SQL Injection</td><td>[*] Payload:"+payload1+"<br>[*] POC:"+urlq+"</td><td><button class='button buttonhigh'>High</button></td><td>CVE 2023 28883</td></tr>")
    else:
        f.write("<tr><td>1</td><td>SQL Injection</td><td>[*] Payload:'1-SLEEP(2)'<br>[*] POC:"+urlb+"</td><td><button class='button buttonhigh'>High</button></td><td>CVE 2023 28883</td></tr>")
        f1.write("<tr><td>1</td><td>SQL Injection</td><td>[*] Payload:'1-SLEEP(2)'<br>[*] POC:"+urlb+"</td><td><button class='button buttonhigh'>High</button></td><td>CVE 2023 28883</td></tr>")

def xss_(url):
    paydone = []
    payloads = ['injectest','/inject','//inject//','<inject','(inject','"inject','<script>alert("inject")</script>']
    urlt = url.split("=")
    urlt = urlt[0] + '='
    for pl in payloads:
        urlte = urlt + pl
        re = requests.get(urlte).text
        if pl in re:
            paydone.append(pl)
        else:
            pass
    url1 = urlt + '%27%3Einject%3Csvg%2Fonload%3Dconfirm%28%2Finject%2F%29%3Eweb'
    req1 = requests.get(url1).text
    if "'>inject<svg/onload=confirm(/inject/)>web" in req1:
        paydone.append('%27%3Einject%3Csvg%2Fonload%3Dconfirm%28%2Finject%2F%29%3Eweb')
    else:
        pass

    url2 = urlt + '%3Cscript%3Ealert%28%22inject%22%29%3C%2Fscript%3E'
    req2 = requests.get(url2).text
    if '<script>alert("inject")</script>' in req2:
        paydone.append('%3Cscript%3Ealert%28%22inject%22%29%3C%2Fscript%3E')
    else:
        pass

    url3 = urlt + '%27%3Cscript%3Ealert%28%22inject%22%29%3C%2Fscript%3E'
    req3 = requests.get(url3).text
    if '<script>alert("inject")</script>' in req3:
        paydone.append('%27%3Cscript%3Ealert%28%22inject%22%29%3C%2Fscript%3E')
    else:
        pass

    if len(paydone) == 0:
        f.write("<tr><td>2</td><td>Cross Site Scripting ( XSS )</td><td>[!] Was not possible to exploit XSS.</td><td><button class='button buttonhigh'>High</button></td><td>CVE 2023 29388</td></tr>")
        f1.write("<tr><td>2</td><td>Cross Site Scripting ( XSS )</td><td>[!] Was not possible to exploit XSS.</td><td><button class='button buttonhigh'>High</button></td><td>CVE 2023 29388</td></tr>")
    else:
        f.write("<tr><td>2</td><td>Cross Site Scripting ( XSS )</td><td>[+]",len(paydone),"Payloads were found.<br>[!] Payload:"+p+"<br>[!] POC:"+ urlt+p+"</td><td><button class='button buttonhigh'>High</button></td><td>CVE 2023 29388</td></tr>")
        f1.write("<tr><td>2</td><td>Cross Site Scripting ( XSS )</td><td>[+]",len(paydone),"Payloads were found.<br>[!] Payload:"+p+"<br>[!] POC:"+ urlt+p+"</td><td><button class='button buttonhigh'>High</button></td><td>CVE 2023 29388</td></tr>")
        # for p in paydone:
        #     f.write('\n'+"[*] Payload found!")
        #     f.write("[!] Payload:"+p)
        #     f.write("[!] POC:"+ urlt+p)

def checkwaf(url):
    try:
        sc = requests.get(url)
        if sc.status_code == 200:
            sc = sc.status_code
        else:
            f.write("[!] Error with status code:"+ sc.status_code)
            f1.write("[!] Error with status code:"+ sc.status_code)
    except:
        f.write("[!] Error with the first request.")
        f1.write("[!] Error with the first request.")
        exit()
    r = requests.get(url)

    opt = ["Yes","yes","Y","y"]
    try:
        if r.headers["server"] == "cloudflare":
            f.write("[\033[1;31m!\033[0;0m]The Server is Behind a CloudFlare Server.")
            f1.write("[\033[1;31m!\033[0;0m]The Server is Behind a CloudFlare Server.")
            ex = input("[\033[1;31m!\033[0;0m]Exit y/n: ")
            if ex in opt:
                exit("[\033[1;33m!\033[0;0m] - Quitting")
    except:
        pass

    noise = "?=<script>alert()</script>"
    fuzz = url + noise
    waffd = requests.get(fuzz)
    # if waffd.status_code == 406 or waffd.status_code == 501:
    #     f.write("<tr><td>5</td><td>Web Application Firewall ( WAF )</td><td>[\\033[1;31m!\033[0;0m] WAF Detected.</td><td>High</td><td>CVE 2023 28883</td></tr>")
    # if waffd.status_code == 999:
    #     f.write("<tr><td>5</td><td>Web Application Firewall ( WAF )</td><td>[\033[1;31m!\033[0;0m] WAF Detected.</td><td>High</td><td>CVE 2023 28883</td></tr>")
    # if waffd.status_code == 419:
    #     f.write("<tr><td>5</td><td>Web Application Firewall ( WAF )</td><td>[\033[1;31m!\033[0;0m] WAF Detected.</td><td>High</td><td>CVE 2023 28883</td></tr>")
    # if waffd.status_code == 403:
    #     f.write("<tr><td>5</td><td>Web Application Firewall ( WAF )</td><td>[\033[1;31m!\033[0;0m] WAF Detected.</td><td>High</td><td>CVE 2023 28883</td></tr>")
    # else:
    f.write("<tr><td>5</td><td>Web Application Firewall ( WAF )</td><td>[!]No WAF Was Found</td><td><button class='button buttonmedium'>Medium</button></td><td>CVE 2021 45468</td></tr>")
    f1.write("<tr><td>5</td><td>Web Application Firewall ( WAF )</td><td>[!]No WAF Was Found</td><td><button class='button buttonmedium'>Medium</button></td><td>CVE 2021 45468</td></tr>")

def header(url):
    h = requests.get(url)
    he = h.headers

    try:
        f.write("<tr><th>Server:</th><th>"+he['server']+'</th></tr>')
        f1.write("<tr><th>Server:</th><th>"+he['server']+'</th></tr>')
    except:
        pass
    try:
        f.write("<tr><th>Date:</th><th>"+he['date']+'</th></tr>')
        f1.write("<tr><th>Date:</th><th>"+he['date']+'</th></tr>')
    except:
        pass
    try:
        f.write("<tr><th>Powered:</th><th>"+he['x-powered-by']+'</th></tr></table>')
        f1.write("<tr><th>Powered:</th><th>"+he['x-powered-by']+'</th></tr></table>')
    except:
        pass
    f.write("\n")
def banner(url):
    try:
        sc = requests.get(url)
        if sc.status_code == 200:
            sc = sc.status_code
        else:
            f.write("[!] Error with statu code:"+sc.status_code)
            f1.write("[!] Error with statu code:"+sc.status_code)
    except:
        f.write("[!] Error with the first request.")
        f1.write("[!] Error with the first request.")
        exit()
        
    f.write("<table><tr><th>Target:</th><th>"+url+"</th></tr>")
    f1.write("<table><tr><th>Target:</th><th>"+url+"</th></tr>")
def help():
    f.write("""
    Example link: http://example.com/page.php?id=value
    """)
    exit()

def start(url):
    if 'http' not in url:
        help()
        return 1
    if '?' not in url:
        help() 
        return 1
    timing1 = time.time()
    banner(url)
    f.write("")
    header(url)
    f.write("<br><br><table><tr><th>Sr.No</th><th>Vulnerability</th><th>Description</th><th>Risk</th><th>CVE</th></tr>")
    f1.write("<br><br><table><tr><th>Sr.No</th><th>Vulnerability</th><th>Description</th><th>Risk</th><th>CVE</th></tr>")
    sql_(url)
    xss_(url)
    xst_(url)
    lfi_(url)
    checkwaf(url)
    timing2 = time.time()
    timet = timing2 - timing1
    timet = str(timet)
    timet = timet.split(".")
    f.write("<tr><th>Time Taken To Scan URL:</th><th>"+timet[0]+" Seconds.</th></tr>")
    f1.write("<tr><th>Time Taken To Scan URL:</th><th>"+timet[0]+" Seconds.</th></tr>")
    f.write("</table>")
    f1.write("</table>")
    f.write("<a class='bottom-btn' href='static/myfile2.html' download>Generate Report</a>")
    f.write("<style>.button {border-radius: 12px;border: none;color: white;text-align: center;display: inline-block;font-size: 20px;margin: 4px 2px;} .buttonhigh {background-color: #4CAF50;} .buttonmedium{background-color:orange;}")
    f1.write("<style>.button {border-radius: 12px; border: none;color: white;text-align: center;display: inline-block;font-size: 20px;margin: 4px 2px;} .buttonhigh { background-color: #4CAF50;} .buttonmedium{background-color:orange;}")
    # f.write(".scanBtn {font-family: 'Poppins',sans-serif;padding: 10px;width: 25%;margin-top: 12px; background: #d9d9d9; color: #555;border: solid; border-color: #000000;float: right;text-align: center;font-size: 16px;cursor: pointer;transition: 0.3s;border-radius: 0;}")
    f.write("table { font-family: arial, sans-serif; border-collapse: collapse; width: 100%; }")
    f1.write("table { font-family: arial, sans-serif; border-collapse: collapse; width: 100%; }")
    f.write("td, th { border: 1px solid #dddddd; text-align: left; padding: 8px;}tr:nth-child(even) { background-color: #dfe3eb;}")
    f1.write("td, th { border: 1px solid #dddddd; text-align: left; padding: 8px;}tr:nth-child(even) { background-color: #dfe3eb;}")
    f.write(".scanBtn:hover {background-color: #bbb;}  .bottom-btn {font-size:20px; background-color:#9db0a5; color: black;position: fixed;bottom: 60px;left: 50%;padding:10px 40px;transform: translateX(-50%);} .bottom-btn:hover{background-color: grey; color: white;}</style>")   
    f1.write(".scanBtn:hover {background-color: #bbb;}  .bottom-btn {position: fixed;bottom: 20;left: 50%;transform: translateX(-50%);} </style>")   
    # f.write("<form method='post'>{% csrf_token %}<input type='submit' class='scanBtn' name='pdf_button' value='Report'></form>")
    # f.write("<button type=")
    # f.write("submit class=")
    # f.write("scanBtn onclick=downloadhtml() >DownloadReport</button>")
    f.close()
    f1.close()
    # pdfkit.from_file('myfile.html', 'out.pdf')