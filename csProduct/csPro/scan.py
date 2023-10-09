import requests
import sys
import time
import urllib
import re
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import xml.etree.ElementTree as ET
import subprocess
import json

# first crawl the website
visited_urls = []
directories = {}
directories_list = []

# Define a list of common sensitive URLs to check for
SENSITIVE_URLS = [
    "/admin",
    "/admin.php",
    "/login.php",
    "/admin/index.php",
    "/admin/login.php",
    "/admin/dashboard.php",
    "/wp-admin",
    "/wp-login.php",
    "/administrator",
    "/administrator/index.php",
    "/administrator/login.php",
    "/user/login",
    "/user/login.php",
]

# Define a list of common user IDs to test for
USER_IDS = ["1", "2", "3", "4", "5", "User", "Admin", "Test"]

# create 2 files, 1 for showing in browser and 1 for downloading as report
f = open("templates/result.html", "w")
f1 = open("static/report.html", "w")

css_styles = """
<style>
    .button {
        border-radius: 12px;
        border: none;
        color: white; 
        text-align: center;
        display: inline-block;
        font-size: 20px;
        margin: 4px 2px;
    }
    .buttonhigh {
        background-color: #4CAF50;
    }
    .buttonmedium {
        background-color: orange;
    }
    table {
        font-family: arial, sans-serif;
        border-collapse: collapse;
        width: 100%;
    }
    td, th {
        border: 1px solid #dddddd;
        text-align: left;
        padding: 8px;
    }
    tr:nth-child(even) {
        background-color: #dfe3eb;
    }
    .scanBtn:hover {
        background-color: #bbb;
    }
    .bottom-btn {
    font-size:20px; 
    background-color:#9db0a5; 
    color: black;
    position: fixed;
    bottom: 20px;
    left: 77.5%;
    padding:10px 40px;
    transform: translateX(-50%);
    transition: bottom 0.5s ease;
  } 
   }
.bottom-btn:hover {
    background-color: grey; 
    color: white;
}
    .bottom-btn1 {
    font-size:20px; 
    background-color:#9db0a5; 
    color: black;
    position: fixed;
    bottom: 20px;
    left: 27.5%;
    padding:10px 40px;
    transform: translateX(-50%);
    float: none;
    } 
    .bottom-btn1:hover {
    background-color: grey; 
    color: white;
    }
</style>
"""
f.write(css_styles)
f1.write(css_styles)

report_head="""
{% load static %}
<style>
/* Style the header */
.header {
    background-color: #99ccff;
    padding: 30px 40px;
    color: white;
    text-align: center;
}

body {
    margin: 40;
    min-width: 250px;
    margin-top: 15px;
    min-height: 80%;
    font-family: 'Poppins',sans-serif;
}

/* Include the padding and border in an element's total width and height */
* {
    box-sizing: border-box;
}

/* Clear floats after the header */
/*.header:after {
    content: "";
    display: table;
    clear: both;
}*/
</style>
<div class="header">
    <h2 style="margin:5px">Here is your scan report</h2>
</div>
<br><br>
"""
f.write(report_head)

def banner(url):
    # run nslookup command to find ip of url
    result = subprocess.run(f"nslookup {url}", shell=True, capture_output=True)

    # Parse the output to retrieve the IPv4 address
    ipv4_regex = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
    ipv4_address = re.findall(ipv4_regex, result.stdout.decode())

    h = requests.get(url)
    he = h.headers
    if 'x-powered-by'in he:
        powered_by = he['x-powered-by']
    else:
        powered_by = "No Powered Info Found"
    try:
        sc = requests.get(url)
        # if sc.status_code == 200:
        #     sc = sc.status_code
        # else:
        #     f.write("[!] Error with statu code:"+str(sc.status_code)+"\n")
    except:
        f.write("[!] Error with the first request.\n")
        exit()
        
    f.write("<table><tr><th>Target:</th><th>"+url+"</th><th>Server:</th><th>"+he['server']+"</th></tr>\n")
    f1.write("<table><tr><th>Target:</th><th>"+url+"</th><th>Server:</th><th>"+he['server']+"</th></tr>\n")
    f.write("<tr><th>Date:</th><th>"+he['date']+"</th><th>Powered:</th><th>"+powered_by+"</th></tr>\n")
    f1.write("<tr><th>Date:</th><th>"+he['date']+"</th><th>Powered:</th><th>"+powered_by+"</th></tr>\n")


# def header(url):
#     h = requests.get(url)
#     he = h.headers

#     try:
#         f.write("<tr><th>Server:</th><th>"+he['server']+'</th></tr>\n')
#         f1.write("<tr><th>Server:</th><th>"+he['server']+'</th></tr>\n')
#     except:
#         pass
#     try:
#         f.write("<tr><th>Date:</th><th>"+he['date']+'</th></tr>\n')
#         f1.write("<tr><th>Date:</th><th>"+he['date']+'</th></tr>\n')
#     except:
#         pass
#     try:
#         f.write("<tr><th>Powered:</th><th>"+he['x-powered-by']+'</th></tr>\n')
#         f1.write("<tr><th>Powered:</th><th>"+he['x-powered-by']+'</th></tr>\n')
#     except:
#         pass
#     f.write("\n")

def whoisapi(url):
   turl = "https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=at_WCjAnHITneXOHBxy3eEPzc3nJkeLg&domainName={}".format(url)
   try:
        response = requests.get(turl)
        
        # parse the XML content and get the root element
        root = ET.fromstring(response.text)

        # get the name of the registrant
        # name = root.findtext('name')
        name = root.findtext('.//name')
        
        # get the registrarIANAID value
        registrarIANAID = root.findtext('registrarIANAID')

        # get the createdDateNormalized value
        createdDateNormalized = root.findtext('createdDateNormalized')

        # get the updatedDateNormalized value
        updatedDateNormalized = root.findtext('updatedDateNormalized')

        # get the expiresDateNormalized value
        expiresDateNormalized = root.findtext('expiresDateNormalized')
        
        # get the registrant Country value
        country = root.find('registrant').find('.//country').text if root.find('registrant') is not None else None

        # print the extracted values
        f.write(f"<tr><th>Registrant:</th><th>{name}</th><th>Registrar IANAID:</th><th>{registrarIANAID}</th></tr>\n")
        f1.write(f"<tr><th>Registrant:</th><th>{name}</th><th>Registrar IANAID:</th><th>{registrarIANAID}</th></tr>\n")
        f.write(f"<tr><th>Created Date:</th><th> {createdDateNormalized}</th><th>Updated Date: </th><th>{updatedDateNormalized}</th></tr>\n")
        f1.write(f"<tr><th>Created Date:</th><th> {createdDateNormalized}</th><th>Updated Date: </th><th>{updatedDateNormalized}</th></tr>\n")
        f.write(f"<tr><th>Expires Date: </th><th>{expiresDateNormalized}</th><th>Registrant country:</th><th>{country}\n</th></tr>\n")
        f1.write(f"<tr><th>Expires Date: </th><th>{expiresDateNormalized}</th><th>Registrant country:</th><th>{country}\n</th></tr>\n")
    
   except requests.exceptions.RequestException as e:
        f.write(f"Error making request for url for whois information: {e}")
        f1.write(f"Error making request for url for whois information: {e}")

def ipapi(url):
    # run nslookup command to fin ip of url
    result = subprocess.run(f"nslookup {url}", shell=True, capture_output=True)

    # Parse the output to retrieve the IPv4 address
    ipv4_regex = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
    ipv4_address = re.findall(ipv4_regex, result.stdout.decode())

    # Print the IPv4 address
    if ipv4_address:
        f.write("<tr><th>IPv4 Address:</th><th>"+ipv4_address[0]+"</th></tr></table>")  
        f1.write("<tr><th>IPv4 Address:</th><th>"+ipv4_address[0]+"</th></tr></table>")  
    else:
        f.write("<tr><th>No IP address found.</th><tr></table>")
        f1.write("<tr><th>No IP address found.</th><tr></table>")
        
def wapapi(url):
    turl= f"https://api.wappalyzer.com/v2/lookup/?url={url}"
    headers = {'x-api-key': '7uZY6VwRZ14qALLO5uIh657WmoIi8tF6NmRRH0t4'}
    
    response = requests.get(turl, headers=headers)
    # Parse the JSON content
    data = json.loads(response.text)

    # Extract the slugs
    slugs = [tech["slug"] for tech in data[0]["technologies"]]
    
    # Print the HTML table
    f.write("<table><tr><th>Technologies:</th><th>{}".format(', '.join(slugs))+"</th></tr></table>")

    # Print the slugs
    # f.write("<table><tr><th>Slugs:</th><th></tr></table>"+slugs)

def crawl(url):
    start_url=url
    # Only crawl links within the start domain
    if urlparse(url).netloc != urlparse(start_url).netloc:
        return
    # Check if this URL has already been visited
    if url in visited_urls:
        return
    visited_urls.append(url)
    # Make a request to the URL and parse the HTML
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    # Extract all links on the page
    links = soup.find_all('a')
    for link in links:
        href = link.get('href')
        if href is not None:
            # Construct the full URL of the link
            full_url = urljoin(url, href)
            # Check if the link is a directory or a page and is part of the start URL
            parsed_url = urlparse(full_url)
            if parsed_url.netloc == urlparse(start_url).netloc and parsed_url.path.startswith(urlparse(start_url).path):
                if parsed_url.path.endswith('/'):
                    # If the link is a directory, crawl it recursively
                    if full_url not in visited_urls:
                        directories[parsed_url.path] = []
                        crawl(full_url)
                else:
                    # If the link is a page, add it to the directory's list of pages
                    directory = parsed_url.path.rsplit('/', 1)[0] + '/'
                    directories.setdefault(directory, []).append(full_url)
    return

def crawllist():
    # append all directories and its pages in a list to scan for each page and directory
    for directory, pages in directories.items():
        directories_list.append(directory)
        for page in pages:
            directories_list.append(page)

# # make 2 files, 1 for showing in broswer and 1 for downloading report
# f = open("static/myfile.html", "w")
# f1 = open("static/myfile2.html", "w")

def xss(url):
    # cross site scripting

    # if any vulnerab le point is found then we will stop scanning
    temp=0
    for item in directories_list:
        if item.endswith("/"):
            turl=url+item
        else:
            turl=item
        response = requests.get(turl)
        soup = BeautifulSoup(response.text, 'html.parser')

        # some payloads to test
        payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "<iframe src=javascript:alert('XSS')></iframe>",
        "<a href=\"javascript:alert('XSS')\">Click me</a>",
        "';alert('XSS');//"]
        # Find all input fields in the HTML
        input_fields = soup.find_all('input')

        for field in input_fields:
            # Check if the input field is a text input
            if field.get('type') == 'text':
                # Check if the input field is vulnerable to XSS by checking for a lack of
                # sanitization or validation in the code
                for payload in payloads:
                    # Inject the payload into the input field's value attribute
                    field['value'] = payload
                
                    # Submit the form and check if the payload is reflected in the response
                    response = requests.post(turl, data={field.get('name'): field.get('value')})
                    if "XSS" in response.text:
                        temp=1
                        f.write("<tr><td>2</td><td>Cross-Site Scripting (XSS)</td><td>XSS vulnerability found in input field:"+ field.get('name')+"</td><td><button class='button buttonhigh'>High</button></td><td>38463</td></tr\n")
                        f1.write("<tr><td>2</td><td>Cross-Site Scripting (XSS)</td><td>XSS vulnerability found in input field:"+ field.get('name')+"</td><td><button class='button buttonhigh'>High</button></td><td>38463</td></tr\n")
                        break
            if temp==1:
                break
        if temp==1:
            break


def sql(url):
    # Sql Injecion

    # if any vulnerab le point is found then we will stop scanning
    temp=0
    for item in directories_list:
        if item.endswith("/"):
            turl=url+item
        else:
            turl=item
        response = requests.get(turl)
        soup = BeautifulSoup(response.text, 'html.parser')

        # some payloads to test
        payloads = [
            "-- or #" ,
                "' OR '1",
                "' OR 1 -- -",
               """' " OR "" =' """,
                '" OR 1 = 1 -- -',
                "' OR '' = '",
                "'='",
        ]
        # Find all input fields in the HTML
        input_fields = soup.find_all('input')

        for field in input_fields:
            # Check if the input field is a text input
            if field.get('type') == 'text':
                # Check if the input field is vulnerable to SQLi by checking for a lack of
                # sanitization or validation in the code
                for payload in payloads:
                    # Inject the payload into the input field's value attribute
                    field['value'] = payload
                
                    # Submit the form and check if the payload is reflected in the response
                    response = requests.post(turl, data={field.get('name'): field.get('value')})
                    if 'mysql_fetch_array()' or 'You have an error in your SQL syntax' or 'error in your SQL syntax' \
            or 'mysql_numrows()' or 'Input String was not in a correct format' or 'mysql_fetch' \
            or 'num_rows' or 'Error Executing Database Query' or 'Unclosed quotation mark' \
            or 'Error Occured While Processing Request' or 'Server Error' or 'Microsoft OLE DB Provider for ODBC Drivers Error' \
            or 'Invalid Querystring' or 'VBScript Runtime' or 'Syntax Error' or 'GetArray()' or 'FetchRows()' in response.text:
                        temp=1
                        f.write("<tr><td>3</td><td>SQL Injection (SQLi)</td><td>SQLi vulnerability found in input field:"+ field.get('name')+"</td><td><button class='button buttonhigh'>High</button></td><td>47523</td></tr\n")
                        f1.write("<tr><td>3</td><td>SQL Injection (SQLi)</td><td>SQLi vulnerability found in input field:"+ field.get('name')+"</td><td><button class='button buttonhigh'>High</button></td><td>47523</td></tr\n")
                        break
            if temp==1:
                break
        if temp==1:
            break

def bac(url):
    # broken access control

    # if any vulnerable point is found then we will stop scanning

    # Define a function to check if a URL requires authentication
    def requires_authentication(url):
        response = requests.get(url)
        if response.status_code == 401:
            return True
        return False

    # Define a function to check if a URL is accessible with a given user ID
    def is_accessible_with_user_id(url, user_id):
        response = requests.get(url, cookies={"user_id": user_id})
        if response.status_code == 200:
            return True
        return False

    # Define the main function to perform the test
    def test_for_broken_access_control(url):
        # Check if the URL requires authentication
        if requires_authentication(url):
            # print(f"{url} requires authentication")

            # Te*st for broken access control by trying common user IDs
            for user_id in USER_IDS:
                if is_accessible_with_user_id(url, user_id):
                    f.write("<tr><td>1</td><td>Broken Access Control</td><td>"+url+" is accessible with user ID"+ user_id+"</td><td><button class='button buttonhigh'>High</button></td><td>16476</td></tr>\n")
                    f1.write("<tr><td>1</td><td>Broken Access Control</td><td>"+url+" is accessible with user ID"+ user_id+"</td><td><button class='button buttonhigh'>High</button></td><td>16476</td></tr>\n")
                    return
        
        # Check for sensitive URLs that should be protected
        if url.endswith("/"):
            url = url[:-1]
        for sensitive_url in SENSITIVE_URLS:
            test_url = f"{url}{sensitive_url}"
            response = requests.get(test_url)
            if response.status_code == 200:
                f.write("<tr><td>1</td><td>Broken Access Control</td><td>"+test_url+" is accessible<br> and may be vulnerable to broken access control</td><td><button class='button buttonhigh'>High</button></td><td>16476</td></tr\n")
                f1.write("<tr><td>1</td><td>Broken Access Control</td><td>"+test_url+" is accessible<br> and may be vulnerable to broken access control</td><td><button class='button buttonhigh'>High</button></td><td>16476</td></tr\n")
                return

    requires_authentication(url)
    test_for_broken_access_control(url)
    for user_id in USER_IDS:
        is_accessible_with_user_id(url, user_id)


# def ia(url):
#     # identification and authentiation failures
#     start_url=url
#     # Test for weak identification by trying to access a page that requires authentication without providing any credentials
#     turl = start_url+"/login.php"
#     response = requests.get(turl)
#     if response.status_code == 401 :
#         # print("Access not granted")
#         return

#     # Test for weak authentication by trying to log in with a known username and a blank password
#     turl = start_url+"/login.php"
#     payload = {"username": "user1", "password": ""}
#     response = requests.post(turl, data=payload)
#     if response.status_code == 401:
#         # print("Access is not given with some payload")
#         return

#     # Test for weak authentication by trying to log in with a known username and a weak password
#     turl = start_url+"/login.php"
#     payload = {"username": "user1", "password": "password1"}
#     response = requests.post(turl, data=payload)
#     if response.status_code == 401:
#         # print("Access is not given with some payload")
#         return

#     # Test for broken session management by logging in, then logging out, and trying to access a page that requires authentication again without providing any credentials
#     turl = start_url+"/login.php"
#     payload = {"username": "admin", "password": "admin"}
#     response = requests.post(turl, data=payload)
#     if response.status_code == 200 or response.status_code==302:
#         turl = start_url+"/logout.php"
#         response = requests.get(turl)
#         if response.status_code == 200:
#             turl = start_url+"/user"
#             response = requests.get(turl)
#             if response.status_code == 401:
#                 print("Page is not authorized")
#                 return
#             else:
#                 print("Page is not authorized")
#                 return


def id(url):
    # insecure design

    # Send a request with the valid session cookie to access the main application page
    response = requests.get(url, cookies={"session": "id"})

    # Test for insecure direct object references by trying to access resources that should not be accessible
    # For example, try to access another user's data by modifying the ID in the URL
    insecure_id = "123"
    insecure_url = f"{url}/resource/{insecure_id}"
    response = requests.get(insecure_url, cookies={"session": "id"})

    # Verify that the request fails with a 403 Forbidden status code or similar error message
    if response.status_code == 403:
        print(f"Access to resource {insecure_id} was forbidden, as expected.")
    elif response.status_code!=404:
        response.status_code=str(response.status_code)
        f.write("<tr><td>4</td><td>Insecure Design</td><td>Unexpected status code:"+response.status_code+" received.</td><td><button class='button buttonhigh'>High</td><td>44874</td></tr>\n")
        f1.write("<tr><td>4</td><td>Insecure Design</td><td>Unexpected status code:"+response.status_code+" received.</td><td><button class='button buttonhigh'>High</td><td>44874</td></tr>\n")
        return
    # Test for insufficient authentication and authorization by trying to access privileged resources with a regular user account
    # For example, try to access an administrative function or resource with a regular user account
    privileged_url = f"{url}/admin/resource"
    response = requests.get(privileged_url, cookies={"session": "id"})

    # Verify that the request fails with a 403 Forbidden status code or similar error message
    if response.status_code == 403:
        print(f"Access to privileged resource was forbidden, as expected.")
    elif response.status_code!=404:
        response.status_code=str(response.status_code)
        f.write("<tr><td>4</td><td>Insecure Design</td><td>Unexpected status code:"+response.status_code+" received.</td><td><button class='button buttonhigh'>High</td><td>44874</td></tr>\n")
        f1.write("<tr><td>4</td><td>Insecure Design</td><td>Unexpected status code:"+response.status_code+" received.</td><td><button class='button buttonhigh'>High</td><td>44874</td></tr>\n")
        return

def lfi(url):
    payloads = ['/../etc/passwd','/../../etc/passwd','/..../..../..../etc/passwd','/..../..../etc/passwd','/../../../etc/passwd']
    for pay in payloads:
        req = requests.get(url+pay).text
        if "root:x:0:0" in req:
            f.write("<tr><td>6</td><td>Local File Inclusion</td><td>LFI Vulnerable</td><td><button class='button buttonhigh'>High</td><td>29887</td></tr>\n")
            f1.write("<tr><td>6</td><td>Local File Inclusion</td><td>LFI Vulnerable</td><td><button class='button buttonhigh'>High</td><td>29887</td></tr>\n")
            break
        else:
            pass
            # print("LFI Secured")

def sm(url):
    # Example of a valid user session cookie
    session_cookie = "valid_session_cookie"

    # Test for default or weak passwords on administrator accounts
    # For example, try common or default passwords such as "admin", "password", or "123456"
    admin_username = "admin"
    common_passwords = ["admin", "password", "123456"]
    for password in common_passwords:
        admin_password = password
        response = requests.post(f"{url}/admin/login", data={"username": admin_username, "password": admin_password},timeout=None)

        # Verify that the request fails with a 401 Unauthorized status code or similar error message
        if response.status_code == 401:
            print(f"Login with username {admin_username} and password {admin_password} was unauthorized, as expected.")
        elif response.status_code!=404:
            response.status_code=str(response.status_code)
            f.write("<tr><td>5</td><td>Security Misconfiguration</td><td>Unexpected status code:"+response.status_code+" received.</td><td><button class='button buttonhigh'>High</td><td>1349</td></tr>\n")
            f1.write("<tr><td>5</td><td>Security Misconfiguration</td><td>Unexpected status code:"+response.status_code+" received.</td><td><button class='button buttonhigh'>High</td><td>1349</td></tr>\n")
            return

    # Test for directory listing or file disclosure vulnerabilities
    # For example, try to access a directory that should not be publicly accessible
    sensitive_directory = "/var/www/html/private"
    sensitive_url = f"{url}/{sensitive_directory}"
    response = requests.get(sensitive_url, cookies={"session": session_cookie})

    # Verify that the request fails with a 404 Not Found status code or similar error message
    if response.status_code == 404:
        print(f"Access to directory {sensitive_directory} was not found, as expected.")
    elif response.status_code!=404:
        response.status_code=str(response.status_code)
        f.write("<tr><td>5</td><td>Security Misconfiguration</td><td>Unexpected status code:"+response.status_code+" received.</td><td><button class='button buttonhigh'>High</td><td>1349</td></tr>\n")
        f1.write("<tr><td>5</td><td>Security Misconfiguration</td><td>Unexpected status code:"+response.status_code+" received.</td><td><button class='button buttonhigh'>High</td><td>1349</td></tr>\n")

# def oc(url):
#     # Example of a valid user session cookie
#     session_cookie = "valid_session_cookie"

#     # Test for vulnerable and outdated components
#     # For example, check the version numbers of software components used by the web application and compare them to known vulnerabilities
#     component_versions = {
#         "component1": "1.2.3",
#         "component2": "4.5.6",
#         "component3": "7.8.9"
#     }
#     known_vulnerabilities = {
#         "component1": {
#             "version": ["1.2.3", "1.2.4", "1.2.5"],
#             "vulnerabilities": ["CVE-2020-1234", "CVE-2021-5678"]
#         },
#         "component2": {
#             "version": ["4.5.6", "4.5.7", "4.5.8"],
#             "vulnerabilities": ["CVE-2021-2345"]
#         },
#         "component3": {
#             "version": ["7.8.9", "7.9.0", "7.9.1"],
#             "vulnerabilities": ["CVE-2022-3456", "CVE-2022-7890"]
#         }
#     }
#     for component, info in component_versions.items():
#         if info['version'] in known_vulnerabilities[component]['vulnerabilities']:
#             print(f"Component {component} version {info['version']} is vulnerable to known vulnerabilities {known_vulnerabilities[component]['vulnerabilities']}.")
#         elif info['version'] < max(known_vulnerabilities[component]['version']):
#             print(f"Component {component} version {info['version']} is outdated and may be vulnerable to unreported vulnerabilities.")
#         else:
#             print(f"Component {component} version {info['version']} is not known to be vulnerable.")

def xst(url):
    response = requests.get(url)
    headers = response.headers

    # Check if the response headers contain any cookies or keywords related to cross-site tracking
    if "Set-Cookie" or "HttpOnly" or "Secure" or "SameSite" in headers:
        if "Set-Cookie" in headers:
            f.write("<tr><td>7</td><td>Cross Site Tracking</td><td>Possibility of Cross-Site Tracking Vulnerability<br>POC:SET-Cookie</td><td>Medium</td></tr>\n")
            f.write("<tr><td>7</td><td>Cross Site Tracking</td><td>Possibility of Cross-Site Tracking Vulnerability<br>POC:SET-Cookie</td><td>Medium</td></tr>\n")
            return
        if "HttpOnly" in headers:
            f.write("<tr><td>7</td><td>Cross Site Tracking</td><td>Possibility of Cross-Site Tracking Vulnerability<br>POC:HttpOnly</td><td>Medium</td></tr>\n")
            f.write("<tr><td>7</td><td>Cross Site Tracking</td><td>Possibility of Cross-Site Tracking Vulnerability<br>POC:HttpOnly</td><td>Medium</td></tr>\n")
            return 
        if "Secure" in headers:
            f.write("<tr><td>7</td><td>Cross Site Tracking</td><td>Possibility of Cross-Site Tracking Vulnerability<br>POC:Secure</td><td>Medium</td></tr>\n")
            f.write("<tr><td>7</td><td>Cross Site Tracking</td><td>Possibility of Cross-Site Tracking Vulnerability<br>POC:Secure</td><td>Medium</td></tr>\n")
            return 
        if "SameSite" in headers:
            f.write("<tr><td>7</td><td>Cross Site Tracking</td><td>Possibility of Cross-Site Tracking Vulnerability<br>POC:SameSite</td><td>Medium</td></tr>\n")
            f.write("<tr><td>7</td><td>Cross Site Tracking</td><td>Possibility of Cross-Site Tracking Vulnerability<br>POC:SameSite</td><td>Medium</td></tr>\n")
            return 
    else:
        return 
        # print("[-] No cross-site tracking vulnerability detected.")

def start(start_url):
    timing1 = time.time()
    banner(start_url)
    # header(start_url)
    whoisapi(start_url)
    ipapi(start_url)
    # wapapi(start_url)
    f.write("<br><br><table><tr><th>Sr.No</th><th>Vulnerability</th><th>Description</th><th>Risk</th><th>CVE</th><tr>\n")
    f1.write("<br><br><table><tr><th>Sr.No</th><th>Vulnerability</th><th>Description</th><th>Risk</th><th>CVE</th><tr>\n")
    crawl(start_url)
    crawllist()
    bac(start_url)
    xss(start_url)
    sql(start_url)
    id(start_url)
    sm(start_url)
    # oc(start_url)
    # ia(start_url)
    lfi(start_url)
    xst(start_url)
    timing2 = time.time()
    timet = timing2 - timing1
    timet = str(timet)
    timet = timet.split(".")
    f.write("<tr><th>Time Taken To Scan URL:</th><th>"+timet[0]+" Seconds.</th></tr>")
    f1.write("<tr><th>Time Taken To Scan URL:</th><th>"+timet[0]+" Seconds.</th></tr>")
    f.write("</table>")
    f1.write("</table>")    
    scanbtn="""<a class="bottom-btn1" href="{% url 'home' %}">New Scan</a> 
                <a class="bottom-btn" href="{% static 'report.html' %}" download>Generate Report</a>"""
    f.write(scanbtn)
    f.close()
    f1.close()