from urllib import unquote
import sys
import os
import time
import hashlib
import socket
import json
import multiprocessing
import functools
from multiprocessing import Process, Queue, Pool
import re
import urllib
import urllib2
import zlib
import gzip
import StringIO

import fileuploader
import filemutator
import rabbitmq

Debug = False

TotalRequest = 0
ProcessedRequest = 0
SuccessRequest = 0

upload_time = 0
vfy_time = 0
mutation_time = 0

PROCESS_LIMIT = 8

CONF = {
        'target':{
            'webHost':'', # HTTP, HTTPS
            'webUploadURL':'',
            'webRootPath': '' # uncertain
        },
        'framework':{
            'mutationChainLimit': 99,
            'monitorEnable': True,
            'monitorHost': '192.168.100.131',
            'monitorPort': 20174
        }
    }


def ungzip(data, encode=None):
    if encode != None:
        if "deflate" in encode.lower():
            ret = zlib.decompress(data, 16+zlib.MAX_WBITS)
        elif "gzip" in encode.lower():
            tmp = StringIO.StringIO(data)
            ret = gzip.GzipFile(fileobj=tmp).read()
    else:
        ret = data
    return ret


class MonitorClient(object):
    __ip__ = None

    def __init__(self, ip, port=20174):
        self.__ip__ = ip
        self.conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.conn.connect((ip, port)) # ip: monitorHost

    def fileValidator(self, filename, filebinary):
        filehash = hashlib.md5(filebinary).hexdigest()
        #print filehash
        if filename[0] != '.':
            namespliter = filename.rsplit('.', 1)
        else:
            namespliter = filename[1:].rsplit('.', 1)
            namespliter[0] = '.'+namespliter[0]

        if len(namespliter) < 2:
            namespliter.append(None)
        sendData = {}
        sendData['type'] = "verify"
        sendData['filename'] = namespliter[0]
        sendData['ext'] = namespliter[1]
        sendData['filehash'] = filehash
        # print sendData
        self.send(sendData)
        response = self.recv()

        # print "[+] RE ... "
        # print response

        if response == None:
            print "Fail to Communicate Server"
        else:
            if response["type"] == "Fail":
                return (False, None)
            else:
                if filehash != response["hash"]:
                    print "[-] File hash is not matched"
                return (True, response)

    def recv(self):
        recvData = ""
        try:
            while True:
                recvDataPart = self.conn.recv(10)

                if not recvDataPart:
                    break
                elif '\n' in recvDataPart:
                    recvData += recvDataPart
                    break
                recvData += recvDataPart

        except:
            print "[-] Error occured during recieving command"
            return None

        if recvData[0] == "\"":
            recvData = recvData[1:]
        if recvData[-2] == "\"":
            recvData = recvData[:-2]
        if '\\' in recvData:
            recvData = recvData.replace('\\', '')
        
        try:
            retData = json.loads(recvData)
        except:
            print "[-] Error occured during parsing recieved command"
            return None
        return retData

    def send(self, data):
        sendData = json.dumps(data)

        while True:
            try:
                self.conn.send(sendData+'\n')
                break
            except:
                print "[Monitor Client Send] Restart monitor socket"
                self.conn.close()
                self.__init__(self.__ip__)

    def close(self):
        closedata = {}
        closedata['type'] = 'disconn'
        try:
            self.send(closedata)
            print "[+] monitorclient close ...."
        except socket.error as e:
            print "[Monitor Client] {}".format(e)
            pass
        self.conn.close()
        

def mutation_wrapping(ch, method, properties, body, manager_wrap, type_seed_files_wrap, resource_files_wrap, inQueue_wrap, req_txt_li, boundary, target):
    if ch.is_open:
        ch.basic_ack(method.delivery_tag)
    mutate_box = rabbitmq.unwrap(body)
    mutate_list = list(mutate_box["mutate_list"])
    #print mutate_list
    mutate_type = mutate_box["type"]
    #type_seed_files_wrap[mutate_type].extend(resource_files_wrap)
    for seed_file in type_seed_files_wrap[mutate_type]:
        #print seed_file
        mut_start = time.time()
        if len(mutate_list) == 0:
          ################### Change here  ######  Add probe request  #####################
            #print seed_file
            mutate_list = []
            mutate_data = manager_wrap.makeMutatedData(mutate_list, seed_file, None)
            #print mutate_data
            mutate_data["filename"] = mutate_data["filename"]+'_SEED'
          ################### Change here  ######  Add probe request  #####################
        else:
            #print seed_file
            mutate_data = manager_wrap.makeMutatedData(mutate_list, seed_file, None)
        
        #print 'filename : ' + mutate_data["filename"]  + '.' + mutate_data['fileext']
        ########################### Generate upload request ###########################
        # print mutate_data['filename']
        # print '[+] mutate_data over...'

        requestSeed = fileuploader.makeUploadRequest(req_txt_li[1], boundary, mutate_data)

        isuploaded = fileuploader.uploadFile(requestSeed, req_txt_li[0], target)
        
        # print "[+] requestseed ..."
        # print requestSeed
        # print isuploaded
        # print "[+] ..."
        # exit()
        
        if mutate_data['fileext'] != None and len(mutate_data['fileext']) > 0:
            file_name = mutate_data['filename']+'.'+mutate_data['fileext']
        else:
            file_name = mutate_data['filename']
        mut_end = time.time()
        mut_time = mut_end - mut_start
        #print file_name
        #print(seed_file)
        inQueue_wrap.put([isuploaded, mutate_data, seed_file, mutate_list, file_name, mutate_type, mut_time])


def mutation(rabbitmq_name, manager, type_seed_files, resource_files, inQueue, req, bound, tar):
    rbQueue = rabbitmq.mqMsgqIo()
    rbQueue.msgqDeclare(rabbitmq_name)
    cb = functools.partial(mutation_wrapping, manager_wrap=manager,
                           type_seed_files_wrap=type_seed_files, resource_files_wrap=resource_files, inQueue_wrap=inQueue,req_txt_li=req, boundary=bound, target=tar)
    rbQueue.workerize(cb)


def verifier(monitorClient, isuploaded, mutate_data, seed_file, mutate_list, file_name):

    if isuploaded[0]: 
        # File Monitor
        if CONF['framework']["monitorEnable"]: 
            # print "[+] mutate_data_content ..."
            # print mutate_data['content']
            # print '[+] ...'
            isvalid = monitorClient.fileValidator(
                file_name, mutate_data['content'])
            if isvalid[0] == True:
                # print "[+] isvalid ..."
                # print isvalid
                # print '[+] ...'
                return [True, mutate_data, seed_file, isvalid[1]['msg'], mutate_list, isvalid[1]['path']]
            else:
                return [False, mutate_data, seed_file, "NOT_CREATED", mutate_list, None]

    else:
        return [False, mutate_data, seed_file, "UPLOAD_FAIL", mutate_list, None]

################################ Mutation operation########################################
def verifier_thread(target, framework, manager, inQueue, rbQueue, opList, req_txt_header, wroot):
    global TotalRequest
    global ProcessedRequest
    global vfy_time
    global mutation_time
    global CONF

    chainCounter = 0
    success_mutation = {}
    PublicSuffixDetection_FailList = []
    PublicSuffixDetection_SuccessList = []
    fail_mutation = []
    result = []

    if framework["monitorEnable"]:
        while True:
            try:
                monitorClient = MonitorClient(
                    framework["monitorHost"], framework["monitorPort"])
            except:
                print "cannot connect to webserver.. try again"
                continue
            break
    
    accessValid = None
    base_url = target["webHost"]
    if base_url[-1] != '/':
        base_url += "/"
    if base_url[:7] != "http://" and base_url[:8] != "https://":
        base_url = "http://"+base_url
    
    # print "[+] monitorClient..."
    # print monitorClient

    print "[+] Connection Succeed"

    if wroot == "":
        conf_response = monitorClient.recv()
        # print "[+] conf_response ... "
        # print conf_response
        if conf_response['rootPath']:
            CONF["target"]['webRootPath'] = conf_response['rootPath'].encode('utf-8')
    else:
        CONF["target"]['webRootPath'] = wroot

    # print "[+] CONF ..."
    # print CONF
    # print "[+] ..."
        
    while True:
        rbQueue.process_data_events()
        if not inQueue.empty():
            data = inQueue.get()
            # print '[+] data...'
            # print data
            # print '[+] ...'
            ProcessedRequest += 1
            vfy_start = time.time()
            seedType = data[5]
            ret = verifier( 
                monitorClient, data[0], data[1], data[2], data[3], data[4])
            mutate_list = ret[4]
            mutation_time += data[6]
            #print 'ret[0] : ' + str(ret[0])
            
            if ret[0] == True:
                # print "[+] ret[5]..."
                # print ret[5]
                # print '[+] ...'
                path = ret[5].replace(target["webRootPath"], "")
                # print path
                url = base_url+path
                
                # print 'url : ' + url
                # print '[+] ...'

                accessValid = fileuploader.accessValidation(
                    target, url, ret[1]["content"], "URadar_Test", seedType, opList, data[1]['filename'], req_txt_header)
                
                # if accessValid[0]:
                #     print "[+] accessValid..."
                #     print accessValid
                #     print '[+] ...'
            else:
                url = ""
                accessValid = [None, None]
            #print success_mutation
            if ((seedType == "php") or (seedType == "js") or (seedType == "html") or (seedType == "xhtml")) and seedType not in success_mutation.keys():
                success_mutation[seedType] = []

            mut_combination = '+'.join(data[3])
            if accessValid[0] and ((seedType == 'js' and accessValid[1] == "Code Exposed") or (seedType == 'php' and (accessValid[1] == "Execution Succeed")) or ((seedType == 'html' or seedType == 'xhtml') and (accessValid[1] == "Code Exposed" or accessValid[1] == "Execution Succeed"))):
                print "Success = [{}] - {}".format(seedType,
                                                   '+'.join(mutate_list))
                if seedType in success_mutation.keys():
                    success_mutation[seedType].append(mutate_list)
                else:
                    success_mutation[seedType] = [mutate_list]
            # PHP PCE - about Extension without M12
            elif seedType == 'php' and (mut_combination != '' and ((accessValid[0] and accessValid[1] == "Code Exposed") or (not accessValid[0] and accessValid[1] == "Forbidden"))):
                print "Success = [{}] - {}".format(seedType,
                                                   '+'.join(mutate_list))
                if seedType in success_mutation.keys():
                    success_mutation[seedType].append(mutate_list)
                else:
                    success_mutation[seedType] = [mutate_list]
            ############################################## Add the test type ################################################################
            elif seedType in opList and accessValid[1] =="File Type Restriction Detection":
                PublicSuffixDetection_SuccessList.append(seedType)
            elif ((seedType != "php") and (seedType != "js") and (seedType != "html") and (seedType != "xhtml")) and ("SEED" in data[1]['filename']):
                #print data[1]['filename']
                PublicSuffixDetection_FailList.append(seedType)
            #############################################################################################################################
            else:
                fail_mutation.append([mutate_list, seedType])        ###Mutation after failure###
            #print fail_mutation
            #print success_mutation
            #print PublicSuffixDetection_SuccessList
            #print PublicSuffixDetection_FailList
            accessValid.append(url)
            accessValid.append(ret)
            result.append(accessValid)
            vfy_end = time.time()
            vfy_time += vfy_end-vfy_start
        else:
            continue

        if TotalRequest == ProcessedRequest:
            if chainCounter > framework['mutationChainLimit']:
                print "[+] Chain counter hits the limit - {}".format(
                    chainCounter)
                break
            else:
                chainCounter += 1

            for ele in fail_mutation:       ############## Set mutation rules ##############
                failed_mutate_ele = '+'.join(ele[0])
                failed_mutate_seed = ele[1]
                append_list = manager.mutation_chain(
                    failed_mutate_ele, failed_mutate_seed, success_mutation[failed_mutate_seed], PublicSuffixDetection_FailList)
                for i in append_list:
                    mutate_box = {}
                    mutate_box["type"] = failed_mutate_seed
                    mutate_box["mutate_list"] = i.split("+")
                    mutate_box_wrapped = rabbitmq.wrap(mutate_box)
                    TotalRequest += 1
                    rbQueue.push(mutate_box_wrapped)
            fail_mutation = []
            print "mutations = {}/{}".format(ProcessedRequest, TotalRequest)
            if TotalRequest == ProcessedRequest:
                break

    return result


def sec2time(second):
    second = int(second)
    sec_ = second % 60
    min_ = second/60
    hour_ = min_/60
    min_ = min_ % 60
    sec_ = "{} sec".format(sec_)
    if min_ != 0:
        min_ = "{} min ".format(min_)
    else:
        min_ = ""
    if hour_ != 0:
        hour_ = "{} hour ".format(hour_)
    else:
        hour_ = ""
    return hour_+min_+sec_


def reporter(results, start_time, mid_time, target, framework, seed_list, seed_report,opList, seedfilename, req_txt_li, report_serial, boundary):
    global SuccessRequest
    pce = {}  # Potencial Code Execution
    ce = {}  # Code Execution
    err = {}

    print "Result Count - {}".format(len(results))

    start = time.time()
    # Determine folder name which is written mutation files that succeed to upload
    folder_name = target["webHost"]
    if folder_name[:7] == "http://":
        folder_name = folder_name[7:]
    elif folder_name[:8] == "https://":
        folder_name = folder_name[8:]

    if "/" in folder_name:
        folder_name = folder_name.split("/")[0]
    if not os.path.isdir(folder_name):
        os.mkdir(folder_name)

    folder_name = folder_name + '/' + folder_name + '_' + str(report_serial)
    if not os.path.isdir(folder_name):
        os.mkdir(folder_name)

    base_url = target["webHost"]
    if base_url[-1] != '/':
        base_url += "/"
    if base_url[:7] != "http://" and base_url[:8] != "https://":
        base_url = "http://"+base_url
    print "[+] Creates the Report...."
    counter = 0
    all_results = len(results)
    for data_ in results:
        if not (data_[0] == None):
            accessValid = data_[0:2]
            url = data_[2]
            i = data_[3]
            seedType = i[2].rsplit(".", 1)[-1]
            if not accessValid[0] and accessValid[1] == "Forbidden" and (seedType == 'php'):
                SuccessRequest += 1
                if seedType not in pce.keys():
                    pce[seedType] = []
                pce[seedType].append((i, url))
            elif accessValid[0] and "M06" in i[4] and (seedType == 'html' or seedType == 'xhtml'):
                SuccessRequest += 1
                if seedType not in ce.keys():
                    ce[seedType] = []
                ce[seedType].append((i, url))
            elif accessValid[0]:
                if accessValid[1] == "Execution Succeed" and (seedType == 'php' or seedType == 'html' or seedType == 'xhtml'):
                    SuccessRequest += 1
                    if seedType not in ce.keys():
                        ce[seedType] = []
                    ce[seedType].append((i, url))
                elif accessValid[1] == "Code Exposed" and (seedType == 'html' or seedType == 'xhtml'):
                    SuccessRequest += 1
                    if seedType not in ce.keys():
                        ce[seedType] = []
                    ce[seedType].append((i, url))
                elif accessValid[1] == "Code Exposed" and (seedType == 'php' or seedType == 'js'):
                    SuccessRequest += 1
                    if seedType not in pce.keys():
                        pce[seedType] = []
                    pce[seedType].append((i, url))
                elif accessValid[1] == "File Type Restriction Detection" and (seedType in opList ):
                    pass
                else:
                    print "something Wrong - [{}, {}] - {}".format(
                        accessValid[0], accessValid[1], i[2].rsplit('.', 1)[-1])
                    if seedType not in err.keys():
                        err[seedType] = []
                    err[seedType].append((i, url))
            else:
                if seedType not in err.keys():
                    err[seedType] = []
                err[seedType].append((i, url))

    end = time.time()
    print "verify_time : {}".format(vfy_time)
    print "Finished headless browser test - {} sec".format(end-start)
    output = "File Upload Vulnerability Detection  Report\n\n"
    output += "[+] Host : {}\n".format(target["webHost"])
    output += "[+] Tried Seed : {}\n".format(', '.join(seed_list))
    output += "[+] Upload Target URL : {}\n".format(target["webUploadURL"])
    # Start
    output += "[+] Total Execution Time : {}\n".format(
        sec2time(end-start_time))
    output += "[+] Preparing Time : {}\n".format(sec2time(mid_time-start_time))
    output += "[+] Average Uploading Time ({} Process) : {}\n".format(
        PROCESS_LIMIT, sec2time(mutation_time/PROCESS_LIMIT))
    output += "[+] Verify Time : {}\n".format(sec2time(vfy_time))
    output += "[+] Tried to Upload File : {}\n".format(TotalRequest)
    output += "[+] Uploaded Files having CE/PCE ability : {}\n\n".format(
        SuccessRequest)

    output += "\n"

    for ceType in ce.keys():
        output += "[+] Found Code Executable Uploaded Files( {} ) - {} files\n".format(
            ceType, len(ce[ceType]))
        for ele in ce[ceType]:
            i = ele[0]
            if i[1]['fileext'] != None and len(i[1]['fileext']) > 0:
                file_name = i[1]['filename']+'.'+i[1]['fileext']
            else:
                file_name = i[1]['filename']
            output += "  Seed({})\t{}:  {}\n".format(
                i[2], '+'.join(i[4]), file_name)
            output += "   -> {}\n".format(ele[1])
            with open("{}/ce_{}".format(folder_name, file_name), "wb") as fp:
                fp.write(i[1]['content'])
        output += "\n"

    for pceType in pce.keys():
        output += "[+] Found Potentially Code Executable Uploaded Files( {} ) - {} files\n".format(
            pceType, len(pce[pceType]))
        for ele in pce[pceType]:
            i = ele[0]
            if i[1]['fileext'] != None and len(i[1]['fileext']) > 0:
                file_name = i[1]['filename']+'.'+i[1]['fileext']
            else:
                file_name = i[1]['filename']
            output += "  Seed({})\t{}:  {}\n".format(
                i[2], '+'.join(i[4]), file_name)
            output += "   -> {}\n".format(ele[1])
            with open("{}/pce_{}".format(folder_name, file_name), "wb") as fp:
                fp.write(i[1]['content'])
        output += "\n"

    for errType in err.keys():
        output += "[-] Upload succeed but not usable ( {} ) - {} files\n".format(
            errType, len(err[errType]))
        for ele in err[errType]:
            i = ele[0]
            if i[1]['fileext'] != None and len(i[1]['fileext']) > 0:
                file_name = i[1]['filename']+'.'+i[1]['fileext']
            else:
                file_name = i[1]['filename']
            output += "  Seed({})\t{}:  {}\n".format(
                i[2], '+'.join(i[4]), file_name)
            output += "   -> {}\n".format(ele[1])
        output += "\n"

    ########### S1 test ############
    # 1. upload .htaccess
    s1request = fileuploader.makeUploadRequest(
        req_txt_li[1], boundary, fileuploader.makeS1Data())
    isS1Uploaded = fileuploader.uploadFile(s1request, req_txt_li[0], target)
    s1Flag = False
    if framework["monitorEnable"]:
        while True:
            try:
                monitorClient = MonitorClient(
                    framework['monitorHost'], framework['monitorPort'])
            except:
                print "cannot connect to webserver.. try again"
                continue
            break

    if isS1Uploaded:
        print ".htaccess uploaded"
        # 2. upload s1 test data
        testdata = fileuploader.makeS1TestData()
        s1TestRequest = fileuploader.makeUploadRequest(req_txt_li[1], boundary, testdata)
        isS1TestUploaded = fileuploader.uploadFile(s1TestRequest, req_txt_li[0], target)
        if isS1TestUploaded[0]:
            print "Test data uploaded"
            # 3. php execution test
            if framework["monitorEnable"]:
                isvalid = monitorClient.fileValidator(
                    testdata["filename"], testdata['content'])
            
            if isvalid[0]:
                print "upload data file created"
                if framework["monitorEnable"]:
                    path = isvalid[1]['path'].replace(
                        target["webRootPath"], "")
                    url = base_url+path
                else:
                    url = base_url+isvalid[1]
                accessValid = fileuploader.accessValidation(
                    target, url, testdata['content'], "URadar_Test", "php", opList, seedfilename, req_txt_li[0])
                if accessValid[0] and accessValid[1] == "Execution Succeed":
                    print "Execution Success"
                    s1Flag = True
    if s1Flag:
        output += "[+] S1 - .htaccess upload success & It works. (Vulnerable!)\n\n"
    else:
        output += "[-] S1 - .htaccess upload fail or It doesn't work (Secure!)\n\n"
        ########### S1+M3_JPG test ############
        # 1. upload .htaccess
        M3_type_list = ['image/jpeg', 'image/png', 'image/gif',
                        'application/zip', 'application/pdf', 'application/x-gzip']
        for mimetype in M3_type_list:
            s1request = fileuploader.makeUploadRequest(
                req_txt_li[1], boundary, fileuploader.makeS1Data(m3_mut=mimetype))
            isS1Uploaded = fileuploader.uploadFile(s1request, req_txt_li[0], target)
            if isS1Uploaded[0]:
                print ".htaccess uploaded"
                # 2. upload s1 test data
                testdata = fileuploader.makeS1TestData()
                s1TestRequest = fileuploader.makeUploadRequest(
                    req_txt_li[1], boundary, testdata)
                # 3. php execution test
                if framework["monitorEnable"]:
                    isvalid = monitorClient.fileValidator(
                        testdata["filename"], testdata['content'])
 
                if isvalid[0]:
                    print "upload data file created"
                    if framework["monitorEnable"]:
                        path = isvalid[1]['path'].replace(
                            target["webRootPath"], "")
                        url = base_url+path
                    accessValid = fileuploader.accessValidation(
                        target, url, testdata['content'], "URadar_Test", "php", opList, seedfilename,req_txt_li[0])
                    if accessValid[0] and accessValid[1] == "Execution Succeed":
                        print "Execution Success"
                        s1Flag = True
                        break
        if s1Flag:
            output += "[+] S1+M3 {} - .htaccess upload success & It works. (Vulnerable!)\n\n".format(
                mimetype)
        else:
            output += "[-] S1+M3 - .htaccess upload fail or It doesn't work (Secure!)\n\n"

    ####################################

    monitorClient.close()

    with open("{}_{}.txt".format(folder_name, "report"), "w") as fp:
        fp.write(output)
    #print output
    print "[!] Report file created - {}_{}.txt\nDone...!".format(
        folder_name, "report")


def startURadar(crawl_req, req, report_num, web_root):
    # origin_req = unquote(req)
    origin_req = req
    print "[+] startURadar {}_{} ...".format(crawl_req, report_num)
    # print "[+] origin_req..."
    print origin_req
    print "..."


    global TotalRequest
    global CONF
    global ProcessedRequest
    global SuccessRequest
    global upload_time
    global vfy_time
    global mutation_time

    TotalRequest = 0
    ProcessedRequest = 0
    SuccessRequest = 0

    upload_time = 0
    vfy_time = 0
    mutation_time = 0

    inQueue = Queue()
    outQueue = Queue()
    rbQueue = rabbitmq.mqMsgqIo()
    rbQname = "mutate_op"
    rbQueue.msgqDeclare(rbQname, True)
    start_time = time.time()

    req_txt_li, boundary, hostUrl, uploadURL = fileuploader.processRequest(origin_req, crawl_req)
    CONF["target"]["webHost"] = hostUrl
    CONF["target"]["webUploadURL"] = uploadURL
    CONF["framework"]["monitorHost"] = hostUrl[7:]

    # print "[+] CONF ..."
    # print CONF
    # print "[+] ..."

    print "[+] Make Mutate List"
    opListCreator = filemutator.mutate_manager()
    #opList = opListCreator.combinatedOpList()

    # Append file path - temp
    seed_files = os.listdir('seed')
    resource_files = os.listdir('resource')
    seed_files = ['seed/' + x for x in seed_files]
    resource_files = ['resource/' + x for x in resource_files]
    seed_files.extend(resource_files)
    opList = []
    for i in seed_files:
        opList.append(i.rsplit('.', 1)[1])
    #print opList
    #total_ops = opList.keys()

    results = []
    mid_time = time.time()
    mutation_length = 0
    seed_result = {}
    pidList = []
    type_seed_files = {}
    for key in opList:  
        type_seed_files[key] = filemutator.get_type_seed_files(key, seed_files)
    while len(pidList) < PROCESS_LIMIT:
        # async
        p = Process(target=mutation, args=(
            rbQname, opListCreator, type_seed_files, resource_files, inQueue, req_txt_li, boundary, CONF['target']))
        p.daemon = True
        p.start()
        pidList.append(p)
    #print opList
    for key in opList:
        mutate_box = {}
        mutate_box["type"] = key
        mutate_box["mutate_list"] = ""
        TotalRequest += 1
        rbQueue.push(rabbitmq.wrap(mutate_box))

    print "[+] Verifier start"
    results = verifier_thread(
        CONF['target'], CONF['framework'], opListCreator, inQueue, rbQueue, opList, req_txt_li[0], web_root)
    print "[+] Finishing Upload Process...."
    while inQueue.qsize() != 0 or not inQueue.empty():
        pass

    while len(pidList) > 0:
        for i in pidList:
            i.terminate()
            i.join()
            pidList.pop(pidList.index(i))
    #end_time = time.time()

    inQueue.close()
    inQueue.join_thread()
    #print results[0][3][1]['filename']
    reporter(results, start_time, mid_time, CONF['target'], CONF['framework'], opList, seed_result, opList, results[0][3][1]['filename'], req_txt_li, report_num, boundary)

    print "[+] EndURadar {}_{} ...".format(crawl_req ,report_num)

    return CONF["target"]["webRootPath"]


if __name__ == "__main__":

    # parameters
    origin_req = """
POST /action/file/upload HTTP/1.1
Host: 192.168.100.130
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:56.0) Gecko/20100101 Firefox/56.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=---------------------------21124170022524
Content-Length: 6093
Referer: http://192.168.100.130/file/add/36
Cookie: Elgg=aismcgjlfrrgaan82kin008kk5
Connection: close
Upgrade-Insecure-Requests: 1

-----------------------------21124170022524
Content-Disposition: form-data; name="__elgg_token"

ITqk85qh0CMHsIGcuqvBzw
-----------------------------21124170022524
Content-Disposition: form-data; name="__elgg_ts"

1655205357
-----------------------------21124170022524
Content-Disposition: form-data; name="upload"; filename="1.png"
Content-Type: image/png

-----------------------------21124170022524
Content-Disposition: form-data; name="title"


-----------------------------21124170022524
Content-Disposition: form-data; name="description"


-----------------------------21124170022524
Content-Disposition: form-data; name="tags"


-----------------------------21124170022524
Content-Disposition: form-data; name="access_id"

2
-----------------------------21124170022524
Content-Disposition: form-data; name="container_guid"

36
-----------------------------21124170022524
Content-Disposition: form-data; name="file_guid"


-----------------------------21124170022524--
"""
    crawl_req = "http://192.168.100.130/action/file/upload"
    web_root = "/var/www/html/elgg-2.3.10/"
    web_root = startURadar(crawl_req,origin_req, 1, web_root)
 

    
