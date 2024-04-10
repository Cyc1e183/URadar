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
import extListExtractor
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
        # print "[+] sendData ..."
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
        
        # print recvData
        
        try:
            retData = json.loads(recvData)
        except:
            print "[-] Error occured during parsing recieved command"
            return None
        return retData

    def send(self, data):
        sendData = json.dumps(data)
        # print "sendData:", sendData

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
def verifier_thread(target, framework, manager, inQueue, rbQueue, opList, req_txt_header, wroot, wholeBlack, wholeWhite):
    global TotalRequest
    global ProcessedRequest
    global vfy_time
    global mutation_time
    global CONF

    chainCounter = 0
    success_mutation = {}
    PublicSuffixDetection_FailList = []
    PublicSuffixDetection_SuccessList = []
    mimeres = False
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
            #elif seedType in opList and accessValid[1] =="File Type Restriction Detection":
            #    PublicSuffixDetection_SuccessList.append(seedType)
            #elif ((seedType != "php") and (seedType != "js") and (seedType != "html") and (seedType != "xhtml")) and ("SEED" in data[1]['filename']):
            #    #print data[1]['filename']
            #    PublicSuffixDetection_FailList.append(seedType)
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
                    failed_mutate_ele, failed_mutate_seed, success_mutation[failed_mutate_seed], wholeBlack, wholeWhite, mimeres)
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
    print "[!] Report file created - {}_{}.txt\nDone...!".format(folder_name, "report")

def detectWhiteOrBlack(monitorClient, req_txt_li, boundary, target, sameExtsClasses, sameClassIndexesList, extArraysList, remove_req_txt_li):
    # seed files need to detect
    seed_files = os.listdir('seed')
    resource_files = os.listdir('resource')
    new_files = os.listdir('newfiles')
    seed_files = ['seed/' + x for x in seed_files]
    resource_files = ['resource/' + x for x in resource_files]
    new_files = ['newfiles/' + x for x in new_files]
    seed_files.extend(resource_files)
    seed_files.extend(new_files)

    base_url = target["webHost"]
    if base_url[-1] != '/':
        base_url += "/"
    if base_url[:7] != "http://" and base_url[:8] != "https://":
        base_url = "http://"+base_url
    
    whiteSameIndexs, blackSameIndexs, uploadNum1 = detectSameIs(monitorClient, seed_files, base_url, sameExtsClasses, req_txt_li, boundary, target, extArraysList, remove_req_txt_li)

    possibleWhiteListIndexes = []
    possibleBlackListIndexes = []
    for sameindex in whiteSameIndexs:
        possibleWhiteListIndexes.extend(sameClassIndexesList[sameindex])
    for sameindex1 in blackSameIndexs:
        possibleBlackListIndexes.extend(sameClassIndexesList[sameindex1])
    print "possibleWhiteListIndexes:", possibleWhiteListIndexes
    print "possibleBlackListIndexes:", possibleBlackListIndexes

    whiteList = []
    # print "detecting whiteLists"
    differExtsClasses = extListExtractor.ExtractDifferExtList(possibleWhiteListIndexes, extArraysList)
    # print "differExtsClasses:"
    # for d in differExtsClasses:
    #     print d
    # print "differExtsClasses in indentifyWhiteList:"
    whiteListIndex, uploadNum2 = identifyWhiteList(True, differExtsClasses, possibleWhiteListIndexes, monitorClient, seed_files, base_url, req_txt_li, boundary, target, remove_req_txt_li)
    # print "whiteListIndex: ", whiteListIndex
    # print "nodifferExtsClasses in indentifyWhiteList:"
    # if len(whiteListIndex) > 0:
    if True:
        noDifferExtsClasses = []
        noDifferClassIndexes = []
        for i in range(0, len(differExtsClasses)):
            emptyDiffer = differExtsClasses[i]
            if len(emptyDiffer) == 0:
                emptyDifferClassIndex = possibleWhiteListIndexes[i]
                noDifferExtsClasses.append(extArraysList[emptyDifferClassIndex])
                noDifferClassIndexes.append(emptyDifferClassIndex)
        # print "noDifferExtsClasses:", noDifferExtsClasses
        whiteListIndex1, uploadNum3 = identifyWhiteList(True, noDifferExtsClasses, noDifferClassIndexes, monitorClient, seed_files, base_url, req_txt_li, boundary, target, remove_req_txt_li)
        if len(whiteListIndex1) > 0:
            whiteListIndex.extend(whiteListIndex1)
    # print "whiteListIndex: ", whiteListIndex
    
    for c_index in whiteListIndex:
        whiteList.append(extArraysList[c_index])

    print "detecting blackLists"
    blackList = []
    print "differExtsClasses in indentifyBlackList:"
    differExtsClasses = extListExtractor.ExtractDifferExtList(possibleBlackListIndexes, extArraysList)
    blackListIndex, uploadNum4 = identifyWhiteList(False, differExtsClasses, possibleBlackListIndexes, monitorClient, seed_files, base_url, req_txt_li, boundary, target, remove_req_txt_li)
    print "blackListIndex: ", blackListIndex
    print "nodifferExtsClasses in indentifyBlackList:"
    # if blackListIndex == -1:
    if True:
        noDifferExtsClasses = []
        noDifferClassIndexes = [] 
        for i in range(0, len(differExtsClasses)):
            emptyDiffer = differExtsClasses[i]
            if len(emptyDiffer) == 0:
                # print "emptyDiffer:", i
                emptyDifferClassIndex = possibleBlackListIndexes[i]
                noDifferExtsClasses.append(extArraysList[emptyDifferClassIndex])
                noDifferClassIndexes.append(emptyDifferClassIndex)
        print "noDifferExtsClasses:", noDifferExtsClasses
        blackListIndex1, uploadNum5 = identifyWhiteList(False, noDifferExtsClasses, noDifferClassIndexes, monitorClient, seed_files, base_url, req_txt_li, boundary, target, remove_req_txt_li)
        if len(blackListIndex1) > 0:
            blackListIndex.extend(blackListIndex1)

    for c_index1 in blackListIndex:
        blackList.append(extArraysList[c_index1])
    print "blackListIndex: ", blackListIndex

    uploadNum = uploadNum1 + uploadNum2 + uploadNum3 + uploadNum4 +uploadNum5

    return whiteList, blackList, uploadNum


def identifyWhiteList(isWhite, differExtsClasses, clssesIndexList, monitorClient, seed_files, base_url, req_txt_li, boundary, target, remove_req_txt_li):
    # print "differExtsClasses in indentifyWhiteList:"
    # for i in range(0,len(differExtsClasses)):
    #     print i,':',differExtsClasses[i]
    # print "seed_files:", seed_files
    # whiteListIndex = -1
    uploadNum = 0
    whiteListIndex = []
    for i in range(0, len(differExtsClasses)):
        opList = []
        if len(differExtsClasses[i])>0:
            print clssesIndexList[i], ':', differExtsClasses[i]
            for ext in differExtsClasses[i]:
                if len(ext) and ext[0] ==".":
                    ext = ext[1:]
                if "'" in ext or '"' in ext or len(ext.strip())==0:
                    continue
                else:
                    opList.append(ext)
            # print "opList:", opList
            type_seed_files = {}
            for key in opList:  
                type_seed_files[key] = filemutator.get_type_seed_files(key, seed_files)
            print "type_seed_files:", type_seed_files

            isAllExts = 1
                        
            for key in type_seed_files:
                currentExtFlag = 0
                for seed_file in type_seed_files[key]:
                    accessValid = uploadFileAccessValid(monitorClient, seed_file, base_url, req_txt_li, boundary, target, opList, key, remove_req_txt_li)
                    uploadNum += 1
                    if accessValid[0]:
                        currentExtFlag = 1
                        break
                if isWhite and currentExtFlag == 0: # accessValid: false
                    print "not white"
                    isAllExts = 0
                    break
                elif not isWhite and currentExtFlag == 1:  # accessValid: true
                    print "not black"
                    print key
                    isAllExts = 0
                    break

            if isAllExts == 1:
                whiteListIndex.append(clssesIndexList[i])

    # print "whiteListIndex: ", whiteListIndex
    return whiteListIndex, uploadNum

def detectSameIs(monitorClient, seed_files, base_url, sameExtsClasses, req_txt_li, boundary, target, extArraysList, remove_req_txt_li):

    print("detectSameIs:")
    blackSameIndexs = []
    whiteSameIndexs = []
    # for eachSameList in sameExtsClasses: # for each sameExtClass
    uploadNum = 0
    for sameIndex in range(0, len(sameExtsClasses)):
        eachSameList = sameExtsClasses[sameIndex]
        print(sameIndex, ':', eachSameList)
        
        opList = []
        for ext in eachSameList:
            if ext[0] ==".":
                ext = ext[1:]
            opList.append(ext)
        # print "opList:", opList       
        type_seed_files = {}
        for key in opList:  
            type_seed_files[key] = filemutator.get_type_seed_files(key, seed_files)
        print "type_seed_files:", type_seed_files
        
        # data = [isuploaded, mutate_data, seed_file, mutate_list, file_name, mutate_type, mut_time]

        isFlagList = 0 # samelist is: 0 init | 1 white | 2 black
        for key in type_seed_files:
            currentExtFlag = 0 # 0 init | 1 white | 2 black
            for seed_file in type_seed_files[key]:
                accessValid = uploadFileAccessValid(monitorClient, seed_file, base_url, req_txt_li, boundary, target, opList, key, remove_req_txt_li)
                uploadNum += 1
                if accessValid[0]:
                    currentExtFlag = 1
                    break
                
            if currentExtFlag == 0:
                currentExtFlag = 2
            if isFlagList == 0:
                isFlagList = currentExtFlag
            elif isFlagList != currentExtFlag:
                isFlagList = 0
                print "exts in SameClass[", sameIndex, "]are different"
                break
        
        if isFlagList == 1:
            whiteSameIndexs.append(sameIndex)
        elif isFlagList == 2:
            blackSameIndexs.append(sameIndex)
    
    return whiteSameIndexs, blackSameIndexs, uploadNum

def uploadFileAccessValid(monitorClient, seed_file, base_url, req_txt_li, boundary, target, opList, key, remove_req_txt_li):
    manager_wrap = filemutator.mutate_manager()
    mutate_list = []
    mutate_data = manager_wrap.makeMutatedData(mutate_list, seed_file, None)
    #print mutate_data
    mutate_data["filename"] = mutate_data["filename"]+'_SEED'
    requestSeed = fileuploader.makeUploadRequest(req_txt_li[1], boundary, mutate_data)
    isuploaded = fileuploader.uploadFile(requestSeed, req_txt_li[0], target)

    # print "isuploaded: ", isuploaded
                
    if mutate_data['fileext'] != None and len(mutate_data['fileext']) > 0:
        file_name = mutate_data['filename']+'.'+mutate_data['fileext']
    else:
        file_name = mutate_data['filename']
    if isuploaded[0]: 
        # time.sleep(5)
        # File Monitor
        if CONF['framework']["monitorEnable"]: 
            # print "[+] mutate_data_content ..."
            # print mutate_data['content']
            # print '[+] ...'
            # print "filename: ", file_name

            isvalid = monitorClient.fileValidator(file_name, mutate_data['content'])
            
            if isvalid[0] == True:
                # print "[+] isvalid ..."
                # print isvalid[0]
                # print '[+] ...'
                ret = [True, mutate_data, seed_file, isvalid[1]['msg'], mutate_list, isvalid[1]['path']]
                path = ret[5].replace(target["webRootPath"], "")
                # print path
                url = base_url+path   
                # print 'url : ' + url
                # print '[+] ...'

                accessValid = fileuploader.accessValidation(
                    target, url, ret[1]["content"], "URadar_Test", key, opList, mutate_data["filename"], req_txt_li[0])
                print "[+] accessValid...",accessValid[0]
                print '[+] ...'
                if target["removeURL"] != "" and accessValid[0]:
                    remove_res = removefile(isuploaded[1], remove_req_txt_li, boundary, target)
                return accessValid            
                # if accessValid[0]:
                #     print "[+] accessValid..."
                #     print accessValid
                #     print '[+] ...'

            else:
                # print "False,", mutate_data, seed_file, "NOT_CREATED", mutate_list, None
                print "[+] isvalid: ",isvalid
                return [False, mutate_data, seed_file, "NOT_CREATED", mutate_list, None]
    else:
        # print "False", mutate_data, seed_file, "UPLOAD_FAIL", mutate_list, None
        return [False, mutate_data, seed_file, "UPLOAD_FAIL", mutate_list, None]

def removefile(upload_suc_res, remove_req_txt, boundary, target): 
    pattern = re.compile("Post.removeAttachment\([0-9]+\)")
    id_strs = pattern.findall(upload_suc_res)
    file_ids = []
    for s in id_strs:
        id_str = s.rsplit(")",1)[0].rsplit("(",1)[1]
        id = int(id_str)
        file_ids.append(id)
    # print "file_ids: ", file_ids
    for fid in file_ids:
        remove_res = fileuploader.makeRemoveRequest(fid, remove_req_txt, boundary, target)
    return remove_res
            

def startURadar(crawl_req, req, report_num, web_root, sameExtsClasses, remove_ori_req):
    # origin_req = unquote(req)
    origin_req = req
    # print "[+] startURadar {}_{} ...".format(crawl_req, report_num)
    # print "[+] origin_req..."
    # print origin_req
    # print "..."

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

    remove_req_txt_li = []
    removeURL = ""
    if remove_ori_req != "":
        remove_req_txt_li, temp1, temp2, removeURL = fileuploader.processRequest(remove_ori_req, crawl_req)

    CONF["target"]["webHost"] = hostUrl
    CONF["target"]["webUploadURL"] = uploadURL
    CONF["framework"]["monitorHost"] = hostUrl[7:]
    CONF["target"]["removeURL"] = removeURL

    # print "monitorHost:", CONF["framework"]["monitorHost"]

    if CONF["framework"]["monitorEnable"]:
        while True:
            try:
                monitorClient = MonitorClient(
                    CONF["framework"]["monitorHost"], CONF["framework"]["monitorPort"])
            except BaseException as e:
                print "cannot connect to webserver.. try again"
                print e
                continue
            break

    print "[+] Connection Succeed"

    if web_root == "":
        conf_response = monitorClient.recv()
        # print conf_response 
        # print(type(conf_response))
        # conf_response = json.load(conf_re)
        # print "[+] conf_response ... "
        # print conf_response
        if conf_response['rootPath']:
            CONF["target"]['webRootPath'] = conf_response['rootPath'].encode('utf-8')
    else:
        CONF["target"]['webRootPath'] = web_root
    
    # print "conf:", CONF
    
    sameExtsClasses = conf_response['sameExtsClasses']
    extArraysList = conf_response['extArraysList']
    sameClassIndexesList = conf_response['classArrays']
    print "extArraysList:"
    for i in range(0,len(extArraysList)):
            print i,':',extArraysList[i]
    print "sameExtsClasses: sameClassIndexesList"
    for i in range(0, len(sameExtsClasses)):
            print i, sameExtsClasses[i],': ', sameClassIndexesList[i]
    
    # start_time1 = time.time()
        
    whiteList, blackList, uploadNum = detectWhiteOrBlack(monitorClient, req_txt_li, boundary, CONF['target'], sameExtsClasses, sameClassIndexesList, extArraysList, remove_req_txt_li)
    # whiteList, blackList, uploadNum = detectWhiteOrBlack(monitorClient, req_txt_li, boundary, CONF['target'], [['png','jpg','gif', 'jpeg']], [[0]], [['png','jpg','gif', 'jpeg']], remove_req_txt_li)

    end_time = time.time()

    print "whiteList:"
    for w in whiteList:
        print w
    print "blackList"
    for b in blackList:
        print b

    wholeWhite = []
    for w in whiteList:
        for ext in w:
            if wholeWhite.count(ext)==0:
                wholeWhite.append(ext)
    print "wholeWhite: ", wholeWhite

    wholeBlack = []
    for w in blackList:
        for ext in w:
            if wholeBlack.count(ext)==0:
                wholeBlack.append(ext)
    print "wholeBlack: ", wholeBlack
    print "uploadNum: ", uploadNum

    print (end_time-start_time)
    print "[+] Detection Execution Time : {}\n".format(sec2time(end_time-start_time))
    # print "[+] Pure Detection Execution Time : {}\n".format(sec2time(end_time-start_time1))


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
    opList = []
    for i in seed_files:
        opList.append(i.rsplit('.', 1)[1])

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
        CONF['target'], CONF['framework'], opListCreator, inQueue, rbQueue, opList, req_txt_li[0], web_root, wholeBlack, wholeWhite)
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
POST /node/add/article?element_parents=field_image/widget/0&ajax_form=1&_wrapper_format=drupal_ajax HTTP/1.1
Host: 172.16.245.141
Content-Length: 5953
Accept: application/json, text/javascript, */*; q=0.01
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryBAqN4r2k3BTJShNu
Origin: http://172.16.245.141
Referer: http://172.16.245.141/node/add/article
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: SESS1effb5724ad177793b4282dfced9bc61=kVuDQ6CUo2odEcDCa5YumAKnbmWb-navuc5joeDaOJg
Connection: close

------WebKitFormBoundaryBAqN4r2k3BTJShNu
Content-Disposition: form-data; name="changed"

1669645990
------WebKitFormBoundaryBAqN4r2k3BTJShNu
Content-Disposition: form-data; name="title[0][value]"


------WebKitFormBoundaryBAqN4r2k3BTJShNu
Content-Disposition: form-data; name="form_build_id"

form-LXyqAyJXIQ-kHRQLXuqy3SPhcYFWlqOXRS3bPqwq6tQ
------WebKitFormBoundaryBAqN4r2k3BTJShNu
Content-Disposition: form-data; name="form_token"

YJojoyQHjKE8gXbeKC3hhHapFLabwvHo-Cu1wWpCpVo
------WebKitFormBoundaryBAqN4r2k3BTJShNu
Content-Disposition: form-data; name="form_id"

node_article_form
------WebKitFormBoundaryBAqN4r2k3BTJShNu
Content-Disposition: form-data; name="body[0][summary]"


------WebKitFormBoundaryBAqN4r2k3BTJShNu
Content-Disposition: form-data; name="body[0][value]"


------WebKitFormBoundaryBAqN4r2k3BTJShNu
Content-Disposition: form-data; name="body[0][format]"

basic_html
------WebKitFormBoundaryBAqN4r2k3BTJShNu
Content-Disposition: form-data; name="field_tags[target_id]"


------WebKitFormBoundaryBAqN4r2k3BTJShNu
Content-Disposition: form-data; name="files[field_image_0]"; filename="q4.png"
Content-Type: image/png

@file
------WebKitFormBoundaryBAqN4r2k3BTJShNu
Content-Disposition: form-data; name="field_image[0][fids]"


------WebKitFormBoundaryBAqN4r2k3BTJShNu
Content-Disposition: form-data; name="field_image[0][display]"

1
------WebKitFormBoundaryBAqN4r2k3BTJShNu
Content-Disposition: form-data; name="revision_log[0][value]"


------WebKitFormBoundaryBAqN4r2k3BTJShNu
Content-Disposition: form-data; name="menu[title]"


------WebKitFormBoundaryBAqN4r2k3BTJShNu
Content-Disposition: form-data; name="menu[description]"


------WebKitFormBoundaryBAqN4r2k3BTJShNu
Content-Disposition: form-data; name="menu[menu_parent]"

main:
------WebKitFormBoundaryBAqN4r2k3BTJShNu
Content-Disposition: form-data; name="menu[weight]"

0
------WebKitFormBoundaryBAqN4r2k3BTJShNu
Content-Disposition: form-data; name="comment[0][status]"

2
------WebKitFormBoundaryBAqN4r2k3BTJShNu
Content-Disposition: form-data; name="path[0][alias]"


------WebKitFormBoundaryBAqN4r2k3BTJShNu
Content-Disposition: form-data; name="uid[0][target_id]"

admin (1)
------WebKitFormBoundaryBAqN4r2k3BTJShNu
Content-Disposition: form-data; name="created[0][value][date]"

2022-11-28
------WebKitFormBoundaryBAqN4r2k3BTJShNu
Content-Disposition: form-data; name="created[0][value][time]"

06:33:10
------WebKitFormBoundaryBAqN4r2k3BTJShNu
Content-Disposition: form-data; name="promote[value]"

1
------WebKitFormBoundaryBAqN4r2k3BTJShNu
Content-Disposition: form-data; name="status[value]"

1
------WebKitFormBoundaryBAqN4r2k3BTJShNu
Content-Disposition: form-data; name="_triggering_element_name"

field_image_0_upload_button
------WebKitFormBoundaryBAqN4r2k3BTJShNu
Content-Disposition: form-data; name="_triggering_element_value"

Upload
------WebKitFormBoundaryBAqN4r2k3BTJShNu
Content-Disposition: form-data; name="_drupal_ajax"

1
------WebKitFormBoundaryBAqN4r2k3BTJShNu
Content-Disposition: form-data; name="ajax_page_state[theme]"

seven
------WebKitFormBoundaryBAqN4r2k3BTJShNu
Content-Disposition: form-data; name="ajax_page_state[theme_token]"

Y49vz3QSCRPK_GMjEIPUrLcuQJg26eqXLCzBMNoqNts
------WebKitFormBoundaryBAqN4r2k3BTJShNu
Content-Disposition: form-data; name="ajax_page_state[libraries]"

big_pipe/big_pipe,ckeditor/drupal.ckeditor,ckeditor/drupal.ckeditor.plugins.drupalimagecaption,classy/base,classy/image-widget,classy/messages,comment/drupal.comment,contextual/drupal.contextual-links,contextual/drupal.contextual-toolbar,core/drupal.active-link,core/drupal.autocomplete,core/drupal.collapse,core/drupal.states,core/html5shiv,core/jquery.form,core/normalize,file/drupal.file,filter/drupal.filter,menu_ui/drupal.menu_ui,node/drupal.node,path/drupal.path,seven/global-styling,seven/node-form,shortcut/drupal.shortcut,text/drupal.text,toolbar/toolbar,toolbar/toolbar.escapeAdmin,tour/tour,user/drupal.user.icons
------WebKitFormBoundaryBAqN4r2k3BTJShNu--

"""

    remove_ori_req = """"""

    crawl_req = "http://172.16.245.141"
    web_root = ""
    # sameExtsClasses = [['embed', 'icon', 'input', 'json', 'output', 'resources', 'xml'], ['php', 'tag', 'total'], ['html'], ['gif', 'jpeg', 'png', 'wbmp', 'xbm'], ['css', 'fake', 'js', 'text', 'text']]
    sameExtsClasses = []
    web_root = startURadar(crawl_req,origin_req, 1, web_root, sameExtsClasses, remove_ori_req)
