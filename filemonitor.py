from random import seed
import sys
import pyinotify
import json
import socket
import threading
import atexit
import time
import hashlib
import os
import extListExtractor

# MONITOR_PATH='/var/www/html/wordpress/'
MONITOR_PORT= 20174           # Default value for test
EVENT_LIST_LIMITATION=8000
EVENT_LIST = []

#Debug = True
Debug = False

# Todo - Daemonize communication module

class FileEventHandler(pyinotify.ProcessEvent):
  def __init__(self):
    self.mutex = threading.Lock()

  def process_IN_ATTRIB(self,event):
    if Debug:
      print "[IN_ATTRIB] {}".format(event.pathname)
    self.mutex.acquire()
    if len(EVENT_LIST)>=EVENT_LIST_LIMITATION:
      for i in range(0,len(EVENT_LIST)-EVENT_LIST_LIMITATION+1):
        EVENT_LIST.remove(EVENT_LIST[0])
      if Debug:
        print "[!] EVENT_LIST Removed - {}".format(len(EVENT_LIST))
    if os.path.isdir(event.pathname):
      pass
    else:
      try:
        with open(event.pathname, 'r') as fp:
          binary = fp.read()
          #print binary
          tmpList = [event.pathname,hashlib.md5(binary).hexdigest()]
        if tmpList not in EVENT_LIST and os.path.isfile(event.pathname):
          EVENT_LIST.append([event.pathname,hashlib.md5(binary).hexdigest()])
          #EVENT_LIST.append([event.pathname,hashlib.md5(binary).hexdigest()])
        if Debug:
          print "[!] Appended - ({}){}".format(hashlib.md5(binary).hexdigest(),event.pathname)
      except:
        pass
    self.mutex.release()

  def process_IN_CREATE(self,event):
    self.mutex.acquire()
    print "[+] new file create ..."
    print event
    print "[+] ..."

    if Debug:
      print "[IN_CREATE] {}".format(event.pathname)
    if len(EVENT_LIST)>=EVENT_LIST_LIMITATION:
      for i in range(0,len(EVENT_LIST)-EVENT_LIST_LIMITATION+1):
        EVENT_LIST.remove(EVENT_LIST[0])
      if Debug:
        print "[!] EVENT_LIST Removed - {}".format(len(EVENT_LIST))
    if os.path.isdir(event.pathname):
      pass
    else:
      try:
        with open(event.pathname, 'r') as fp:
          binary = fp.read()
          tmpList = [event.pathname,hashlib.md5(binary).hexdigest()]
        #print binary
        if tmpList not in EVENT_LIST and os.path.isfile(event.pathname):
          EVENT_LIST.append([event.pathname,hashlib.md5(binary).hexdigest()])
          print "[!] Appended - ({}){}".format(hashlib.md5(binary).hexdigest(),event.pathname)
        if Debug:
          print "[!] Appended - ({}){}".format(hashlib.md5(binary).hexdigest(),event.pathname)
      except Exception as e:
        print 'except:', e
        pass
    self.mutex.release()

class EventCommunicator(object):
  def __init__(self,ip,port):
    self.host = ip
    self.port = port
    return
  def connWait(self):
    self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    self.server.bind((self.host,self.port))
    self.server.listen(5)
    self.conn, self.addr = self.server.accept()
    # print "conn:",conn
  def recv(self):
    recvData = ""
    try:
      while True:
        recvDataPart = self.conn.recv(10)
        if not recvDataPart or len(recvDataPart)==0:
          break
        elif '\n' in recvDataPart:
          recvData += recvDataPart
          break
        recvData += recvDataPart
    except:
      print "Error occured during recieving command"
      return None
    if Debug:
      print "[RECV] {}".format(recvData)
    print "recvData: ", recvData
    try:
      retData = json.loads(recvData)
    except:
      print "Error occured during parsing recieved command"
      return None
    return retData
  def send(self,data):
    sendData = json.dumps(data)
    self.conn.send(sendData+'\n')
  def close(self):
    self.conn.close()

def eventMonitor(path):
  monitorObj = pyinotify.WatchManager()
  monitorObj.add_watch(path,pyinotify.ALL_EVENTS, rec=True, auto_add=True)

  eventHandler = FileEventHandler()

  notifier = pyinotify.Notifier(monitorObj, eventHandler)
  notifier.loop()

def extract_content(path):
  try:
    with open(path, "rb") as f:
      content = f.read()
    return content
  except:
    return " "

def connectionThread(connObj):
  mutex = threading.Lock()
  while connObj:
    cmd = connObj.recv()
    print "[+] cmd ..."
    print cmd
    print "[+] ..."
    ret_msg = {}
    try:
      type_ = cmd["type"]
      if type_  == 'disconn':
        if mutex.test():
          mutex.release()
        connObj.close()
        print "[+] filemonitor close ...."
        return
      filename = cmd["filename"]
      ext = cmd["ext"]
      filehash = cmd["filehash"]
      if Debug:
        print "[!] Parsed - filename : {}".format(filename)
        print "[!] Parsed - ext : {}".format(ext)
        print "[!] Parsed - filehash : {}".format(filehash)
    except:
      ret_msg["msg"] = "Wrong Command..."
      ret_msg["type"] = "Error"
      connObj.send(json.dumps(ret_msg))
      continue
    mutex.acquire()
    ListedFile=[]
    Listhash=[]
    for i in EVENT_LIST:
      print "EVENT_LIST:", i[0], i[1]
      mutate_data = extract_content(i[0])
      #print hashlib.md5(mutate_data).hexdigest()
      Listhash.append(hashlib.md5(mutate_data).hexdigest())
      ListedFile.append(i[0].split('/')[-1])
      if Debug:
        
        print "[~] Comparing hash.. {} - {}".format(filehash, Listhash)
        print "[~] Comparing hash.. {} - {}" . format(filehash, Listhash) 
        #print "[~] Comparing.. {} - {}".format(filename, ListedFile)
      
      # print "ListedFile: ",ListedFile
      # print "Listhash: " ,Listhash
      # isExist = False
      # for name in ListedFile:
      #   if filename in name:
      #     isExist = True
      #     break
      # if isExist:
      if filename in ListedFile:
        if ext and filehash in Listhash:
          ret_msg["msg"] = "Exactly Matched"
          ret_msg["type"] = "Exist"
          ret_msg["path"] = i[0]
          ret_msg["hash"] = filehash
          EVENT_LIST.remove(i)
          break
        elif not ext:
          ret_msg["msg"] = "Exactly Matched"
          ret_msg["type"] = "Exist"
          ret_msg["path"] = i[0]
          ret_msg["hash"] = filehash
          EVENT_LIST.remove(i)
          break
      if Debug:
        print "[~] Comparing.. {} - {}".format(i[1], filehash)
      
      # print "filehash:", filehash
      # print "i1:",i[1]
      if i[1] == filehash:
        # print "i[1] == filehash"
        ret_msg["msg"] = "Exactly Matched"
        ret_msg["type"] = "Exist"
        ret_msg["path"] = i[0]
        ret_msg["hash"] = filehash
        EVENT_LIST.remove(i)
        break
    if Debug:
      if len(ret_msg.keys())!=0:
        print "[~] Result : {} - {}".format(filename,ret_msg["msg"])
      else:
        print "[~] Result : {} - Fail".format(filename)

    mutex.release()

    # print "ret_msg", ret_msg
    if len(ret_msg.keys()) == 0:
      ret_msg["msg"] = "Fail to find file"
      ret_msg["type"] = "Fail"
    else:
      # print "ret_msg", ret_msg["path"]
      if not os.path.isfile(ret_msg["path"]):
        # print "not file"
        ret_msg = {}
        ret_msg["msg"] = "Fail to find file"
        ret_msg["type"] = "Fail"
    #print ret_msg
    connObj.send(json.dumps(ret_msg))

def readApacheConf():
    conf_path = '/etc/apache2/sites-enabled' # ubuntu apache
    filesname = os.listdir(conf_path)
    conf_name = ''
    for fname in filesname:
        # print fname
        if '.conf' in fname:
            conf_name = '/' + fname
            break
    conf_path += conf_name
    doc_root_line = ''
    with open(conf_path) as file_obj:
        lines = file_obj.readlines()
        for line in lines:
            if '#' not in line and 'DocumentRoot' in line:
                doc_root_line = line
                break
    # print doc_root_line
    doc_root = doc_root_line.split()[1].strip()
    if doc_root[-1] != '/':
      doc_root += '/'
    return doc_root

def sendRootPath(connObj, root_path, sameExtsClasses, classArrays, extArraysList):
    ret_msg = {}
    ret_msg['rootPath'] = root_path
    ret_msg['sameExtsClasses'] =sameExtsClasses
    ret_msg['classArrays'] = classArrays
    ret_msg['extArraysList'] = extArraysList
    connObj.send(json.dumps(ret_msg))
    print root_path
    print "Rootpath sended!"


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


if __name__ == '__main__':
  # 0. root_path: give parameter or read apache conf
  if len(sys.argv)>1:
    root_path = sys.argv[1]
  else:
    root_path = readApacheConf()
  firstconnect = True
  print "root_path:", root_path

  start_time = time.time()
  sameExtsClasses, classArrays, extArraysList = extListExtractor.ExtractSameExtList(root_path)
  end_time = time.time()
  # print "extArraysList:"
  # print extArraysList
  for i in range(0,len(extArraysList)):
        print i,':',extArraysList[i]
  # print "sameExtsClasses: classArrays"
  # for i in range(0, len(sameExtsClasses)):
  #       print sameExtsClasses[i],': ', classArrays[i]

  print "[+] Execution Time : {}\n".format(end_time-start_time)
  print "[+] Extraction Execution Time : {}\n".format(sec2time(end_time-start_time))

  # 1. run monitor thread
  print "Start Event Monitor Thread"
  t = threading.Thread(target = eventMonitor,args=(root_path,))
  t.daemon = True
  t.start()

  # 2. connect with client
  while True:
    print "Connection with client"
    connObj = EventCommunicator('0.0.0.0',MONITOR_PORT)
    connObj.connWait()
    if firstconnect:
      sendRootPath(connObj, root_path, sameExtsClasses, classArrays, extArraysList)
      firstconnect = False
    tc = threading.Thread(target=connectionThread, args=(connObj,))
    tc.start()
    tc.join()