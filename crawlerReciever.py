from multiprocessing import Process, Queue
import socket
import base64
from framework import startURadar
from urllib import unquote

# def main():
#     server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
#     server_socket.bind(("0.0.0.0", 1122))
#     server_socket.listen(128)
#     while True:
#         client_socket, clien_cAddr = server_socket.accept()
#         # print ("client_socket:\n", client_socket)
#         # # print ("clien_cAddr", clien_cAddr)
#         # print ("client_socket.recv\n", client_socket.recv(10240))

#         handle_client(client_socket)

def handle_client(client_socket):
    recv_data = bytes()
    while True:
        recvDataPart = client_socket.recv(1024)
        recv_data += recvDataPart
        if len(recvDataPart) < 1024:
            break
    if not recv_data:
        return False, "", ""
    
    recv_data = recv_data.decode('utf-8', errors="ignore")
    # recv_data = client_socket.recv(1024).decode('utf-8', errors="ignore")
    # print "[+] recv_data [] ..."
    # print recv_data
    # print "[+] ... recv_data"

    if "raw=" not in recv_data or "url=" not in recv_data:
        return False, "", ""
    else:
        b64content = recv_data.split("url=",1)[1].split("&raw=",1)
        b64url = b64content[0].strip()
        b64req = b64content[1].strip()
        if b64url == "" or b64req == "":
            return False, "", ""

        crawl_url = base64.b64decode(unquote(b64url))
        crawl_req = base64.b64decode(unquote(b64req))

        if 'crawlerEnd' in crawl_req:
            # print "return: True,", crawl_url, crawl_req
            return True, crawl_url, crawl_req
        else:
            # print "return: False,", crawl_url, crawl_req
            return False, crawl_url, crawl_req

    # print ("******************************************")
    # response = "HTTP/1.1 200 OK\r\n"
    # response += "Content-Type:text/html\r\n" #
    # response += "\r\n"
    # response += "<p>i have recieved the file!<p>"
    # client_socket.send(response.encode('utf-8'))

def acceptRequest(server_socket, requestQueen, isCrawlEnd = False):
    print "[+] acceptRequest begin ..."
    accept_num = 0
    # while not isCrawlEnd:
    while True:
        client_socket, clien_cAddr = server_socket.accept()
        isCrawlEnd, crawl_url, origin_req = handle_client(client_socket)
        # print "[+] isCrawlEnd, origin_req [{}]...".format(accept_num+1)
        # print isCrawlEnd
        # print crawl_url
        # print origin_req
        # reqlines = origin_req.splitlines()
        # for line in reqlines:
        #     if 'Cookie:' in line:
        #         print (line)
        # print "[+] [{}]...".format(accept_num+1)
        accept_num += 1
        requestQueen.put([isCrawlEnd, crawl_url, origin_req])
        if isCrawlEnd == True and crawl_url == "all":
            break
    print "[+] acceptRequest End [accept_num = {}]...".format(accept_num)

if __name__ == "__main__":
    # main()
    reqQueue = Queue()

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(("0.0.0.0", 1122))
    server_socket.listen(128)

    p_accept = Process(target=acceptRequest, args=(server_socket, reqQueue))
    p_accept.start()

    report_num_dic = {}
    root_path_dic = {}
    while True:
        if not reqQueue.empty():
            req = reqQueue.get()
            if req[0] == True and req[1] == "all":
                print "Recieved All isCrawlEnd request!"
                break
            elif req[0]: # isCrawlEnd == True
                report_num_dic[req[1]] = -1
                root_path_dic[req[1]] = ""
                print "{} is tested totally!".format(req[1])
            elif req[1] != '' and req[2] != '':
                if req[1] not in report_num_dic.keys():
                    report_num_dic[req[1]] = 0
                    root_path_dic[req[1]] = ""
                elif report_num_dic[req[1]] == -1:
                    print "{} is ended before!".format(req[1])
                    continue
                web_root = startURadar(req[1], req[2], report_num_dic[req[1]]+1, root_path_dic[req[1]])
                # print "[+] URadar start ", req[1], report_num_dic[req[1]]+1
                # print req[2]
                # print "[+] ..."
                report_num_dic[req[1]] += 1
                root_path_dic[req[1]] = web_root
        else:
            continue

    reqQueue.close()
    reqQueue.join_thread()
    print "All tasks are tested successfully!"