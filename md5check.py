#coding=utf-8 
import hashlib 
import os #Python os模块包含普遍的操作系统功能。如果你希望你的程序能够与平台无关的话，这个模块是尤为重要的。 
_FILE_SLIM=100*1024*1024 
def File_md5(filename): 
    calltimes = 0     #分片的个数 
    hmd5 = hashlib.md5() 
    fp = open(filename, "rb") 
    f_size = os.stat(filename).st_size #得到文件的大小 
    if f_size > _FILE_SLIM: 
        while (f_size > _FILE_SLIM): 
            hmd5.update(fp.read(_FILE_SLIM)) 
            f_size /= _FILE_SLIM 
            calltimes += 1  # delete    #文件大于100M时进行分片处理 
        if (f_size > 0) and (f_size <= _FILE_SLIM): 
            hmd5.update(fp.read()) 
    else: 
        hmd5.update(fp.read()) 
    return (hmd5.hexdigest(), calltimes) 
   
filepath = raw_input('input path: ') 
print File_md5(filepath)  