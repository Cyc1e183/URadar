#coding=utf-8
#-*- coding:utf-8 -*-


from genericpath import isfile
import os
import re
import io
import time


DEBUG_MODE = False
saveArrayCode = 'monstra.txt' 
saveArrays = 'extArraysList.txt' 


search_file_ext = ".php" 

intresting_ext = ["php", "png", "jpg", "pdf", "zip","js","html","bmp", "gif", "tar.gz","xml","xhtml", "mp3", "mpg", "swf",'ico',"py","cmd", "htaccess", "bat", "jse", "sys", "vbs","xlsx","ppt","txt", "rar", "zipx"]
oriExtArraysList = []


def extractExt(s):
    extlist = []
    if "=>" in s and '|' in s:
        ext = s.split("=",1)[0].strip()[1:-1]
        if len(ext)<8 or '|' in ext: 
            extlist.append(ext)
    else:
        pattern = re.compile("""\'[\w\|_]{1,8}\'|\"[\w\|_]{1,8}\"|[\"\\'][\w\|_]{1,8},|,[\s]*[\w\|_]{1,8},|,[\s]*[\w\|_]{1,8}[\"\\']|\.[\w\|_]{1,8}[;/']""")  
        oriextlist = pattern.findall(s)
        for i in range(len(oriextlist)):
            ext = oriextlist[i][1:-1].strip()
            if ext.find('|')>0:
                exts = ext.split('|')
                extlist.extend(list(map(lambda x:x.strip(), exts)))
            else:
                extlist.append(ext)

        if len(extlist)>1:
            intreFlag = False
            for ext_type in intresting_ext: # 
                if extlist.count(ext_type)>0:
                    intreFlag = True
                    break
            if not intreFlag:
                extlist = []

    return extlist


def extractExtFromMysql(s):
    if len(s) and not s.startswith('#') and '(' in s and ')' in s:
        s = s.split('(',1)[1].rsplit(')',1)[0]
        nameS = s.split(')',1)[0]
        if 'extension' in nameS and '(' in s:
            valueS = s.rsplit('(',1)[1]
            nameList = list(map(lambda x:x.strip(), nameS.split(',')))
            valueList = list(map(lambda x:x.strip(), valueS.split(',')))
            if 'extension' in nameList:
                value = valueList[nameList.index('extension')][1:-1]
                return [value]
    return []



def findArrayAboutFile(path):
    
    if DEBUG_MODE:
        debug_write_file_object = io.open(saveArrayCode, 'w', encoding='utf-8')
    
    filter_pattern = re.compile("""[a-zA-Z]+""") 

    file_list = os.listdir(path)
    for file in file_list:
        cur_path = os.path.join(path, file)
        if os.path.isdir(cur_path):
            findArrayAboutFile(cur_path)
        elif os.path.isfile(cur_path):
            filename,fileext = os.path.splitext(file)
            if True:
                file_object = io.open(cur_path,'r',encoding='ISO-8859-15') 
                if DEBUG_MODE:
                    debug_write_file_object.write(cur_path+":\n")
                lines = file_object.readlines()
                lineIndex = 0
                while lineIndex < len(lines):
                    line = lines[lineIndex].strip()
                    if not line.startswith("#") and not line.startswith("//"):
                        if "array(" in line:
                            lastIndex = lineIndex
                            fileextFlag = False 
                            extList = [] 
                            while lastIndex < len(lines): 
                                line = lines[lastIndex].strip()
                                if not line.startswith("#") and not line.startswith("//"):
                                    if lastIndex > lineIndex and "array(" in line: 
                                        fileextFlag = False
                                        break
                                    if not fileextFlag:
                                        for ext_type in intresting_ext:
                                            index = line.find(ext_type)
                                            if index != -1 and (line[index-2:index] == "'." or line[index-2:index] == '".' or line[index-1] == "'" or line[index-1] == '"' or line[index+1] == ',' or line[index+1] == '"'):
                                                fileextFlag = True
                                                break
                                    if len(line) == 0 and fileextFlag:
                                        for l in range(lineIndex, lastIndex):
                                            extendexts = extractExt(lines[l]) 
                                            if DEBUG_MODE:
                                                debug_write_file_object.write(lines[l]+"\n")
                                            for e in extendexts:
                                                if extList.count(e) == 0:
                                                    filter_res = filter_pattern.findall(e)
                                                    if len(filter_res):
                                                        extList.append(e)
                                        if len(extList) and len(extList)<60:
                                            for ext_type in intresting_ext: 
                                                if extList.count(ext_type)>0:
                                                    oriExtArraysList.append(extList)
                                                    break
                                        extList = []
                                        fileextFlag = False
                                        lineIndex = lastIndex
                                    
                                    if ")" in line:
                                        if lastIndex == lineIndex: 
                                            line = line.split("array(",1)[1].rsplit(")",1)[0]
                                            extList = extractExt(line.strip()) 
                                        else:
                                            for l in range(lineIndex, lastIndex+1):
                                                extendexts = extractExt(lines[l].strip()) 
                                                if DEBUG_MODE:
                                                    debug_write_file_object.write(lines[l]+"\n")
                                                for e in extendexts:
                                                    if extList.count(e) == 0:
                                                        filter_res = filter_pattern.findall(e)
                                                        if len(filter_res):
                                                            extList.append(e)
                                        if len(extList) and len(extList)<100:
                                            for ext_type in intresting_ext:
                                                if extList.count(ext_type)>0:
                                                    oriExtArraysList.append(extList)
                                                    break
                                        lastIndex += 1
                                        break 
                                lastIndex += 1
                            lineIndex = lastIndex
                        elif "'extensions'" in line and "=>" in line and "*" in line: 
                            lastIndex = lineIndex 
                            fileextFlag = False 
                            extList = [] 
                            while lastIndex < len(lines):
                                line = lines[lastIndex].strip()
                                if not fileextFlag:
                                    for ext_type in intresting_ext:
                                        index = line.find(ext_type)
                                        if index != -1 and (line[index-2:index] == "'." or line[index-2:index] == '".' or line[index-2:index] == '*.' or line[index-1] == "'" or line[index-1] == '"' or line[index+1] == ',' or line[index+1] == '"'):
                                            fileextFlag = True
                                            break
                                elif "]" in line:
                                    for l in range(lineIndex, lastIndex+1):
                                        extendexts = extractExt(lines[l].strip())
                                        if DEBUG_MODE:
                                            debug_write_file_object.write(lines[l]+"\n")
                                        for e in extendexts:
                                            if extList.count(e) == 0:
                                                filter_res = filter_pattern.findall(e)
                                                if len(filter_res):
                                                    extList.append(e)
                                    if len(extList) and len(extList)<60:
                                        for ext_type in intresting_ext:
                                            if extList.count(ext_type)>0:
                                                oriExtArraysList.append(extList)
                                                break
                                    break 
                                lastIndex += 1
                            lineIndex = lastIndex
                
                        elif "extension" in line and "INSERT INTO" in line:
                            lastIndex = lineIndex 
                            fileextFlag = False
                            extList = [] 
                            while lastIndex < len(lines):
                                line = lines[lastIndex].strip()
                                if not fileextFlag:
                                    for ext_type in intresting_ext:
                                        index = line.find(ext_type)
                                        if index != -1 and (line[index-2:index] == "'." or line[index-2:index] == '".' or line[index-1] == "'" or line[index-1] == '"' or line[index+1] == ',' or line[index+1] == '"'):
                                            fileextFlag = True
                                            break
                                elif len(line) == 0:
                                    for l in range(lineIndex, lastIndex):
                                        extendexts = extractExtFromMysql(lines[l].strip())
                                        if DEBUG_MODE:
                                            debug_write_file_object.write(lines[l]+"\n")
                                        for e in extendexts:
                                            if extList.count(e) == 0:
                                                filter_res = filter_pattern.findall(e)
                                                if len(filter_res):
                                                    extList.append(e)
                                    if len(extList)  and len(extList)<60:
                                        for ext_type in intresting_ext:
                                            if extList.count(ext_type)>0:
                                                oriExtArraysList.append(extList)
                                                break
                                    break
                                
                                lastIndex += 1
                            
                            lineIndex = lastIndex
                
                        elif "<?php echo isset($upload_" in line and "<input" in line:
                            extStr = line.rsplit(":",1)[1].split('"')[1]
                            exts = extStr.split(",")
                            
                            if len(exts) and len(extList)<60:
                                for ext_type in intresting_ext:
                                    if exts.count(ext_type)>0:
                                        oriExtArraysList.append(exts)
                                        break
                            lineIndex += 1
                        
                        elif "'file_validate_extensions'" in line and "=>" in line:
                            exts = []
                            extStr = line.split("=>",1)[1]
                            if "['" in extStr:
                                extStr = extStr.split("['", 1)[1]
                                if "']" in extStr:
                                    extStr = extStr.rsplit("']",1)[0]
                                    if len(extStr.strip()):
                                        exts = extStr.split(" ")
                            if len(exts) and len(exts)<60:
                                for ext_type in intresting_ext:
                                    if exts.count(ext_type)>0:
                                        oriExtArraysList.append(exts)
                                        break
                            lineIndex += 1

                        elif "$cf['filebrowser']['extensions_" in line and "=" in line:
                            exts = []
                            extStr = line.split("=",1)[1].strip()
                            if extStr[0]=='"' and extStr[-1]==';':
                                extStr = extStr[1:-2]
                                if "," in extStr:
                                    exts = extStr.split(",")
                                    exts = [x.strip() for x in exts]
                            if len(exts) and len(exts)<60:
                                for ext_type in intresting_ext:
                                    if exts.count(ext_type)>0:
                                        oriExtArraysList.append(exts)
                                        break
                            lineIndex += 1

                        else:
                            lineIndex += 1
                    else:
                        lineIndex += 1

                file_object.close()
    
    if DEBUG_MODE:
        debug_write_file_object.close()
        file=io.open(saveArrays,'w') 
        file.write(str(oriExtArraysList));
        file.close()

    return oriExtArraysList



def CalcuSameExts(extsA, extsB):
    extsA.sort()
    extsB.sort()
    sameExts = []
    i, j = 0, 0
    while i<len(extsA) and j<len(extsB):
        if extsA[i]==extsB[j]:
            sameExts.append(extsA[i])
            i += 1
            j += 1
        elif extsA[i]>extsB[j]:
            j += 1
        elif extsA[i]<extsB[j]:
            i += 1
    return sameExts


def ExtractSameExtList(path):
    start_time = time.time()
    oriExtArraysList = findArrayAboutFile(path)

    noSameExtArrayList = []
    noSameExtArrayList.append(oriExtArraysList[0])
    for i in range(1, len(oriExtArraysList)):
        if oriExtArraysList[i] not in noSameExtArrayList:
            noSameExtArrayList.append(oriExtArraysList[i])
    extArraysList = noSameExtArrayList
    sameExtsClasses = []
    sameExtsClasses.append(extArraysList[0])
    classIndexList = []
    classIndexList.append([0])

    for currentArrayIndex in range(1,len(extArraysList)):
        sameExist = False
        for classIndex in range(len(sameExtsClasses)):
            sameExts = CalcuSameExts(sameExtsClasses[classIndex], extArraysList[currentArrayIndex])
            if len(sameExts):
                classIndexList[classIndex].append(currentArrayIndex)
                sameExtsClasses[classIndex] = sameExts
                sameExist = True
                break
        if not sameExist:
            sameExtsClasses.append(extArraysList[currentArrayIndex])
            classIndexList.append([currentArrayIndex])
    end_time = time.time()
    print end_time - start_time
    return sameExtsClasses, classIndexList, extArraysList


def ExtractDifferExtList(thisClassIndexArray, extArraysList):
    differClasses = []

    allExtsInSameArray = CalcuUnionForInter(-1, thisClassIndexArray, extArraysList) 


    for cindex in thisClassIndexArray:
        differexts = []
        oriArray = extArraysList[cindex]
        unionExceptOri = CalcuUnionForInter(cindex, thisClassIndexArray, extArraysList) 
        for ext in oriArray:
            if ext not in unionExceptOri:
                differexts.append(ext)
                if len(differexts) > 25:
                    break
        differClasses.append(differexts)
    return differClasses
    


def CalcuUnionForInter(exp_index, thisIndexList, allExtList):
    unionexts = []
    if exp_index!=-1: 
        for cindex in thisIndexList:
            if cindex != exp_index:
                unionexts.extend(allExtList[cindex])
    else:
        for cindex in thisIndexList:
            unionexts.extend(allExtList[cindex])
    unionexts = list(set(unionexts))
    return unionexts

if __name__ == '__main__':

    path = "/var/www/html"

    extArraysList = findArrayAboutFile(path)
