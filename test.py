# import os
# from turtle import pensize

# # l = ['html', 'message']

# # print(l.count('h'));

# # print(len(l))



# def get_type_seed_files(types, seed_files):
#     type_seed_files = []
#     for i in seed_files:
#         # XXX: Maybe we can check file metadata, not use the file extension to
#         # check their type?
#         if "." + types in i:
#             type_seed_files.append(i)
#     return type_seed_files

# seed_files = os.listdir('seed')
# resource_files = os.listdir('resource')
# seed_files = ['seed/' + x for x in seed_files]
# resource_files = ['resource/' + x for x in resource_files]
# seed_files.extend(resource_files)
# opList = ['html','re']
# # for i in seed_files:
# #     opList.append(i.rsplit('.', 1)[1])
#     #print opList
#     #total_ops = opList.keys()

# mutation_length = 0
# seed_result = {}
# type_seed_files = {}
# for key in opList:  
#     type_seed_files[key] = get_type_seed_files(key, seed_files)

# print(type_seed_files)

# for key in type_seed_files:
#     print(type_seed_files[key])

# for i in range(0,10):
# #     print i;

# L1 = []
# L2 = [1, 'm']
# L3 = ['j']

# # L3.extend(L2)
# L3.extend(L1)

# print(L3)

# with open('newfiles/newsogou.html', 'w') as fp:
#     page_txt=fp.write('urader')
# print('hellp')

# import os
# newfs = os.listdir('newfiles')
# print(newfs)

# import socket

# client=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
# client.connect(("172.16.245.132", 20174))

# line = '$cf[\'filebrowser\'][\'extensions_images\']=\"jpg,  jpeg, gif, png, tif, tiff, svg\"'

# extStr = line.rsplit("=",1)[1].split('"')[1]
# exts = extStr.split(",");
# exts = [x.strip() for x in exts]

# print exts

# L = [[1,2],[2,3],[3,4]]
# wholeWhite = []
# for w in L:
#     for i in w:
#         if wholeWhite.count(i)==0:
#             wholeWhite.append(i)
# print wholeWhite

# import re

# def removefile(upload_suc_res, remove_ori_req):
#     pattern = re.compile("Post.removeAttachment\([0-9]+\)")
#     id_strs = pattern.findall(upload_suc_res)
#     file_ids = []
#     for s in id_strs:
#         id_str = s.rsplit(")",1)[0].rsplit("(",1)[1]
#         id = int(id_str)
#         file_ids.append(id)
#     print(file_ids)
    

# if __name__ == "__main__":
#     res = """
#     <input type="submit" class="button" name="rem" value="Remove" onclick="return Post.removeAttachment(1807);" />
# <!-- end: post_attachments_attachment_remove --> <!-- start: post_attachments_attachment_postinsert -->
# <input type="button" class="button" name="insert" value="Insert Into Post" onclick="$('#message').sceditor('instance').insertText('[attachment=1807]'); return false;" />
# <!-- end: post_attachments_attachment_postinsert --></td>
# </tr>
# <!-- end: post_attachments_attachment --><!-- start: post_attachments_attachment -->
# <tr>
# <td class="trow2" width="1" align="center"><!-- start: attachment_icon -->
# <img src="http://172.16.245.131/images/attachtypes/image.png" title="JPG Image" border="0" alt=".jpg" />
# <!-- end: attachment_icon --></td>
# <td class="trow2" width="60%" style="white-space: nowrap">dj1.jpg (54.49 KB)</td>
# <td class="trow2" style="white-space: nowrap; text-align: center;"> <!-- start: post_attachments_attachment_remove -->
# <input type="submit" class="button" name="rem" value="Remove" onclick="return Post.removeAttachment(1804);" />
# <!-- end: post_attachments_attachment_remove --> <!-- start: post_attachments_attachment_postinsert -->
# <input type="button" class="button" name="insert" value="Insert Into Post" onclick="$('#message').sceditor('instance').insertText('[attachment=1804]'); return false;" />
# <!-- end: post_attachments_attachment_postinsert --></td>
# </tr>
# <!-- end: post_attachments_attachment --><!-- start: post_attachments_attachment -->
# <tr>
# <td class="trow2" width="1" align="center"><!-- start: attachment_icon -->
# <img src="http://172.16.245.131/images/attachtypes/image.png" title="PNG Image" border="0" alt=".png" />
# <!-- end: attachment_icon --></td>
# <td class="trow2" width="60%" style="white-space: nowrap">dj.png (384.72 KB)</td>
# <td class="trow2" style="white-space: nowrap; text-align: center;"> <!-- start: post_attachments_attachment_remove -->
# <input type="submit" class="button" name="rem" value="Remove" onclick="return Post.removeAttachment(1805);" />
# <!-- end: post_attachments_attachment_remove --> <!-- start: post_attachments_attachment_postinsert -->
# <input type="button" class="button" name="insert" value="Insert Into Post" onclick="$('#message').sceditor('instance').insertText('[attachment=1805]'); return false;" />
# <!-- end: post_attachments_attachment_postinsert --></td>
# </tr>
# <!-- end: post_attachments_attachment --><!-- start: post_attachments_attachment -->
# <tr>
# <td class="trow2" width="1" align="center"><!-- start: attachment_icon -->
# <img src="http://172.16.245.131/images/attachtypes/image.png" title="JPG Image" border="0" alt=".jpg" />
# <!-- end: attachment_icon --></td>
# <td class="trow2" width="60%" style="white-space: nowrap">sit.jpg (4.37 KB)</td>
# <td class="trow2" style="white-space: nowrap; text-align: center;"> <!-- start: post_attachments_attachment_remove -->
# <input type="submit" class="button" name="rem" value="Remove" onclick="return Post.removeAttachment(1808);" />
# <!-- end: post_attachments_attachment_remove --> <!-- start: post_attachments_attachment_postinsert -->
# <input type="button" class="button" name="insert" value="Insert Into Post" onclick="$('#message').sceditor('instance').insertText('[attachment=1808]'); return false;" />
# <!-- end: post_attachments_attachment_postinsert --></td>
# </tr>
#     """
#     req = '123'

#     removefile(res, req)

import time

start_time = time.time()
time.sleep(5)

end_time = time.time()

print start_time
print end_time

print (end_time - start_time)