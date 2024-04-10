#!/usr/bin/env python
import os
import re
import utils


class mutate_manager:
    __op_path__ = './mutation_op/'
    def extension(x): return x.rsplit('.', 1)[1]
    __seedList__ = map(extension, os.listdir('./seed/'))
    def importor(self, x): return __import__(self.__op_path__[
        2:-1]+'.'+x.lower(), fromlist=["{}.{}".format(x, x)])

    def file2class(self, x): return (x.split('.', 1)[0]).upper()
    op_dict = {}

    def __init__(self):
        op_dir = os.listdir(self.__op_path__)
        ops = []
        class_re = re.compile(r'm\d+.*[.]py$')
        for i in op_dir:
            # File name should always match with m[Number].py
            if class_re.match(i):
                ops.append(i)
        ops = list(set(map(self.file2class, ops)))
        for i in ops:
            self.op_dict[i] = self.importor(i)

    def mutation_op_list(self):
        dir_list = os.listdir(self.__op_path__)
        mutation_list = []
        for i in dir_list:
            if ".py" not in i or ".pyc" in i or "__init__" in i or "mutation" in i:
                pass
            else:
                mutationname = i.upper().rsplit('.', 1)[0]
                mutation_list.append(mutationname)
        mutation_list.sort()
        return mutation_list

################################ Mutation operation########################################
    def mutation_chain(self, base_chain, seed_type, success_list, wholeBlack, wholeWhite, mimeres):    
        mutation_list = self.mutation_op_list()
        #print mutation_list
        #print base_chain
        #print success_list   ################# need rewrite
        #print PublicSuffixDetection_FailList    #[u'jpg', u'zip', u'gif', u'png', u'pdf', u'gz']
        if '+' in base_chain:
            last_op_idx = mutation_list.index(base_chain.rsplit('+', 1)[-1])+1
            base_chain = base_chain.split('+')
        elif len(base_chain) <= 0:
            last_op_idx = 0
            base_chain = []
        else:
            last_op_idx = mutation_list.index(base_chain)+1
            base_chain = [base_chain]

      ########################################## Set up control rules ##########################################
        op_range = mutation_list[last_op_idx:]
        ret = []
        #IMCFList = ['m01', 'm02','m03','m12']
        base_chain_import = {}
        op_range_import = {}
        #print base_chain
        for i in base_chain:
            #print i
            #if i.split('_')[-1].lower() not in PublicSuffixDetection_FailList:
            base_chain_import[i] = self.importor(i)
        for i in op_range:
            op_range_import[i] = self.importor(i)
        #####################################################Change the Rule#############################################################
        if wholeBlack:
            for i in op_range:
                #print i.lower()
                excludedflag = True
                if (seed_type not in op_range_import[i].mOP.__seed_dependency__) or (i.split('_')[-1].lower() in wholeBlack):# or (i.split('_')[-1][-3:].lower() in wholeBlack):
                    excludedflag = False
                else:
                    for ele in base_chain_import.keys():
                        #print base_chain_import[ele].mOP.__exclusion_op__.keys()
                        if (seed_type not in base_chain_import[ele].mOP.__exclusion_op__.keys()) or (ele.split('_')[-1].lower() in wholeBlack):# or (ele.split('_')[-1][-3:].lower() in wholeBlack):
                            excludedflag = False
                            break
                        elif (i in base_chain_import[ele].mOP.__exclusion_op__[seed_type]) or (i.split('_')[-1].lower() in wholeBlack):# or (i.split('_')[-1][-3:].lower() in wholeBlack): ##### black list
                            excludedflag = False
                            break
                ##############################################################################################################################
                if excludedflag:
                    input_mutation = ('+'.join(base_chain)+"+{}".format(i))
                    if input_mutation[0] == "+":
                        ret.append(input_mutation[1:])
                    else:
                        ret.append(input_mutation)
        elif wholeWhite:
            for i in op_range:
                #print i.lower()
                excludedflag = True
                if (seed_type not in op_range_import[i].mOP.__seed_dependency__) or ((i.split('_')[0].lower() == 'm04' or i.split('_')[0].lower() == 'm12') and (i.split('_')[-1].lower() not in wholeWhite)):# or (i.split('_')[-1][-3:].lower() in wholeBlack):
                    excludedflag = False
                else:
                    for ele in base_chain_import.keys():
                        #print base_chain_import[ele].mOP.__exclusion_op__.keys()
                        if (seed_type not in base_chain_import[ele].mOP.__exclusion_op__.keys()) or ((ele.split('_')[0].lower() == 'm04' or ele.split('_')[0].lower() == 'm12') and (ele.split('_')[-1].lower() not in wholeWhite)):# or (ele.split('_')[-1][-3:].lower() in wholeBlack):
                            excludedflag = False
                            break
                        elif (i in base_chain_import[ele].mOP.__exclusion_op__[seed_type]) or ((i.split('_')[0].lower() == 'm04' or i.split('_')[0].lower() == 'm12') and (i.split('_')[-1].lower() not in wholeWhite)):# or (i.split('_')[-1][-3:].lower() in wholeBlack): ##### black list
                            excludedflag = False
                            break
                ##############################################################################################################################
                if excludedflag:
                    input_mutation = ('+'.join(base_chain)+"+{}".format(i))
                    #print(i)
                    if input_mutation[0] == "+":
                        ret.append(input_mutation[1:])
                    else:
                        ret.append(input_mutation)
        else:
            for i in op_range:
                #print i.lower()
                excludedflag = True
                if (seed_type not in op_range_import[i].mOP.__seed_dependency__):# or (i.split('_')[-1][-3:].lower() in wholeBlack):
                    excludedflag = False
                else:
                    for ele in base_chain_import.keys():
                        #print base_chain_import[ele].mOP.__exclusion_op__.keys()
                        if (seed_type not in base_chain_import[ele].mOP.__exclusion_op__.keys()):# or (ele.split('_')[-1][-3:].lower() in wholeBlack):
                            excludedflag = False
                            break
                        elif (i in base_chain_import[ele].mOP.__exclusion_op__[seed_type]):# or (i.split('_')[-1][-3:].lower() in wholeBlack): ##### black list
                            excludedflag = False
                            break
                ##############################################################################################################################
                if excludedflag:
                    input_mutation = ('+'.join(base_chain)+"+{}".format(i))
                    if input_mutation[0] == "+":
                        ret.append(input_mutation[1:])
                    else:
                        ret.append(input_mutation)
        filtered_ret = []
        for i in ret:
            banflag = False
            for ban in success_list:
                if type(ban) == str and ban in i:   
                    banflag = True
                    break
                elif type(ban) == list:
                    hitcount = 0
                    for ban_ele in ban:
                        if ban_ele in i:
                            hitcount += 1
                    if hitcount == len(ban):
                        banflag = True
                        break
            if not banflag:
                filtered_ret.append(i)
        return filtered_ret

    def combinatedOpList(self, seedtype=None):
        print "combinatedOpList"
        opList = {}
        if seedtype == None:
            for i in self.__seedList__:
                opList[i] = self.combinatedOpListFactory(i)
        elif seedtype in self.__seedList__:
            opList[seedtype] = self.combinatedOpListFactory(seedtype)
        else:
            print "[-] Given seed type is not exist in seed list"
            return None
        return opList

    def combinatedOpListFactory(self, seedtype):
        available_op = []
        oplist = []

        # find available op
        for i in self.op_dict.keys():
            if seedtype in self.op_dict[i].mOP.__seed_dependency__ and i != "M0":
                available_op.append([i])

        oplist += available_op  # 1R - same with oplist, available_op

        # make list, 2R~
        for aop in available_op:  # List(List(Str)) -> List(Str)
            round_templist = []
            for opl in oplist:
                banflag = False
                # List(List
                for banop in self.op_dict[aop[0]].mOP.__exclusion_op__[seedtype]:
                    if banop in opl:
                        banflag = True
                        break
                if not banflag and aop[0] not in opl:
                    append_op = []
                    append_op += aop
                    append_op += opl
                else:
                    continue
                round_templist.append(append_op)
            map(list.sort, round_templist)

            oplist += round_templist
            oplist = map(tuple, oplist)
            oplist = map(list, set(oplist))
        return oplist

    def makeMutatedData(self, mutate_list, seed_file, resource_file):
        output = {
            'filename': utils.extract_filename(seed_file),
            'fileext': utils.extract_fileext(seed_file),
            'filetype': utils.extract_filetype(seed_file),
            'content': utils.extract_content(seed_file)
        }

        # insert specific data for hash
        output['content'] = output['content'].replace(
            "%unique#", os.urandom(8).encode('hex'))


        for mutation in mutate_list:
            mutator = self.op_dict[mutation].mOP()
            mutator.operation(output, seed_file, resource_file)
         # XXX: Finally, use output variable to make request
        #print output
        return output


def get_type_seed_files(types, seed_files):
    type_seed_files = []
    for i in seed_files:
        # XXX: Maybe we can check file metadata, not use the file extension to
        # check their type?
        if "." + types in i and i.endswith(types):
            type_seed_files.append(i)
    if len(type_seed_files) == 0:
        newfname = 'newfiles/test.'+types
        with open(newfname, 'w') as newf:
            newf.write('URadar_Test')
        type_seed_files.append(newfname)
    # print "type_seed_files:", type_seed_files
            
    return type_seed_files


# if you need to find full chain, use this code.
if __name__ == '__main__':
    test = mutate_manager()
    OpList = test.combinatedOpList()

    seed_files = os.listdir('seed')
    resource_files = os.listdir('resource')

    seed_files = ['seed/' + x for x in seed_files]
    resource_files = ['resource/' + x for x in resource_files]

    count = 0
    for key in OpList.keys():
        type_seed_files = get_type_seed_files(key, seed_files)
        print "{} - {}".format(key, len(OpList[key]))
