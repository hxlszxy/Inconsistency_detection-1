#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
功能：比较cve与NVD数据的差异性
"""


import os
import ast
import re
import json
import re
import copy

# 获取txt文件中的字典内容
def get_data_from_dict():
    # 获取cpe字典内容
    cpe_dic_path = os.getcwd() + '/data/cpe-dictionary/'  # 存放的文件夹
    cpe_dic_filename = 'cpe_name_dic.txt'
    cpe_dic_name = os.path.join('%s%s' % (cpe_dic_path, cpe_dic_filename))  # 去除%s\%s之间的\，以免在服务器上运行出错，虽然在win不会出错
    cpe_dict = dict()  # 先初始化
    with open(cpe_dic_name, 'r', encoding='UTF-8') as cpe_f:  # 打开文件
        cpe_lines = cpe_f.readlines()  # 获取文件的所有行
        for cpe_line in cpe_lines:
            cpe_raw = cpe_line
            cpe_raw = cpe_raw.lstrip('cpe_software_version_dict=')
            cpe_dict = ast.literal_eval(cpe_raw)  # 转化为字典，只有一行数据，可以不加break

    # 获取openwall内容
    openwall_dic_path = os.getcwd() + '/data/openwall/'  # 存放的文件夹
    openwall_dic_filename = 'openwall_softname_and_version.txt'
    openwall_dic_name = os.path.join('%s%s' % (openwall_dic_path, openwall_dic_filename))
    openwall_dict = dict()  # 先初始化
    with open(openwall_dic_name, 'r', encoding='UTF-8') as openwall_f:  # 打开文件
        openwall_lines = openwall_f.readlines()  # 获取文件的所有行
        for openwall_line in openwall_lines:
            openwall_raw = openwall_line
            openwall_raw = openwall_raw.lstrip('name_and_version_dict=')
            openwall_dict = ast.literal_eval(openwall_raw)  # 转化为字典，只有一行数据，可以不加break

    # 获取nvd内容
    nvd_data_path = os.getcwd() + '/data/nvd/'  # 存放nvd的文件夹
    nvd_data_filename = 'nvd_softname_and_version.txt'
    nvd_data_file_path = os.path.join('%s%s' % (nvd_data_path, nvd_data_filename))
    nvd_dict = dict()  # 先初始化
    with open(nvd_data_file_path, 'r', encoding='UTF-8') as nvd_f:  # 打开文件
        nvd_lines = nvd_f.readlines()  # 获取文件的所有行
        for nvd_line in nvd_lines:
            nvd_raw = nvd_line
            nvd_raw = nvd_raw.lstrip('name_and_version_dict=')
            nvd_dict = ast.literal_eval(nvd_raw)  # 转化为字典，只有一行数据，可以不加break
    return cpe_dict, openwall_dict, nvd_dict


# 合并openwall和nvd的数据到一个dict中
def get_openwall_and_nvd_soft_origin():
    cpe_dict, openwall_dict, nvd_dict = get_data_from_dict()
    openwall_and_nvd_soft_origin = dict()

    cveid_cnt = 0
    for cveid in openwall_dict:
        cveid_cnt = cveid_cnt + 1
        print('cveid：' + str(cveid) + '    cveid的数量：' + str(cveid_cnt) + '\n')
        openwall_and_nvd_soft_origin[cveid] = {}
        openwall_and_nvd_soft_origin[cveid]['openwall'] = openwall_dict[cveid]
        if cveid in nvd_dict:
            openwall_and_nvd_soft_origin[cveid]['nvd'] = nvd_dict[cveid]
        else:
            openwall_and_nvd_soft_origin[cveid]['nvd'] = ''  # 如果cveid不存在于NVD中，则值为''
    # 保存在本地
    openwall_and_nvd_soft_path = os.getcwd() + '/data/softname_version_compare/'  # 文件夹
    openwall_and_nvd_soft_filename = '1_origin.txt'
    print_name_and_version_filename = '1_origin_print.txt'
    openwall_and_nvd_soft_file_path = os.path.join('%s%s' % (openwall_and_nvd_soft_path, openwall_and_nvd_soft_filename))
    print_name_and_version_file_path = os.path.join('%s%s' % (openwall_and_nvd_soft_path, print_name_and_version_filename))
    # 字典原始格式保存在本地
    with open(openwall_and_nvd_soft_file_path, 'w', encoding='utf-8') as name_and_version_f:  # 用w而非a，用于覆盖
        name_and_version_f.write('name_and_version_dict=' + str(openwall_and_nvd_soft_origin))  # 写入数据
    # 为了方便观察，以较好的格式另外保存到一个文件中
    for j in openwall_and_nvd_soft_origin:
        with open(print_name_and_version_file_path, 'a', encoding='utf-8') as print_name_and_version_f:  # 用a，用于追加
            print_name_and_version_f.write(j + ' ' + str(openwall_and_nvd_soft_origin[j]) + '\n')  # 写入数据


# 在匹配软件名称前先预处理
# !!!!!!!!!!注意，如果后面要对比版本，需要把before等词语映射为<=符号
def clean_openwall_and_nvd_softname_version():
    # 获取softname和version内容
    soft_dic_path = os.getcwd() + '/data/softname_version_compare/'  # 存放的文件夹
    soft_dic_filename = '1_origin.txt'
    soft_dic_name = os.path.join('%s%s' % (soft_dic_path, soft_dic_filename))
    soft_dict = dict()
    with open(soft_dic_name, 'r', encoding='UTF-8') as soft_f:  # 打开文件
        soft_lines = soft_f.readlines()  # 获取文件的所有行
        for soft_line in soft_lines:
            soft_raw = soft_line
            soft_raw = soft_raw.lstrip('name_and_version_dict=')
            soft_dict = ast.literal_eval(soft_raw)  # 转化为字典，只有一行数据，可以不加break

            cveid_cnt = 0
            for cveid in soft_dict:
                cveid_cnt = cveid_cnt + 1
                print('cveid：' + str(cveid) + '    cveid的数量：' + str(cveid_cnt) + '\n')
                openwall_soft = soft_dict[cveid]['openwall']

                # 对openwall进行处理
                tmp_z = 0
                openwall_list = list(openwall_soft.keys())
                while tmp_z < len(openwall_list):  # 修改了CNNVD函数的for循环代码为while
                    # 处理软件名称，把软件名转换为小写，并且把符号'-'改为空格
                    version = openwall_soft[openwall_list[tmp_z]]
                    del openwall_soft[openwall_list[tmp_z]]  # 删除原来的键值
                    openwall_list[tmp_z] = openwall_list[tmp_z].lower().replace('_', ' ')
                    # 处理版本
                    tmp_i = 0
                    while tmp_i < len(version):  # 对每个版本号去除前后的空格
                        version[tmp_i] = version[tmp_i].strip()
                        tmp_i = tmp_i + 1
                    tmp_j = 0
                    while tmp_j < len(version):
                        match_result = re.match(r'[-_*]+', version[tmp_j])  # 这些符号至少出现一次，能匹配'--'，不能匹配'openwall-2018-0001'
                        if (match_result is not None) or (version[tmp_j] == ''):
                            version.remove(version[tmp_j])
                        elif len(version[tmp_j]) > 0:  # 避免数据为空，出现错误：has on attribute 'find'
                            if version[tmp_j].find(' - ') != -1:
                                if (version[tmp_j].find('bit') == -1) and (version[tmp_j].find('.*') == -1) and (version[tmp_j].find('.x') == -1) and (version[tmp_j].find('.X') == -1):  # 避免CVE-2017-15251（-的右端包括'bit'）和CVE-2016-1571，'3.3.x - 4.6.x']
                                    version[tmp_j] = 'from ' + version[tmp_j].replace('-', ' to ')
                            elif version[tmp_j].find('之前的版本') != -1:  # 处理中文，比如CVE-2010-3433
                                version[tmp_j] = '<' + version[tmp_j].strip('之前的版本')
                            elif version[tmp_j].find('以及以前版本') != -1:  # CVE-2010-3262
                                version[tmp_j] = '<=' + version[tmp_j].strip('以及以前版本')
                            elif version[tmp_j].find('及之前版本') != -1:  # 处理中文
                                version[tmp_j] = '<=' + version[tmp_j].strip('及之前版本')
                            elif version[tmp_j].find('以下版本') != -1:  # CVE-2009-4269
                                version[tmp_j] = '<' + version[tmp_j].strip('以下版本')
                            elif version[tmp_j].find('之前版本') != -1:  # 处理中文
                                version[tmp_j] = '<' + version[tmp_j].strip('之前版本')
                            elif version[tmp_j].find('版本至') != -1:  #
                                start_pos = version[tmp_j].find('版本至')
                                tmp_list = version[tmp_j][start_pos+3:]
                                if len(tmp_list) > 0:
                                    if tmp_list.find('版本') != -1:
                                        version[tmp_j] = 'from ' + version[tmp_j].replace('版本至', ' to ').replace('版本', '')
                                    else:
                                        version[tmp_j] = 'from ' + version[tmp_j].replace('版本至', ' to ')  # CVE-2015-4939
                            elif version[tmp_j].find('至') != -1:
                                version[tmp_j] = 'from ' + version[tmp_j].replace('至', ' to ')  # CVE-2015-4939
                            elif version[tmp_j].find('版本') != -1:  # CVE-2010-3094
                                version[tmp_j] = version[tmp_j].strip('版本')
                        tmp_j = tmp_j + 1
                    openwall_soft[openwall_list[tmp_z]] = version  # 增加修改后的键值
                    tmp_z = tmp_z + 1


                # 对nvd进行类似的操作
                nvd_soft = soft_dict[cveid]['nvd']
                for softname in nvd_soft:
                    version = nvd_soft[softname]
                    del nvd_soft[softname]  # 删除原来的键值
                    softname = softname.lower().replace('_', ' ')
                    # 处理版本
                    tmp_i = 0
                    while tmp_i < len(version):  # 对每个版本号去除前后的空格
                        version[tmp_i] = version[tmp_i].strip()
                        tmp_i = tmp_i + 1
                    for each_version in version:
                        match_result = re.match(r'[-_*]+', each_version)  # 这些符号至少出现一次
                        if (match_result is not None) or (each_version == ''):
                            version.remove(each_version)
                        """
                        # 打印含字符'-'的版本号，可能是一个版本范围（有的是，有的不是，我们暂时把他们不视为范围）                       
                        elif len(each_version) > 0:
                            if each_version.find('-') != -1:
                                print(each_version + '\n')
                        """
                    nvd_soft[softname] = version  # 增加修改后的键值
    # 保存在本地
    openwall_and_nvd_soft_path = os.getcwd() + '/data/softname_version_compare/'  # 文件夹
    openwall_and_nvd_soft_filename = '2_clean_softname_version.txt'  # 这样命名方便查看
    print_name_and_version_filename = '2_clean_softname_version_print.txt'
    openwall_and_nvd_soft_file_path = os.path.join('%s%s' % (openwall_and_nvd_soft_path, openwall_and_nvd_soft_filename))
    print_name_and_version_file_path = os.path.join('%s%s' % (openwall_and_nvd_soft_path, print_name_and_version_filename))
    # 字典原始格式保存在本地
    with open(openwall_and_nvd_soft_file_path, 'w', encoding='utf-8') as name_and_version_f:  # 用w而非a，用于覆盖
        name_and_version_f.write('name_and_version_dict=' + str(soft_dict))  # 写入数据
    # 为了方便观察，以较好的格式另外保存到一个文件中
    for j in soft_dict:
        with open(print_name_and_version_file_path, 'a', encoding='utf-8') as print_name_and_version_f:  # 用a，用于追加
            print_name_and_version_f.write(j + ' ' + str(soft_dict[j]) + '\n')  # 写入数据


# 保留相同软件名称的数据项，名字完全相同才匹配
def keep_same_version_of_openwall_and_nvd():
    # 获取softname和version内容
    soft_dic_path = os.getcwd() + '/data/softname_version_compare/'  # 存放的文件夹
    soft_dic_filename = '2_clean_softname_version.txt'
    soft_dic_name = os.path.join('%s%s' % (soft_dic_path, soft_dic_filename))
    soft_dict = dict()
    with open(soft_dic_name, 'r', encoding='UTF-8') as soft_f:  # 打开文件
        soft_lines = soft_f.readlines()  # 获取文件的所有行
        for soft_line in soft_lines:
            soft_raw = soft_line
            soft_raw = soft_raw.lstrip('name_and_version_dict=')
            soft_dict = ast.literal_eval(soft_raw)  # 转化为字典，只有一行数据，可以不加break

            cveid_cnt = 0
            for cveid in soft_dict:
                cveid_cnt = cveid_cnt + 1
                print('cveid：' + str(cveid) + '    CVEID的数量：' + str(cveid_cnt) + '\n')
                openwall_soft = soft_dict[cveid]['openwall']
                nvd_soft = soft_dict[cveid]['nvd']
                # 只保留相同的软件名的数据项
                tmp_i = 0
                # 只对字典处理，不对空的字符串处理
                if isinstance(openwall_soft, dict):
                    openwall_list = list(openwall_soft.keys())
                    while tmp_i < len(openwall_list):
                        if openwall_list[tmp_i] not in nvd_soft:
                            del openwall_soft[openwall_list[tmp_i]]
                        tmp_i = tmp_i + 1

                tmp_j = 0
                # 只对字典处理，不对空的字符串处理
                if isinstance(nvd_soft, dict):
                    nvd_list = list(nvd_soft.keys())
                    while tmp_j < len(nvd_list):
                        if nvd_list[tmp_j] not in openwall_soft:
                            del nvd_soft[nvd_list[tmp_j]]
                        tmp_j = tmp_j + 1

    # 去除没有数据项的CVEID对应的数据
    tmp_k = 0
    soft_list = list(soft_dict.keys())
    while tmp_k < len(soft_list):
        openwall_soft = soft_dict[soft_list[tmp_k]]['openwall']
        nvd_soft = soft_dict[soft_list[tmp_k]]['nvd']
        if (not openwall_soft) or (nvd_soft == ''):  # 为空则去掉
            del soft_dict[soft_list[tmp_k]]
        tmp_k = tmp_k + 1

    # 保存在本地
    openwall_and_nvd_soft_path = os.getcwd() + '/data/softname_version_compare/'  # 文件夹
    openwall_and_nvd_soft_filename = '3_keep_same_version_of_openwall_and_nvd.txt'  # 这样命名方便查看
    print_name_and_version_filename = '3_keep_same_version_of_openwall_and_nvd_print.txt'
    openwall_and_nvd_soft_file_path = os.path.join('%s%s' % (openwall_and_nvd_soft_path, openwall_and_nvd_soft_filename))
    print_name_and_version_file_path = os.path.join('%s%s' % (openwall_and_nvd_soft_path, print_name_and_version_filename))
    # 字典原始格式保存在本地
    with open(openwall_and_nvd_soft_file_path, 'w', encoding='utf-8') as name_and_version_f:  # 用w而非a，用于覆盖
        name_and_version_f.write('name_and_version_dict=' + str(soft_dict))  # 写入数据
    # 为了方便观察，以较好的格式另外保存到一个文件中
    for j in soft_dict:
        with open(print_name_and_version_file_path, 'a', encoding='utf-8') as print_name_and_version_f:  # 用a，用于追加
            print_name_and_version_f.write(j + ' ' + str(soft_dict[j]) + '\n')  # 写入数据


# CPE字典映射
def cpe_map(softname, start_version, end_version, flag_str):  # flag为Ture则表示范围为<=，否则为from to
    # 获取cpe_dict内容
    cpe_dic_path = os.getcwd() + '/data/cpe-dictionary/'  # 存放cpe字典的文件夹
    cpe_dic_filename = 'cpe_name_dic.txt'
    cpe_dic_name = os.path.join('%s%s' % (cpe_dic_path, cpe_dic_filename))
    cpe_dict = dict()
    with open(cpe_dic_name, 'r', encoding='UTF-8') as cpe_f:  # 打开文件
        cpe_lines = cpe_f.readlines()  # 获取文件的所有行
        for cpe_line in cpe_lines:
            cpe_raw = cpe_line
            cpe_raw = cpe_raw.lstrip('cpe_software_version_dict=')
            cpe_dict = ast.literal_eval(cpe_raw)  # 转化为字典，只有一行数据，可以不加break
    # 版本映射
    # 修改原来的代码，先预处理

    flag_str = flag_str
    version = start_version  # 范围为<=等
    start_version = start_version  # 范围为from to
    end_version = end_version  # 范围为from to
    new_version_list = []
    convert_flag = False  # 是否经过了映射，默认没有

    # 如果软件名不存在于cpe_dict中，则去除软件名中的厂商名再在cpe_dict里面找
    softname_remove_firm = ''
    softname_split = softname.split()
    if len(softname_split) > 1:
        i = 1
        while i < len(softname_split)-1:
            softname_remove_firm = softname_remove_firm + softname_split[i] + ' '
            i = i + 1
        softname_remove_firm = softname_remove_firm + softname_split[-1]

    if softname in cpe_dict.keys():
        cpe_version = cpe_dict[softname]
        if flag_str == '<=':  # 范围为<=  避免CVE-2016-1680 发生'>51.0.2704.63'包括'6.0'
            if version in cpe_version:
                end_index = cpe_version.index(version)  # 第一个匹配的version的下标
                tmp_i = 0
                while tmp_i < end_index:
                    if version.find('.') != -1:
                        out_pos = version.find('.')
                        out_version = version[:out_pos]
                        if out_version.isdigit() is True:
                            int_version = int(out_version)
                            if cpe_version[tmp_i].find('.')!=-1:
                                end_pos= cpe_version[tmp_i].find('.')
                                first_number = cpe_version[tmp_i][:end_pos]
                                if first_number.isdigit() is True:
                                    int_number = int(first_number)
                                    if int_number <= int_version:
                                        new_version_list.append(cpe_version[tmp_i])
                                        convert_flag = True
                    tmp_i = tmp_i + 1
                new_version_list.append(cpe_version[end_index])

        elif flag_str == 'from to':  # 范围为from to
            if (start_version in cpe_version) and (end_version in cpe_version):
                start_index = cpe_version.index(start_version)
                end_index = cpe_version.index(end_version)
                tmp_i = start_index
                while tmp_i < end_index:
                    if (start_version.find('.') != -1) and (end_version.find('.') != -1):
                        out_start_pos = start_version.find('.')
                        out_start_version = start_version[:out_start_pos]
                        out_end_pos = end_version.find('.')
                        out_end_version = end_version[:out_end_pos]
                        if (out_end_version.isdigit() is True) and (out_start_version.isdigit() is True):
                            int_out_start_version = int(out_start_version)
                            int_out_end_version = int(out_end_version)
                            if cpe_version[tmp_i].find('.')!=-1:
                                end_pos= cpe_version[tmp_i].find('.')
                                first_number = cpe_version[tmp_i][:end_pos]
                                if first_number.isdigit() is True:
                                    int_number = int(first_number)
                                    if (int_number <= int_out_end_version) and (int_number >= int_out_start_version):
                                        new_version_list.append(cpe_version[tmp_i])
                                        convert_flag = True
                    tmp_i = tmp_i + 1
                new_version_list.append(cpe_version[end_index])

        elif flag_str == '*':  # 范围为*
            for tmp_cpe in cpe_version:
                if tmp_cpe != '':
                    if tmp_cpe.find(version) == 0:  # 不能!=-1，如想匹配16.x，结果3.16.x也匹配了
                        new_version_list.append(tmp_cpe)
                        convert_flag = True
        elif flag_str == '>=*':  # 范围为>=*
            start_index = ''
            for tmp_cpe in cpe_version:
                if tmp_cpe != '':
                    if tmp_cpe.find(version) == 0:  # 不能用!=-1，如想匹配16.x，结果3.16.x也匹配了
                        start_index = cpe_version.index(tmp_cpe)
                        break  # 加break
            if start_index != '':
                tmp_i = start_index
                while tmp_i < len(cpe_version):
                    if version.find('.') != -1:
                        out_pos = version.find('.')
                        out_version = version[:out_pos]
                        if out_version.isdigit() is True:
                            int_version = int(out_version)
                            if cpe_version[tmp_i].find('.')!=-1:
                                end_pos= cpe_version[tmp_i].find('.')
                                first_number = cpe_version[tmp_i][:end_pos]
                                if first_number.isdigit() is True:
                                    int_number = int(first_number)
                                    if int_number >= int_version:
                                        new_version_list.append(cpe_version[tmp_i])
                                        convert_flag = True
                    tmp_i = tmp_i + 1
                new_version_list.append(cpe_version[start_index])

        elif flag_str == '<=*':  # 范围为<=*
            end_index = ''
            tmp_w = len(cpe_version) - 1
            while tmp_w >= 0:
                if cpe_version[tmp_w].find(version) == 0:  # 不能用!=-1，如想匹配16.x，结果3.16.x也匹配了
                    end_index = cpe_version.index(cpe_version[tmp_w])
                    break  # 加break
                tmp_w = tmp_w - 1
            if end_index != '':
                tmp_i = 0
                while tmp_i < end_index:
                    if version.find('.') != -1:
                        out_pos = version.find('.')
                        out_version = version[:out_pos]
                        if out_version.isdigit() is True:
                            int_version = int(out_version)
                            if cpe_version[tmp_i].find('.')!=-1:
                                end_pos= cpe_version[tmp_i].find('.')
                                first_number = cpe_version[tmp_i][:end_pos]
                                if first_number.isdigit() is True:
                                    int_number = int(first_number)
                                    if int_number <= int_version:
                                        new_version_list.append(cpe_version[tmp_i])
                                        convert_flag = True
                    tmp_i = tmp_i + 1
                new_version_list.append(cpe_version[end_index])
        elif flag_str == '<':  # 范围为<
            if version in cpe_version:
                end_index = cpe_version.index(version)  # 第一个匹配的version的下标
                tmp_i = 0
                while tmp_i < end_index:
                    if version.find('.')!=-1:
                        out_pos = version.find('.')
                        out_version = version[:out_pos]
                        if out_version.isdigit() is True:
                            int_version = int(out_version)
                            if cpe_version[tmp_i].find('.')!=-1:
                                end_pos= cpe_version[tmp_i].find('.')
                                first_number = cpe_version[tmp_i][:end_pos]
                                if first_number.isdigit() is True:
                                    int_number = int(first_number)
                                    if int_number <= int_version:
                                        new_version_list.append(cpe_version[tmp_i])
                                        convert_flag = True
                    tmp_i = tmp_i + 1
        elif flag_str == '>=':  # 范围为>=
            if version in cpe_version:
                start_index = cpe_version.index(version)  # 第一个匹配的version的下标
                tmp_i = start_index
                while tmp_i < len(cpe_version):
                    if version.find('.')!=-1:
                        out_pos = version.find('.')
                        out_version = version[:out_pos]
                        if out_version.isdigit() is True:
                            int_version = int(out_version)
                            if cpe_version[tmp_i].find('.')!=-1:
                                end_pos= cpe_version[tmp_i].find('.')
                                first_number = cpe_version[tmp_i][:end_pos]
                                if first_number.isdigit() is True:
                                    int_number = int(first_number)
                                    if int_number >= int_version:
                                        new_version_list.append(cpe_version[tmp_i])
                                        convert_flag = True
                    tmp_i = tmp_i + 1
                new_version_list.append(cpe_version[start_index])  # 似乎没有用，不过影响不大，后面会去重

        elif flag_str == '>':  # 范围为>
            if version in cpe_version:
                start_index = cpe_version.index(version)  # 第一个匹配的version的下标
                tmp_i = start_index + 1  # 避免末尾情况，CVE-2019-9896从'>0.71'转化为'>0.71'
                while tmp_i < len(cpe_version):
                    print(tmp_i)
                    if version.find('.')!=-1:
                        out_pos = version.find('.')
                        out_version = version[:out_pos]
                        if out_version.isdigit() is True:
                            int_version = int(out_version)
                            if cpe_version[tmp_i].find('.')!=-1:
                                end_pos= cpe_version[tmp_i].find('.')
                                first_number = cpe_version[tmp_i][:end_pos]
                                if first_number.isdigit() is True:
                                    int_number = int(first_number)
                                    if int_number >= int_version:  # 这里是>=
                                        new_version_list.append(cpe_version[tmp_i])
                                        convert_flag = True
                    tmp_i = tmp_i + 1
                print('haha')
    elif softname_remove_firm != '':
        if softname_remove_firm in cpe_dict.keys():
            cpe_version = cpe_dict[softname_remove_firm]
            if flag_str == '<=':  # 范围为<=  避免CVE-2016-1680 发生'>51.0.2704.63'包括'6.0'
                if version in cpe_version:
                    end_index = cpe_version.index(version)  # 第一个匹配的version的下标
                    tmp_i = 0
                    while tmp_i < end_index:
                        if version.find('.') != -1:
                            out_pos = version.find('.')
                            out_version = version[:out_pos]
                            if out_version.isdigit() is True:
                                int_version = int(out_version)
                                if cpe_version[tmp_i].find('.') != -1:
                                    end_pos = cpe_version[tmp_i].find('.')
                                    first_number = cpe_version[tmp_i][:end_pos]
                                    if first_number.isdigit() is True:
                                        int_number = int(first_number)
                                        if int_number <= int_version:
                                            new_version_list.append(cpe_version[tmp_i])
                                            convert_flag = True
                        tmp_i = tmp_i + 1
                    new_version_list.append(cpe_version[end_index])

            elif flag_str == 'from to':  # 范围为from to
                if (start_version in cpe_version) and (end_version in cpe_version):
                    start_index = cpe_version.index(start_version)
                    end_index = cpe_version.index(end_version)
                    tmp_i = start_index
                    while tmp_i < end_index:
                        if (start_version.find('.') != -1) and (end_version.find('.') != -1):
                            out_start_pos = start_version.find('.')
                            out_start_version = start_version[:out_start_pos]
                            out_end_pos = end_version.find('.')
                            out_end_version = end_version[:out_end_pos]
                            if (out_end_version.isdigit() is True) and (out_start_version.isdigit() is True):
                                int_out_start_version = int(out_start_version)
                                int_out_end_version = int(out_end_version)
                                if cpe_version[tmp_i].find('.') != -1:
                                    end_pos = cpe_version[tmp_i].find('.')
                                    first_number = cpe_version[tmp_i][:end_pos]
                                    if first_number.isdigit() is True:
                                        int_number = int(first_number)
                                        if (int_number <= int_out_end_version) and (
                                                int_number >= int_out_start_version):
                                            new_version_list.append(cpe_version[tmp_i])
                                            convert_flag = True
                        tmp_i = tmp_i + 1
                    new_version_list.append(cpe_version[end_index])

            elif flag_str == '*':  # 范围为*
                for tmp_cpe in cpe_version:
                    if tmp_cpe != '':
                        if tmp_cpe.find(version) == 0:  # 不能!=-1，如想匹配16.x，结果3.16.x也匹配了
                            new_version_list.append(tmp_cpe)
                            convert_flag = True
            elif flag_str == '>=*':  # 范围为>=*
                start_index = ''
                for tmp_cpe in cpe_version:
                    if tmp_cpe != '':
                        if tmp_cpe.find(version) == 0:  # 不能用!=-1，如想匹配16.x，结果3.16.x也匹配了
                            start_index = cpe_version.index(tmp_cpe)
                            break  # 加break
                if start_index != '':
                    tmp_i = start_index
                    while tmp_i < len(cpe_version):
                        if version.find('.') != -1:
                            out_pos = version.find('.')
                            out_version = version[:out_pos]
                            if out_version.isdigit() is True:
                                int_version = int(out_version)
                                if cpe_version[tmp_i].find('.') != -1:
                                    end_pos = cpe_version[tmp_i].find('.')
                                    first_number = cpe_version[tmp_i][:end_pos]
                                    if first_number.isdigit() is True:
                                        int_number = int(first_number)
                                        if int_number >= int_version:
                                            new_version_list.append(cpe_version[tmp_i])
                                            convert_flag = True
                        tmp_i = tmp_i + 1
                    new_version_list.append(cpe_version[start_index])

            elif flag_str == '<=*':  # 范围为<=*
                end_index = ''
                tmp_w = len(cpe_version) - 1
                while tmp_w >= 0:
                    if cpe_version[tmp_w].find(version) == 0:  # 不能用!=-1，如想匹配16.x，结果3.16.x也匹配了
                        end_index = cpe_version.index(cpe_version[tmp_w])
                        break  # 加break
                    tmp_w = tmp_w - 1
                if end_index != '':
                    tmp_i = 0
                    while tmp_i < end_index:
                        if version.find('.') != -1:
                            out_pos = version.find('.')
                            out_version = version[:out_pos]
                            if out_version.isdigit() is True:
                                int_version = int(out_version)
                                if cpe_version[tmp_i].find('.') != -1:
                                    end_pos = cpe_version[tmp_i].find('.')
                                    first_number = cpe_version[tmp_i][:end_pos]
                                    if first_number.isdigit() is True:
                                        int_number = int(first_number)
                                        if int_number <= int_version:
                                            new_version_list.append(cpe_version[tmp_i])
                                            convert_flag = True
                        tmp_i = tmp_i + 1
                    new_version_list.append(cpe_version[end_index])
            elif flag_str == '<':  # 范围为<
                if version in cpe_version:
                    end_index = cpe_version.index(version)  # 第一个匹配的version的下标
                    tmp_i = 0
                    while tmp_i < end_index:
                        if version.find('.') != -1:
                            out_pos = version.find('.')
                            out_version = version[:out_pos]
                            if out_version.isdigit() is True:
                                int_version = int(out_version)
                                if cpe_version[tmp_i].find('.') != -1:
                                    end_pos = cpe_version[tmp_i].find('.')
                                    first_number = cpe_version[tmp_i][:end_pos]
                                    if first_number.isdigit() is True:
                                        int_number = int(first_number)
                                        if int_number <= int_version:
                                            new_version_list.append(cpe_version[tmp_i])
                                            convert_flag = True
                        tmp_i = tmp_i + 1
            elif flag_str == '>=':  # 范围为>=
                if version in cpe_version:
                    start_index = cpe_version.index(version)  # 第一个匹配的version的下标
                    tmp_i = start_index
                    while tmp_i < len(cpe_version):
                        if version.find('.') != -1:
                            out_pos = version.find('.')
                            out_version = version[:out_pos]
                            if out_version.isdigit() is True:
                                int_version = int(out_version)
                                if cpe_version[tmp_i].find('.') != -1:
                                    end_pos = cpe_version[tmp_i].find('.')
                                    first_number = cpe_version[tmp_i][:end_pos]
                                    if first_number.isdigit() is True:
                                        int_number = int(first_number)
                                        if int_number >= int_version:
                                            new_version_list.append(cpe_version[tmp_i])
                                            convert_flag = True
                        tmp_i = tmp_i + 1
                    new_version_list.append(cpe_version[start_index])  # 似乎没有用，不过影响不大，后面会去重

            elif flag_str == '>':  # 范围为>
                if version in cpe_version:
                    start_index = cpe_version.index(version)  # 第一个匹配的version的下标
                    tmp_i = start_index + 1  # 避免末尾情况，CVE-2019-9896从'>0.71'转化为'>0.71'
                    while tmp_i < len(cpe_version):
                        print(tmp_i)
                        if version.find('.') != -1:
                            out_pos = version.find('.')
                            out_version = version[:out_pos]
                            if out_version.isdigit() is True:
                                int_version = int(out_version)
                                if cpe_version[tmp_i].find('.') != -1:
                                    end_pos = cpe_version[tmp_i].find('.')
                                    first_number = cpe_version[tmp_i][:end_pos]
                                    if first_number.isdigit() is True:
                                        int_number = int(first_number)
                                        if int_number >= int_version:  # 这里是>=
                                            new_version_list.append(cpe_version[tmp_i])
                                            convert_flag = True
                        tmp_i = tmp_i + 1
                    print('haha')
    return new_version_list, convert_flag


# 用CPE字典把软件版本范围映射为离散值，便于之后的版本比较
def cpe_map_version_of_cve_and_nvd():
    # 获取softname和version内容
    soft_dic_path = os.getcwd() + '/data/softname_version_compare/'  # 存放的文件夹
    soft_dic_filename = '3_keep_same_version_of_cve_and_nvd.txt'
    soft_dic_name = os.path.join('%s%s' % (soft_dic_path, soft_dic_filename))
    soft_dict = dict()
    with open(soft_dic_name, 'r', encoding='UTF-8') as soft_f:  # 打开文件
        soft_lines = soft_f.readlines()  # 获取文件的所有行
        for soft_line in soft_lines:
            soft_raw = soft_line
            soft_raw = soft_raw.lstrip('name_and_version_dict=')
            soft_dict = ast.literal_eval(soft_raw)  # 转化为字典，只有一行数据，可以不加break

            cveid_cnt = 0
            for cveid in soft_dict:
                #if cveid_cnt==51:  # 测试100个，仅测试使用，记得删除------------
                #    break
                #if cveid != 'CVE-2018-1911':  # 仅测试使用，记得删除---------------------------------
                #   continue
                cveid_cnt = cveid_cnt + 1
                print('CVEID：' + str(cveid) + '    CVEID的数量：' + str(cveid_cnt) + '\n')
                cve_soft = soft_dict[cveid]['cve']
                nvd_soft = soft_dict[cveid]['nvd']

                # 处理cve
                tmp_i = 0
                cve_list = list(cve_soft.keys())
                while tmp_i < len(cve_list):
                    if len(cve_list[tmp_i]) > 0:  # 软件名长度>0
                        version_list = cve_soft[cve_list[tmp_i]]  # 该软件名的版本列表
                        tmp_j = 0
                        while tmp_j < len(version_list):
                            if len(version_list[tmp_j]) > 0:  # 版本长度>0
                                # 暂时只处理最后一位为*的且只有一个*
                                multi_list = ['>', '<', '=', '.', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9']
                                multi_flag = False  # 有*
                                if (version_list[tmp_j][-2:] == '.*') or (version_list[tmp_j][-2:] == '.x') or (version_list[tmp_j][-2:] == '.X'):
                                    for tmp_single in version_list[tmp_j][:-2]:
                                        if tmp_single in multi_list:
                                            multi_flag = True
                                        else:
                                            multi_flag = False
                                    if multi_flag is True:
                                        version_list[tmp_j] = version_list[tmp_j][:-1] + '*'  # 最后一位统一为*


                                # 从xx版本到xx版本
                                if (version_list[tmp_j].find('from') != -1) and (version_list[tmp_j].find('to') != -1):
                                    small_version_start_pos = version_list[tmp_j].find('from')+4
                                    small_version_end_pos = version_list[tmp_j].find('to') - 2
                                    small_version = version_list[tmp_j][small_version_start_pos:small_version_end_pos].strip()
                                    big_version_start_pos = version_list[tmp_j].find('to') + 2
                                    big_version = version_list[tmp_j][big_version_start_pos:].strip()
                                    softname = cve_list[tmp_i]
                                    new_version_list, convert_flag = cpe_map(softname, small_version, big_version, 'from to')
                                    if convert_flag:  # 经过了映射
                                        version_list[tmp_j] = new_version_list
                                elif multi_flag is True:  # 有*
                                    softname = cve_list[tmp_i]

                                    # 暂时只分3种情况
                                    # *
                                    if version_list[tmp_j][0].isdigit() is True:  # CVE-2019-1759
                                        #tmp_j = tmp_j + 1  # 测试的代码，要删除------------------
                                        #continue  # 测试的代码，要删除------------------
                                        small_version = version_list[tmp_j].rstrip('*')
                                        new_version_list, convert_flag = cpe_map(softname, small_version, small_version, '*')
                                        if convert_flag:  # 经过了映射
                                            version_list[tmp_j] = new_version_list
                                    # >=*
                                    elif version_list[tmp_j][0] == '>':  # CVE-2017-7656
                                        #tmp_j = tmp_j + 1  # 测试的代码，要删除------------------
                                        #continue  # 测试的代码，要删除------------------
                                        small_version = version_list[tmp_j].lstrip('>=').rstrip('*')
                                        new_version_list, convert_flag = cpe_map(softname, small_version, small_version, '>=*')
                                        if convert_flag:  # 经过了映射
                                            version_list[tmp_j] = new_version_list
                                    # <=*
                                    elif version_list[tmp_j][0] == '<':  # CVE-2018-14504
                                        #tmp_j = tmp_j + 1  # 测试的代码，要删除------------------
                                        #continue  # 测试的代码，要删除------------------
                                        small_version = version_list[tmp_j].lstrip('<=').rstrip('*')
                                        new_version_list, convert_flag = cpe_map(softname, small_version, small_version, '<=*')
                                        if convert_flag:  # 经过了映射
                                            version_list[tmp_j] = new_version_list

                                # “ > <”等条件语句放在elif multi_flag is True的后面，优先判断后者
                                # <=xx版本
                                elif version_list[tmp_j].find('<=') != -1:  # CVE-2016-1683
                                    #tmp_j = tmp_j + 1  # 测试的代码，要删除------------------
                                    #continue  # 测试的代码，要删除------------------
                                    small_version = version_list[tmp_j].strip('<=')
                                    softname = cve_list[tmp_i]
                                    new_version_list, convert_flag = cpe_map(softname, small_version, small_version, '<=')
                                    if convert_flag:  # 经过了映射
                                        version_list[tmp_j] = new_version_list
                                # <xx版本
                                elif version_list[tmp_j].find('<') != -1:
                                    #tmp_j = tmp_j + 1  # 测试的代码，要删除------------------
                                    #continue  # 测试的代码，要删除------------------
                                    small_version = version_list[tmp_j].strip('<')
                                    softname = cve_list[tmp_i]
                                    new_version_list, convert_flag = cpe_map(softname, small_version, small_version, '<')
                                    if convert_flag:  # 经过了映射
                                        version_list[tmp_j] = new_version_list
                                # >=xx版本
                                elif version_list[tmp_j].find('>=') != -1:
                                    #tmp_j = tmp_j + 1  # 测试的代码，要删除------------------
                                    #continue  # 测试的代码，要删除------------------
                                    small_version = version_list[tmp_j].strip('>=')
                                    softname = cve_list[tmp_i]
                                    new_version_list, convert_flag = cpe_map(softname, small_version, small_version, '>=')
                                    if convert_flag:  # 经过了映射
                                        version_list[tmp_j] = new_version_list
                                # >xx版本
                                elif version_list[tmp_j].find('>') != -1:
                                    #tmp_j = tmp_j + 1  # 测试的代码，要删除------------------
                                    #continue  # 测试的代码，要删除------------------
                                    small_version = version_list[tmp_j].strip('>')
                                    softname = cve_list[tmp_i]
                                    new_version_list, convert_flag = cpe_map(softname, small_version, small_version, '>')
                                    if convert_flag:  # 经过了映射
                                        version_list[tmp_j] = new_version_list
                            tmp_j = tmp_j + 1
                        cve_soft[cve_list[tmp_i]] = version_list  # 修改字典中的值
                    tmp_i = tmp_i + 1

                #  处理NVD，与cve类似
                tmp_k = 0
                nvd_list = list(nvd_soft.keys())
                while tmp_k < len(nvd_list):
                    if len(nvd_list[tmp_k]) > 0:  # 软件名长度>0
                        version_list = nvd_soft[nvd_list[tmp_k]]  # 该软件名的版本列表
                        tmp_l = 0
                        while tmp_l < len(version_list):
                            if len(version_list[tmp_l]) > 0:  # 版本长度>0#
                                # 暂时只处理最后一位为*的且只有一个*
                                multi_list = ['>', '<', '=', '.', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9']
                                multi_flag = False  # 有*
                                if (version_list[tmp_l][-2:] == '.*') or (version_list[tmp_l][-2:] == '.x') or (version_list[tmp_l][-2:] == '.X'):
                                    for tmp_single in version_list[tmp_l][:-2]:
                                        if tmp_single in multi_list:
                                            multi_flag = True
                                        else:
                                            multi_flag = False
                                    if multi_flag is True:
                                        version_list[tmp_l] = version_list[tmp_l][:-1] + '*'  # 最后一位统一为*


                                # 从xx版本到xx版本
                                if (version_list[tmp_l].find('from') != -1) and (version_list[tmp_l].find('to') != -1):
                                    small_version_start_pos = version_list[tmp_l].find('from')+4
                                    small_version_end_pos = version_list[tmp_l].find('to') - 2
                                    small_version = version_list[tmp_l][small_version_start_pos:small_version_end_pos].strip()
                                    big_version_start_pos = version_list[tmp_l].find('to') + 2
                                    big_version = version_list[tmp_l][big_version_start_pos:].strip()
                                    softname = nvd_list[tmp_k]   # 注意修改softname = nvd_list[tmp_k]
                                    new_version_list, convert_flag = cpe_map(softname, small_version, big_version, 'from to')
                                    if convert_flag:  # 经过了映射
                                        version_list[tmp_l] = new_version_list
                                elif multi_flag is True:  # 有*
                                    softname = nvd_list[tmp_k]  # 注意修改softname = nvd_list[tmp_k]

                                    # 暂时只分3种情况
                                    # *
                                    if version_list[tmp_l][0].isdigit() is True:  # CVE-2019-1759
                                        #tmp_l = tmp_l + 1  # 测试的代码，要删除------------------
                                        #continue  # 测试的代码，要删除------------------
                                        small_version = version_list[tmp_l].rstrip('*')
                                        new_version_list, convert_flag = cpe_map(softname, small_version, small_version, '*')
                                        if convert_flag:  # 经过了映射
                                            version_list[tmp_l] = new_version_list
                                    # >=*
                                    elif version_list[tmp_l][0] == '>':  # CVE-2017-7656
                                        #tmp_l = tmp_l + 1  # 测试的代码，要删除------------------
                                        #continue  # 测试的代码，要删除------------------
                                        small_version = version_list[tmp_l].lstrip('>=').rstrip('*')
                                        new_version_list, convert_flag = cpe_map(softname, small_version, small_version, '>=*')
                                        if convert_flag:  # 经过了映射
                                            version_list[tmp_l] = new_version_list
                                    # <=*
                                    elif version_list[tmp_l][0] == '<':  # CVE-2018-14504
                                        #tmp_l = tmp_l + 1  # 测试的代码，要删除------------------
                                        #continue  # 测试的代码，要删除------------------
                                        small_version = version_list[tmp_l].lstrip('<=').rstrip('*')
                                        new_version_list, convert_flag = cpe_map(softname, small_version, small_version, '<=*')
                                        if convert_flag:  # 经过了映射
                                            version_list[tmp_l] = new_version_list

                                # “ > <”等条件语句放在elif multi_flag is True的后面，优先判断后者
                                # <=xx版本
                                elif version_list[tmp_l].find('<=') != -1:  # CVE-2016-1683
                                    #tmp_l = tmp_l + 1  # 测试的代码，要删除------------------
                                    #continue  # 测试的代码，要删除------------------
                                    small_version = version_list[tmp_l].strip('<=')
                                    softname = nvd_list[tmp_k]  # 注意修改softname = nvd_list[tmp_k]
                                    new_version_list, convert_flag = cpe_map(softname, small_version, small_version, '<=')
                                    if convert_flag:  # 经过了映射
                                        version_list[tmp_l] = new_version_list
                                # <xx版本
                                elif version_list[tmp_l].find('<') != -1:
                                    #tmp_l = tmp_l + 1  # 测试的代码，要删除------------------
                                    #continue  # 测试的代码，要删除------------------
                                    small_version = version_list[tmp_l].strip('<')
                                    softname = nvd_list[tmp_k]  # 注意修改softname = nvd_list[tmp_k]
                                    new_version_list, convert_flag = cpe_map(softname, small_version, small_version, '<')
                                    if convert_flag:  # 经过了映射
                                        version_list[tmp_l] = new_version_list
                                # >=xx版本
                                elif version_list[tmp_l].find('>=') != -1:
                                    #tmp_l = tmp_l + 1  # 测试的代码，要删除------------------
                                    #continue  # 测试的代码，要删除------------------
                                    small_version = version_list[tmp_l].strip('>=')
                                    softname = nvd_list[tmp_k]  # 注意修改softname = nvd_list[tmp_k]
                                    new_version_list, convert_flag = cpe_map(softname, small_version, small_version, '>=')
                                    if convert_flag:  # 经过了映射
                                        version_list[tmp_l] = new_version_list
                                # >xx版本
                                elif version_list[tmp_l].find('>') != -1:
                                    #tmp_l = tmp_l + 1  # 测试的代码，要删除------------------
                                    #continue  # 测试的代码，要删除------------------
                                    small_version = version_list[tmp_l].strip('>')
                                    softname = nvd_list[tmp_k]  # 注意修改softname = nvd_list[tmp_k]
                                    new_version_list, convert_flag = cpe_map(softname, small_version, small_version, '>')
                                    if convert_flag:  # 经过了映射
                                        version_list[tmp_l] = new_version_list
                            tmp_l = tmp_l + 1
                        nvd_soft[nvd_list[tmp_k]] = version_list  # 修改字典中的值
                    tmp_k = tmp_k + 1

    # 保存在本地
    cve_and_nvd_soft_path = os.getcwd() + '/data/softname_version_compare/'  # 文件夹
    cve_and_nvd_soft_filename = '4_map_version_of_cve_and_nvd.txt'  # 这样命名方便查看
    print_name_and_version_filename = '4_map_version_of_cve_and_nvd_print.txt'
    cve_and_nvd_soft_file_path = os.path.join('%s%s' % (cve_and_nvd_soft_path, cve_and_nvd_soft_filename))
    print_name_and_version_file_path = os.path.join('%s%s' % (cve_and_nvd_soft_path, print_name_and_version_filename))
    # 字典原始格式保存在本地
    with open(cve_and_nvd_soft_file_path, 'w', encoding='utf-8') as name_and_version_f:  # 用w而非a，用于覆盖
        name_and_version_f.write('name_and_version_dict=' + str(soft_dict))  # 写入数据
    # 为了方便观察，以较好的格式另外保存到一个文件中
    for j in soft_dict:
        with open(print_name_and_version_file_path, 'a', encoding='utf-8') as print_name_and_version_f:  # 用a，用于追加
            print_name_and_version_f.write(j + ' ' + str(soft_dict[j]) + '\n')  # 写入数据


# 将软件版本list中的字符串提取出来，便于之后的版本比较，win内存不够大，一次加载字典可能出错，所以用json加载数据，
# 本函数之前（行数小于本函数）的函数如果报字典加载内存不够的Error，那么也可以像该函数用json加载
def get_str_version_of_cve_and_nvd():
    # 获取softname和version内容
    soft_dic_path = os.getcwd() + '/data/softname_version_compare/'  # 存放的文件夹
    soft_dic_filename = '4_map_version_of_cve_and_nvd.txt'
    soft_dic_name = os.path.join('%s%s' % (soft_dic_path, soft_dic_filename))
    soft_dict = dict()
    with open(soft_dic_name, 'r', encoding='UTF-8') as soft_f:  # 打开文件
        soft_lines = soft_f.readlines()  # 获取文件的所有行
        for soft_line in soft_lines:
            soft_raw = soft_line
            soft_raw = soft_raw.lstrip('name_and_version_dict=')
            soft_dict = ast.literal_eval(soft_raw)
            # 不能通过ast.literal_eval转化为字典，数据量太大会导致memory error  soft_dict = ast.literal_eval(soft_raw)

            cveid_cnt = 0
            for cveid in soft_dict:
                cveid_cnt = cveid_cnt + 1
                print('CVEID：' + str(cveid) + '    CVEID的数量：' + str(cveid_cnt) + '\n')
                cve_soft = soft_dict[cveid]['cve']
                nvd_soft = soft_dict[cveid]['nvd']

                # 处理NVD
                tmp_i = 0
                nvd_list = list(nvd_soft.keys())
                while tmp_i < len(nvd_list):
                    if len(nvd_list[tmp_i]) > 0:  # 软件名长度>0
                        version_list = nvd_soft[nvd_list[tmp_i]]  # 该软件名的版本列表
                        tmp_j = 0
                        len_version_list = len(version_list)
                        remove_list_index = []  # 如果version_list[tmp_j]为list，则记录tmp_j到该list中
                        while tmp_j < len_version_list:
                            if len(version_list[tmp_j]) > 0:  # 版本长度>0
                                # 如果为list，需要把list里的字符串提取出来
                                if isinstance(version_list[tmp_j], list):
                                    for v in version_list[tmp_j]:
                                        ver = v
                                        if (ver[0] == 'v')or (ver[0] == 'V'):  # v2.5改为2.5
                                            ver = ver[1:]
                                        version_list.append(ver)
                                    remove_list_index.append(tmp_j)
                                else:
                                    vv = version_list[tmp_j]
                                    if (vv[0] == 'v') or (vv[0] == 'V'):  # v2.5改为2.5
                                        vv = vv[1:]
                                    version_list[tmp_j] = vv
                            tmp_j = tmp_j + 1
                        # 删除version_list中索引为remove_list_index的元素
                        a_index = [i for i in range(len(version_list))]
                        a_index = set(a_index)
                        b_index = set(remove_list_index)
                        c_index = list(a_index - b_index)
                        tmp_list = [version_list[i] for i in c_index]
                        final_list = []  # 去重
                        for i in tmp_list:
                            if i not in final_list:
                                final_list.append(i)
                        version_list = sorted(final_list)  # 排序存放
                        print(cveid+' nvd\n')
                        nvd_soft[nvd_list[tmp_i]] = version_list   # 修改字典中的值
                    tmp_i = tmp_i + 1

                # 处理cve
                tmp_k = 0
                cve_list = list(cve_soft.keys())
                while tmp_k < len(cve_list):
                    if len(cve_list[tmp_k]) > 0:  # 软件名长度>0
                        version_list = cve_soft[cve_list[tmp_k]]  # 该软件名的版本列表
                        tmp_l = 0
                        len_version_list = len(version_list)
                        remove_list_index = []  # 如果version_list[tmp_j]为list，则记录tmp_j到该list中
                        while tmp_l < len_version_list:
                            if len(version_list[tmp_l]) > 0:  # 版本长度>0
                                # 如果为list，需要把list里的字符串提取出来
                                if isinstance(version_list[tmp_l], list):
                                    for v in version_list[tmp_l]:
                                        version_list.append(v)
                                    remove_list_index.append(tmp_l)
                            tmp_l = tmp_l + 1
                        # 删除version_list中索引为remove_list_index的元素
                        a_index = [i for i in range(len(version_list))]
                        a_index = set(a_index)
                        b_index = set(remove_list_index)
                        c_index = list(a_index - b_index)
                        tmp_list = [version_list[i] for i in c_index]
                        final_list = []  # 去重
                        for i in tmp_list:
                            if i not in final_list:
                                final_list.append(i)
                        version_list = sorted(final_list)  # 排序存放
                        print(cveid + ' cve\n')
                        cve_soft[cve_list[tmp_k]] = version_list   # 修改字典中的值
                    tmp_k = tmp_k + 1

    # 不必类似nvd_parser.py保存json里的数据到另一个dict中
    # 保存在本地
    cve_and_nvd_soft_path = os.getcwd() + '/data/softname_version_compare/'  # 文件夹
    cve_and_nvd_soft_filename = '5_get_str_version_of_cve_and_nvd.txt'  # 这样命名方便查看
    print_name_and_version_filename = '5_get_str_version_of_cve_and_nvd_print.txt'
    cve_and_nvd_soft_file_path = os.path.join('%s%s' % (cve_and_nvd_soft_path, cve_and_nvd_soft_filename))
    print_name_and_version_file_path = os.path.join('%s%s' % (cve_and_nvd_soft_path, print_name_and_version_filename))
    # 字典原始格式保存在本地
    with open(cve_and_nvd_soft_file_path, 'w', encoding='utf-8') as name_and_version_f:  # 用w而非a，用于覆盖
        name_and_version_f.write('name_and_version_dict=' + str(soft_dict))  # 写入数据
    # 为了方便观察，以较好的格式另外保存到一个文件中
    for j in soft_dict:
        with open(print_name_and_version_file_path, 'a', encoding='utf-8') as print_name_and_version_f:  # 用a，用于追加
            print_name_and_version_f.write(j + ' ' + str(soft_dict[j]) + '\n')  # 写入数据


# 去除版本号为空的或者''或者'*'所对应的软件名称
def remove_bad_version_first():
    # 获取softname和version内容
    soft_dic_path = os.getcwd() + '/data/softname_version_compare/'  # 存放的文件夹
    soft_dic_filename = '5_get_str_version_of_cve_and_nvd.txt'
    soft_dic_name = os.path.join('%s%s' % (soft_dic_path, soft_dic_filename))
    soft_dict = dict()

    # 首先去除版本号为空的或者''或者'*'所对应的软件名称
    with open(soft_dic_name, 'r', encoding='UTF-8') as soft_f:  # 打开文件
        soft_lines = soft_f.readlines()  # 获取文件的所有行
        for soft_line in soft_lines:
            soft_raw = soft_line
            soft_raw = soft_raw.lstrip('name_and_version_dict=')
            soft_dict = ast.literal_eval(soft_raw)

            cveid_cnt = 0
            for cveid in soft_dict:
                cveid_cnt = cveid_cnt + 1
                print('CVEID：' + str(cveid) + '    CVEID的数量：' + str(cveid_cnt) + '\n')
                cve_soft = soft_dict[cveid]['cve']
                nvd_soft = soft_dict[cveid]['nvd']

                # 处理cve
                tmp_i = 0
                cve_list = list(cve_soft.keys())
                while tmp_i < len(cve_list):
                    if len(cve_list[tmp_i]) > 0:  # 软件名长度>0
                        version_list = cve_soft[cve_list[tmp_i]]  # 该软件名的版本列表
                        if version_list:
                            bad_version = ['', '*', '-']
                            if len(version_list) == 1:
                                if version_list[0] in bad_version:
                                    del cve_soft[cve_list[tmp_i]]
                        else:  # 为空
                            del cve_soft[cve_list[tmp_i]]
                    tmp_i = tmp_i + 1

                #  处理NVD，与cve类似
                tmp_k = 0
                nvd_list = list(nvd_soft.keys())
                while tmp_k < len(nvd_list):
                    if len(nvd_list[tmp_k]) > 0:  # 软件名长度>0
                        version_list = nvd_soft[nvd_list[tmp_k]]  # 该软件名的版本列表
                        if version_list:
                            bad_version = ['', '*', '-']
                            if len(version_list) == 1:
                                if version_list[0] in bad_version:
                                    del nvd_soft[nvd_list[tmp_k]]
                        else:  # 为空
                            del nvd_soft[nvd_list[tmp_k]]
                    tmp_k = tmp_k + 1

    # 保存在本地
    cve_and_nvd_soft_path = os.getcwd() + '/data/softname_version_compare/'  # 文件夹
    cve_and_nvd_soft_filename = '6_remove_bad_version_first.txt'  # 这样命名方便查看
    print_name_and_version_filename = '6_remove_bad_version_first_print.txt'
    cve_and_nvd_soft_file_path = os.path.join('%s%s' % (cve_and_nvd_soft_path, cve_and_nvd_soft_filename))
    print_name_and_version_file_path = os.path.join('%s%s' % (cve_and_nvd_soft_path, print_name_and_version_filename))
    # 字典原始格式保存在本地
    with open(cve_and_nvd_soft_file_path, 'w', encoding='utf-8') as name_and_version_f:  # 用w而非a，用于覆盖
        name_and_version_f.write('name_and_version_dict=' + str(soft_dict))  # 写入数据
    # 为了方便观察，以较好的格式另外保存到一个文件中
    for j in soft_dict:
        with open(print_name_and_version_file_path, 'a', encoding='utf-8') as print_name_and_version_f:  # 用a，用于追加
            print_name_and_version_f.write(j + ' ' + str(soft_dict[j]) + '\n')  # 写入数据


# 保留相同软件名称的数据项，类似函数keep_same_version_of_cve_and_nvd()
def remove_bad_version_second():
    # 获取softname和version内容
    soft_dic_path = os.getcwd() + '/data/softname_version_compare/'  # 存放的文件夹
    soft_dic_filename = '6_remove_bad_version_first.txt'
    soft_dic_name = os.path.join('%s%s' % (soft_dic_path, soft_dic_filename))
    soft_dict = dict()

    # 保留相同软件名称的数据项，类似函数keep_same_version_of_cve_and_nvd()
    with open(soft_dic_name, 'r', encoding='UTF-8') as soft_f:  # 打开文件
        soft_lines = soft_f.readlines()  # 获取文件的所有行
        for soft_line in soft_lines:
            soft_raw = soft_line
            soft_raw = soft_raw.lstrip('name_and_version_dict=')
            soft_dict = ast.literal_eval(soft_raw)

            cveid_cnt = 0
            for cveid in soft_dict:
                cveid_cnt = cveid_cnt + 1
                print('CVEID：' + str(cveid) + '    CVEID的数量：' + str(cveid_cnt) + '\n')
                cve_soft = soft_dict[cveid]['cve']
                nvd_soft = soft_dict[cveid]['nvd']
                # 只保留相同的软件名的数据项
                tmp_i = 0
                # 只对字典处理，不对空的字符串处理
                if isinstance(cve_soft, dict):
                    cve_list = list(cve_soft.keys())
                    while tmp_i < len(cve_list):
                        if cve_list[tmp_i] not in nvd_soft:
                            del cve_soft[cve_list[tmp_i]]
                        tmp_i = tmp_i + 1

                tmp_j = 0
                # 只对字典处理，不对空的字符串处理
                if isinstance(nvd_soft, dict):
                    nvd_list = list(nvd_soft.keys())
                    while tmp_j < len(nvd_list):
                        if nvd_list[tmp_j] not in cve_soft:
                            del nvd_soft[nvd_list[tmp_j]]
                        tmp_j = tmp_j + 1

    # 去除没有数据项的CVEID对应的数据
    tmp_k = 0
    soft_list = list(soft_dict.keys())
    while tmp_k < len(soft_list):
        cve_soft = soft_dict[soft_list[tmp_k]]['cve']
        nvd_soft = soft_dict[soft_list[tmp_k]]['nvd']
        if (not cve_soft) or (nvd_soft == ''):  # 为空则去掉
            del soft_dict[soft_list[tmp_k]]
        tmp_k = tmp_k + 1

    # 保存在本地
    cve_and_nvd_soft_path = os.getcwd() + '/data/softname_version_compare/'  # 文件夹
    cve_and_nvd_soft_filename = '7_remove_bad_version_second.txt'  # 这样命名方便查看
    print_name_and_version_filename = '7_remove_bad_version_second_print.txt'
    cve_and_nvd_soft_file_path = os.path.join('%s%s' % (cve_and_nvd_soft_path, cve_and_nvd_soft_filename))
    print_name_and_version_file_path = os.path.join('%s%s' % (cve_and_nvd_soft_path, print_name_and_version_filename))
    # 字典原始格式保存在本地
    with open(cve_and_nvd_soft_file_path, 'w', encoding='utf-8') as name_and_version_f:  # 用w而非a，用于覆盖
        name_and_version_f.write('name_and_version_dict=' + str(soft_dict))  # 写入数据
    # 为了方便观察，以较好的格式另外保存到一个文件中
    for j in soft_dict:
        with open(print_name_and_version_file_path, 'a', encoding='utf-8') as print_name_and_version_f:  # 用a，用于追加
            print_name_and_version_f.write(j + ' ' + str(soft_dict[j]) + '\n')  # 写入数据


# 测量一致性，指标分为测量的总体指标和详细指标
def measure_inconsistency():
    # 获取softname和version内容
    soft_dic_path = os.getcwd() + '/data/softname_version_compare/'  # 存放的文件夹
    soft_dic_filename = '7_remove_bad_version_second.txt'
    soft_dic_name = os.path.join('%s%s' % (soft_dic_path, soft_dic_filename))
    soft_dict = dict()
    with open(soft_dic_name, 'r', encoding='UTF-8') as soft_f:  # 打开文件
        soft_lines = soft_f.readlines()  # 获取文件的所有行
        for soft_line in soft_lines:
            soft_raw = soft_line
            soft_raw = soft_raw.lstrip('name_and_version_dict=')
            soft_dict = ast.literal_eval(soft_raw)

            cveid_cnt = 0
            for cveid in soft_dict:
                cveid_cnt = cveid_cnt + 1
                print('CVEID：' + str(cveid) + '    CVEID的数量：' + str(cveid_cnt) + '\n')
                # 把原来的值装到“子键”soft中
                cve_origin_soft = copy.deepcopy(soft_dict[cveid]['cve'])  # 深拷贝，直接赋值会使得cve_overall_soft['soft'] = dict()也对cve_origin_soft添加了键'soft'
                cve_overall_soft = soft_dict[cveid]['cve']
                cve_overall_soft['soft'] = dict()
                cve_overall_soft['soft'] = cve_origin_soft  # 把原来的值装到“子键”soft中
                for i in cve_origin_soft:
                    del cve_overall_soft[i]
                nvd_overall_soft = soft_dict[cveid]['nvd']

                # 初始化测量的总体指标
                soft_dict[cveid]['overall_loose_match'] = []
                soft_dict[cveid]['overall_strict_match'] = ''
                # 初始化测量的详细指标
                cve_overall_soft['detail_loose_match'] = dict()
                cve_overall_soft['detail_strict_match'] = dict()

                # 开始比较
                nvd_contains_cve = False  # cve的版本是nvd的子集或相等，默认不是
                cve_contains_nvd = False  # nvd的版本是cve的子集或相等，默认不是
                overall_loose_match = False  # 所有软件版本都松匹配，默认不是
                overall_loose_match_exact = 'a'  # 为了说明overall_loose_match的情况具体为exact或者其他，不要初始化为False或True
                overall_loose_match_overclaim = 'a'
                overall_loose_match_underclaim = 'a'
                overall_strict_match = False  # 所有软件版本都严匹配，默认不是
                tmp_k = 0
                cve_list = list(cve_overall_soft['soft'].keys())
                while tmp_k < len(cve_list):
                    if len(cve_list[tmp_k]) > 0:  # 软件名长度>0
                        cve_version_list = []
                        nvd_version_list = []
                        cve_version_list = cve_overall_soft['soft'][cve_list[tmp_k]]  # cve的软件名的版本列表
                        if cve_list[tmp_k] in nvd_overall_soft:
                            nvd_version_list = nvd_overall_soft[cve_list[tmp_k]]  # nvd的软件名的版本列表
                        if set(cve_version_list) <= set(nvd_version_list):
                            nvd_contains_cve = True
                        if set(nvd_version_list) <= set(cve_version_list):
                            cve_contains_nvd = True
                        softname = cve_list[tmp_k]  # 软件名
                        if (nvd_contains_cve is True) and (cve_contains_nvd is True):  # 匹配
                            overall_loose_match = True
                            overall_loose_match_exact = True
                            overall_strict_match = True
                            cve_overall_soft['detail_loose_match'][softname] = [True, 'Exact']
                            cve_overall_soft['detail_strict_match'][softname] = True
                        elif (nvd_contains_cve is True) and (cve_contains_nvd is False):  # 高估
                            overall_loose_match = True
                            overall_loose_match_exact = False
                            overall_loose_match_overclaim = True
                            overall_strict_match = False
                            cve_overall_soft['detail_loose_match'][softname] = [True, 'Overclaim']  # nvd相对于cve高估了版本
                            cve_overall_soft['detail_strict_match'][softname] = False
                        elif (nvd_contains_cve is False) and (cve_contains_nvd is True):  # 低估
                            overall_loose_match = True
                            overall_loose_match_exact = False
                            overall_loose_match_underclaim = True
                            overall_strict_match = False
                            cve_overall_soft['detail_loose_match'][softname] = [True, 'Underclaim']  # nvd相对于cve低估了版本
                            cve_overall_soft['detail_strict_match'][softname] = False
                        elif (nvd_contains_cve is False) and (cve_contains_nvd is False):  # 不属于前三种情况
                            overall_loose_match = False
                            overall_loose_match_exact = False
                            overall_strict_match = False
                            cve_overall_soft['detail_loose_match'][softname] = [False, '']
                            cve_overall_soft['detail_strict_match'][softname] = False
                    tmp_k = tmp_k + 1

                # 总体的测量结果
                if overall_loose_match is True:
                    soft_dict[cveid]['overall_loose_match'].append(True)
                    if overall_loose_match_exact is True:
                        soft_dict[cveid]['overall_loose_match'].append('Exact')
                    elif (overall_loose_match_overclaim is True) and (overall_loose_match_underclaim is True):
                        soft_dict[cveid]['overall_loose_match'].append('Both Overclaim and Underclaim')
                    elif (overall_loose_match_overclaim is False or overall_loose_match_overclaim == 'a') and (overall_loose_match_underclaim is True):  # 'a'为初始化的值
                        soft_dict[cveid]['overall_loose_match'].append('Underclaim')
                    elif (overall_loose_match_overclaim is True) and (overall_loose_match_underclaim is False or overall_loose_match_underclaim == 'a'):
                        soft_dict[cveid]['overall_loose_match'].append('Overclaim')
                elif overall_loose_match is False:
                    soft_dict[cveid]['overall_loose_match'].append(False)
                    soft_dict[cveid]['overall_loose_match'].append('')

                if overall_strict_match is True:
                    soft_dict[cveid]['overall_strict_match'] = True
                elif overall_strict_match is False:
                    soft_dict[cveid]['overall_strict_match'] = False

    # 保存在本地
    cve_and_nvd_soft_path = os.getcwd() + '/data/softname_version_compare/'  # 文件夹
    cve_and_nvd_soft_filename = '8_measure_inconsistency.txt'  # 这样命名方便查看
    print_name_and_version_filename = '8_measure_inconsistency_print.txt'
    cve_and_nvd_soft_file_path = os.path.join('%s%s' % (cve_and_nvd_soft_path, cve_and_nvd_soft_filename))
    print_name_and_version_file_path = os.path.join('%s%s' % (cve_and_nvd_soft_path, print_name_and_version_filename))
    # 字典原始格式保存在本地
    with open(cve_and_nvd_soft_file_path, 'w', encoding='utf-8') as name_and_version_f:  # 用w而非a，用于覆盖
        name_and_version_f.write('name_and_version_dict=' + str(soft_dict))  # 写入数据
    # 为了方便观察，以较好的格式另外保存到一个文件中
    for j in soft_dict:
        with open(print_name_and_version_file_path, 'a', encoding='utf-8') as print_name_and_version_f:  # 用a，用于追加
            print_name_and_version_f.write(j + ' ' + str(soft_dict[j]) + '\n')  # 写入数据


# 获取总体的测试结果，在服务器运行该代码
def get_result_overall():
    # 获取softname和version内容
    soft_dic_path = os.getcwd() + '/data/softname_version_compare/'  # 存放的文件夹
    soft_dic_filename = '8_measure_inconsistency.txt'
    soft_dic_name = os.path.join('%s%s' % (soft_dic_path, soft_dic_filename))
    soft_dict = dict()
    with open(soft_dic_name, 'r', encoding='UTF-8') as soft_f:  # 打开文件
        soft_lines = soft_f.readlines()  # 获取文件的所有行
        for soft_line in soft_lines:
            soft_raw = soft_line
            soft_raw = soft_raw.lstrip('name_and_version_dict=')
            # json格式加载失败，https://www.json.cn/提示RangeError: Invalid array length
            # soft_replace = re.sub('\'', '\"', soft_raw)
            # soft_dict = json.loads(soft_replace)
            soft_dict = ast.literal_eval(soft_raw)

            # 严格匹配参数
            cve_overall_strict_match_true_cnt = 0
            cve_overall_strict_match_false_cnt = 0
            # 松散匹配参数
            cve_overall_loose_match_true_cnt = 0
            cve_overall_loose_match_false_cnt = 0
            cve_overall_loose_match_true_overclaim_cnt = 0
            cve_overall_loose_match_true_underclaim_cnt = 0
            cve_overall_loose_match_true_both_cnt = 0

            for cveid in soft_dict:
                print(cveid + '\n')
                cve_overall_soft = soft_dict[cveid]

                # 严格匹配
                cve_overall_strict_match = cve_overall_soft['overall_strict_match']
                if cve_overall_strict_match is True:
                    cve_overall_strict_match_true_cnt = cve_overall_strict_match_true_cnt + 1
                elif cve_overall_strict_match is False:
                    cve_overall_strict_match_false_cnt = cve_overall_strict_match_false_cnt + 1

                # 松散匹配
                cve_overall_loose_match = cve_overall_soft['overall_loose_match']
                if cve_overall_loose_match[0] is True:
                    cve_overall_loose_match_true_cnt = cve_overall_loose_match_true_cnt + 1
                    if cve_overall_loose_match[1] == 'Overclaim':
                        cve_overall_loose_match_true_overclaim_cnt = cve_overall_loose_match_true_overclaim_cnt + 1
                    elif cve_overall_loose_match[1] == 'Underclaim':
                        cve_overall_loose_match_true_underclaim_cnt = cve_overall_loose_match_true_underclaim_cnt + 1
                    elif cve_overall_loose_match[1] == 'Both Overclaim and Underclaim':
                        cve_overall_loose_match_true_both_cnt = cve_overall_loose_match_true_both_cnt + 1
                elif cve_overall_loose_match[0] is False:
                    cve_overall_loose_match_false_cnt = cve_overall_loose_match_false_cnt + 1

    cve_overall_strict_match_cnt = cve_overall_strict_match_true_cnt + cve_overall_strict_match_false_cnt
    print('严格匹配：\n')
    print('严格匹配正确的CVEID数量：' + str(cve_overall_strict_match_true_cnt) + '\n')
    print('严格匹配正确率：' + str(cve_overall_strict_match_true_cnt / cve_overall_strict_match_cnt) + '\n')
    print('严格匹配错误的CVEID数量：' + str(cve_overall_strict_match_false_cnt) + '\n')
    print('严格匹配错误率：' + str(cve_overall_strict_match_false_cnt / cve_overall_strict_match_cnt) + '\n')

    overall_loose_match_cnt = cve_overall_loose_match_true_cnt + cve_overall_loose_match_false_cnt
    print('松散匹配：\n')
    print('松散匹配正确的CVEID数量：' + str(cve_overall_loose_match_true_cnt) + '\n')
    print('松散匹配正确率：' + str(cve_overall_loose_match_true_cnt / overall_loose_match_cnt) + '\n')
    print('松散匹配错误的CVEID数量：' + str(cve_overall_loose_match_false_cnt) + '\n')
    print('松散匹配错误率：' + str(cve_overall_loose_match_false_cnt / overall_loose_match_cnt) + '\n')

    cve_overall_loose_match_cnt = cve_overall_loose_match_true_overclaim_cnt + cve_overall_loose_match_true_underclaim_cnt + cve_overall_loose_match_true_both_cnt
    print('松散匹配正确且具体为Overclaim的CVEID数量：' + str(cve_overall_loose_match_true_overclaim_cnt) + '\n')
    print('松散匹配正确且具体为Overclaim的比率：' + str(cve_overall_loose_match_true_overclaim_cnt/cve_overall_loose_match_cnt) + '\n')
    print('松散匹配正确且具体为Underclaim的CVEID数量：' + str(cve_overall_loose_match_true_underclaim_cnt) + '\n')
    print('松散匹配正确且具体为Underclaim的比率：' + str(cve_overall_loose_match_true_underclaim_cnt/cve_overall_loose_match_cnt) + '\n')
    print('松散匹配正确且具体为Both Overclaim and Underclaim的CVEID数量：' + str(cve_overall_loose_match_true_both_cnt) + '\n')
    print('松散匹配正确且具体为Both Overclaim and Underclaim的比率：' + str(cve_overall_loose_match_true_both_cnt/cve_overall_loose_match_cnt) + '\n')

    # 保存在本地
    cve_and_nvd_soft_path = os.getcwd() + '/data/softname_version_compare/'  # 文件夹
    cve_and_nvd_soft_filename = '9_get_result_overall.txt'  # 这样命名方便查看
    cve_and_nvd_soft_file_path = os.path.join('%s%s' % (cve_and_nvd_soft_path, cve_and_nvd_soft_filename))
    # 字典原始格式保存在本地
    with open(cve_and_nvd_soft_file_path, 'w', encoding='utf-8') as name_and_version_f:  # 用w而非a，用于覆盖
        name_and_version_f.write('严格匹配：\n')  # 写入数据
        name_and_version_f.write('严格匹配正确的CVEID数量：' + str(cve_overall_strict_match_true_cnt) + '\n')
        name_and_version_f.write('严格匹配正确率：' + str(cve_overall_strict_match_true_cnt / cve_overall_strict_match_cnt) + '\n')
        name_and_version_f.write('严格匹配错误的CVEID数量：' + str(cve_overall_strict_match_false_cnt) + '\n')
        name_and_version_f.write('严格匹配错误率：' + str(cve_overall_strict_match_false_cnt / cve_overall_strict_match_cnt) + '\n')

        name_and_version_f.write('\n松散匹配：\n')
        name_and_version_f.write('松散匹配正确的CVEID数量：' + str(cve_overall_loose_match_true_cnt) + '\n')
        name_and_version_f.write('松散匹配正确率：' + str(cve_overall_loose_match_true_cnt / overall_loose_match_cnt) + '\n')
        name_and_version_f.write('松散匹配错误的CVEID数量：' + str(cve_overall_loose_match_false_cnt) + '\n')
        name_and_version_f.write('松散匹配错误率：' + str(cve_overall_loose_match_false_cnt / overall_loose_match_cnt) + '\n')

        name_and_version_f.write('松散匹配正确且具体为Overclaim的CVEID数量：' + str(cve_overall_loose_match_true_overclaim_cnt) + '\n')
        name_and_version_f.write('松散匹配正确且具体为Overclaim的比率：' + str(cve_overall_loose_match_true_overclaim_cnt/cve_overall_loose_match_cnt) + '\n')
        name_and_version_f.write('松散匹配正确且具体为Underclaim的CVEID数量：' + str(cve_overall_loose_match_true_underclaim_cnt) + '\n')
        name_and_version_f.write('松散匹配正确且具体为Underclaim的比率：' + str(cve_overall_loose_match_true_underclaim_cnt/cve_overall_loose_match_cnt) + '\n')
        name_and_version_f.write('松散匹配正确且具体为Both Overclaim and Underclaim的CVEID数量：' + str(cve_overall_loose_match_true_both_cnt) + '\n')
        name_and_version_f.write('松散匹配正确且具体为Both Overclaim and Underclaim的比率：' + str(cve_overall_loose_match_true_both_cnt/cve_overall_loose_match_cnt) + '\n')


# 获取一致性随时间变化的结果，在服务器运行该代码
def get_result_by_year():
    # 获取softname和version内容
    soft_dic_path = os.getcwd() + '/data/softname_version_compare/'  # 存放的文件夹
    soft_dic_filename = '8_measure_inconsistency.txt'
    soft_dic_name = os.path.join('%s%s' % (soft_dic_path, soft_dic_filename))
    soft_dict = dict()

    # 严格匹配参数
    cve_overall_strict_match_true_cnt_2019 = 0
    cve_overall_strict_match_false_cnt_2019 = 0
    cve_overall_strict_match_true_cnt_2018 = 0
    cve_overall_strict_match_false_cnt_2018 = 0
    cve_overall_strict_match_true_cnt_2017 = 0
    cve_overall_strict_match_false_cnt_2017 = 0
    cve_overall_strict_match_true_cnt_2016 = 0
    cve_overall_strict_match_false_cnt_2016 = 0
    cve_overall_strict_match_true_cnt_2015 = 0
    cve_overall_strict_match_false_cnt_2015 = 0
    cve_overall_strict_match_true_cnt_2014 = 0
    cve_overall_strict_match_false_cnt_2014 = 0
    cve_overall_strict_match_true_cnt_2013 = 0
    cve_overall_strict_match_false_cnt_2013 = 0
    cve_overall_strict_match_true_cnt_2012 = 0
    cve_overall_strict_match_false_cnt_2012 = 0
    cve_overall_strict_match_true_cnt_2011 = 0
    cve_overall_strict_match_false_cnt_2011 = 0
    cve_overall_strict_match_true_cnt_2010 = 0
    cve_overall_strict_match_false_cnt_2010 = 0
    cve_overall_strict_match_true_cnt_2009 = 0
    cve_overall_strict_match_false_cnt_2009 = 0
    cve_overall_strict_match_true_cnt_2008 = 0
    cve_overall_strict_match_false_cnt_2008 = 0
    cve_overall_strict_match_true_cnt_2007 = 0
    cve_overall_strict_match_false_cnt_2007 = 0
    cve_overall_strict_match_true_cnt_2006 = 0
    cve_overall_strict_match_false_cnt_2006 = 0
    cve_overall_strict_match_true_cnt_2005 = 0
    cve_overall_strict_match_false_cnt_2005 = 0
    cve_overall_strict_match_true_cnt_2004 = 0
    cve_overall_strict_match_false_cnt_2004 = 0
    cve_overall_strict_match_true_cnt_2003 = 0
    cve_overall_strict_match_false_cnt_2003 = 0
    cve_overall_strict_match_true_cnt_2002 = 0
    cve_overall_strict_match_false_cnt_2002 = 0
    cve_overall_strict_match_true_cnt_2001 = 0
    cve_overall_strict_match_false_cnt_2001 = 0
    cve_overall_strict_match_true_cnt_2000 = 0
    cve_overall_strict_match_false_cnt_2000 = 0
    cve_overall_strict_match_true_cnt_1999 = 0
    cve_overall_strict_match_false_cnt_1999 = 0
    # 松散匹配参数
    cve_overall_loose_match_true_cnt_2019 = 0
    cve_overall_loose_match_false_cnt_2019 = 0
    cve_overall_loose_match_true_cnt_2018 = 0
    cve_overall_loose_match_false_cnt_2018 = 0
    cve_overall_loose_match_true_cnt_2017 = 0
    cve_overall_loose_match_false_cnt_2017 = 0
    cve_overall_loose_match_true_cnt_2016 = 0
    cve_overall_loose_match_false_cnt_2016 = 0
    cve_overall_loose_match_true_cnt_2015 = 0
    cve_overall_loose_match_false_cnt_2015 = 0
    cve_overall_loose_match_true_cnt_2014 = 0
    cve_overall_loose_match_false_cnt_2014 = 0
    cve_overall_loose_match_true_cnt_2013 = 0
    cve_overall_loose_match_false_cnt_2013 = 0
    cve_overall_loose_match_true_cnt_2012 = 0
    cve_overall_loose_match_false_cnt_2012 = 0
    cve_overall_loose_match_true_cnt_2011 = 0
    cve_overall_loose_match_false_cnt_2011 = 0
    cve_overall_loose_match_true_cnt_2010 = 0
    cve_overall_loose_match_false_cnt_2010 = 0
    cve_overall_loose_match_true_cnt_2009 = 0
    cve_overall_loose_match_false_cnt_2009 = 0
    cve_overall_loose_match_true_cnt_2008 = 0
    cve_overall_loose_match_false_cnt_2008 = 0
    cve_overall_loose_match_true_cnt_2007 = 0
    cve_overall_loose_match_false_cnt_2007 = 0
    cve_overall_loose_match_true_cnt_2006 = 0
    cve_overall_loose_match_false_cnt_2006 = 0
    cve_overall_loose_match_true_cnt_2005 = 0
    cve_overall_loose_match_false_cnt_2005 = 0
    cve_overall_loose_match_true_cnt_2004 = 0
    cve_overall_loose_match_false_cnt_2004 = 0
    cve_overall_loose_match_true_cnt_2003 = 0
    cve_overall_loose_match_false_cnt_2003 = 0
    cve_overall_loose_match_true_cnt_2002 = 0
    cve_overall_loose_match_false_cnt_2002 = 0
    cve_overall_loose_match_true_cnt_2001 = 0
    cve_overall_loose_match_false_cnt_2001 = 0
    cve_overall_loose_match_true_cnt_2000 = 0
    cve_overall_loose_match_false_cnt_2000 = 0
    cve_overall_loose_match_true_cnt_1999 = 0
    cve_overall_loose_match_false_cnt_1999 = 0

    with open(soft_dic_name, 'r', encoding='UTF-8') as soft_f:  # 打开文件
        soft_lines = soft_f.readlines()  # 获取文件的所有行
        for soft_line in soft_lines:
            soft_raw = soft_line
            soft_raw = soft_raw.lstrip('name_and_version_dict=')
            # json格式加载失败，https://www.json.cn/提示RangeError: Invalid array length
            # soft_replace = re.sub('\'', '\"', soft_raw)
            # soft_dict = json.loads(soft_replace)
            soft_dict = ast.literal_eval(soft_raw)

            cveid_cnt = 0
            for cveid in soft_dict:
                cveid_cnt = cveid_cnt + 1
                print('CVEID：' + str(cveid) + '    CVEID的数量：' + str(cveid_cnt) + '\n')
                cve_overall_soft = soft_dict[cveid]

                # 严格匹配
                cve_overall_strict_match = cve_overall_soft['overall_strict_match']
                if cve_overall_strict_match is True:
                    if cveid[4:8] == '2019':
                        cve_overall_strict_match_true_cnt_2019 = cve_overall_strict_match_true_cnt_2019 + 1
                    elif cveid[4:8] == '2018':
                        cve_overall_strict_match_true_cnt_2018 = cve_overall_strict_match_true_cnt_2018 + 1
                    elif cveid[4:8] == '2017':
                        cve_overall_strict_match_true_cnt_2017 = cve_overall_strict_match_true_cnt_2017 + 1
                    elif cveid[4:8] == '2016':
                        cve_overall_strict_match_true_cnt_2016 = cve_overall_strict_match_true_cnt_2016 + 1
                    elif cveid[4:8] == '2015':
                        cve_overall_strict_match_true_cnt_2015 = cve_overall_strict_match_true_cnt_2015 + 1
                    elif cveid[4:8] == '2014':
                        cve_overall_strict_match_true_cnt_2014 = cve_overall_strict_match_true_cnt_2014 + 1
                    elif cveid[4:8] == '2013':
                        cve_overall_strict_match_true_cnt_2013 = cve_overall_strict_match_true_cnt_2013 + 1
                    elif cveid[4:8] == '2012':
                        cve_overall_strict_match_true_cnt_2012 = cve_overall_strict_match_true_cnt_2012 + 1
                    elif cveid[4:8] == '2011':
                        cve_overall_strict_match_true_cnt_2011 = cve_overall_strict_match_true_cnt_2011 + 1
                    elif cveid[4:8] == '2010':
                        cve_overall_strict_match_true_cnt_2010 = cve_overall_strict_match_true_cnt_2010 + 1
                    elif cveid[4:8] == '2009':
                        cve_overall_strict_match_true_cnt_2009 = cve_overall_strict_match_true_cnt_2009 + 1
                    elif cveid[4:8] == '2008':
                        cve_overall_strict_match_true_cnt_2008 = cve_overall_strict_match_true_cnt_2008 + 1
                    elif cveid[4:8] == '2007':
                        cve_overall_strict_match_true_cnt_2007 = cve_overall_strict_match_true_cnt_2007 + 1
                    elif cveid[4:8] == '2006':
                        cve_overall_strict_match_true_cnt_2006 = cve_overall_strict_match_true_cnt_2006 + 1
                    elif cveid[4:8] == '2005':
                        cve_overall_strict_match_true_cnt_2005 = cve_overall_strict_match_true_cnt_2005 + 1
                    elif cveid[4:8] == '2004':
                        cve_overall_strict_match_true_cnt_2004 = cve_overall_strict_match_true_cnt_2004 + 1
                    elif cveid[4:8] == '2003':
                        cve_overall_strict_match_true_cnt_2003 = cve_overall_strict_match_true_cnt_2003 + 1
                    elif cveid[4:8] == '2002':
                        cve_overall_strict_match_true_cnt_2002 = cve_overall_strict_match_true_cnt_2002 + 1
                    elif cveid[4:8] == '2001':
                        cve_overall_strict_match_true_cnt_2001 = cve_overall_strict_match_true_cnt_2001 + 1
                    elif cveid[4:8] == '2000':
                        cve_overall_strict_match_true_cnt_2000 = cve_overall_strict_match_true_cnt_2000 + 1
                    elif cveid[4:8] == '1999':
                        cve_overall_strict_match_true_cnt_1999 = cve_overall_strict_match_true_cnt_1999 + 1
                elif cve_overall_strict_match is False:
                    if cveid[4:8] == '2019':
                        cve_overall_strict_match_false_cnt_2019 = cve_overall_strict_match_false_cnt_2019 + 1
                    elif cveid[4:8] == '2018':
                        cve_overall_strict_match_false_cnt_2018 = cve_overall_strict_match_false_cnt_2018 + 1
                    elif cveid[4:8] == '2017':
                        cve_overall_strict_match_false_cnt_2017 = cve_overall_strict_match_false_cnt_2017 + 1
                    elif cveid[4:8] == '2016':
                        cve_overall_strict_match_false_cnt_2016 = cve_overall_strict_match_false_cnt_2016 + 1
                    elif cveid[4:8] == '2015':
                        cve_overall_strict_match_false_cnt_2015 = cve_overall_strict_match_false_cnt_2015 + 1
                    elif cveid[4:8] == '2014':
                        cve_overall_strict_match_false_cnt_2014 = cve_overall_strict_match_false_cnt_2014 + 1
                    elif cveid[4:8] == '2013':
                        cve_overall_strict_match_false_cnt_2013 = cve_overall_strict_match_false_cnt_2013 + 1
                    elif cveid[4:8] == '2012':
                        cve_overall_strict_match_false_cnt_2012 = cve_overall_strict_match_false_cnt_2012 + 1
                    elif cveid[4:8] == '2011':
                        cve_overall_strict_match_false_cnt_2011 = cve_overall_strict_match_false_cnt_2011 + 1
                    elif cveid[4:8] == '2010':
                        cve_overall_strict_match_false_cnt_2010 = cve_overall_strict_match_false_cnt_2010 + 1
                    elif cveid[4:8] == '2009':
                        cve_overall_strict_match_false_cnt_2009 = cve_overall_strict_match_false_cnt_2009 + 1
                    elif cveid[4:8] == '2008':
                        cve_overall_strict_match_false_cnt_2008 = cve_overall_strict_match_false_cnt_2008 + 1
                    elif cveid[4:8] == '2007':
                        cve_overall_strict_match_false_cnt_2007 = cve_overall_strict_match_false_cnt_2007 + 1
                    elif cveid[4:8] == '2006':
                        cve_overall_strict_match_false_cnt_2006 = cve_overall_strict_match_false_cnt_2006 + 1
                    elif cveid[4:8] == '2005':
                        cve_overall_strict_match_false_cnt_2005 = cve_overall_strict_match_false_cnt_2005 + 1
                    elif cveid[4:8] == '2004':
                        cve_overall_strict_match_false_cnt_2004 = cve_overall_strict_match_false_cnt_2004 + 1
                    elif cveid[4:8] == '2003':
                        cve_overall_strict_match_false_cnt_2003 = cve_overall_strict_match_false_cnt_2003 + 1
                    elif cveid[4:8] == '2002':
                        cve_overall_strict_match_false_cnt_2002 = cve_overall_strict_match_false_cnt_2002 + 1
                    elif cveid[4:8] == '2001':
                        cve_overall_strict_match_false_cnt_2001 = cve_overall_strict_match_false_cnt_2001 + 1
                    elif cveid[4:8] == '2000':
                        cve_overall_strict_match_false_cnt_2000 = cve_overall_strict_match_false_cnt_2000 + 1
                    elif cveid[4:8] == '1999':
                        cve_overall_strict_match_false_cnt_1999 = cve_overall_strict_match_false_cnt_1999 + 1

                # 松散匹配
                cve_overall_loose_match = cve_overall_soft['overall_loose_match']
                if cve_overall_loose_match[0] is True:  # 暂时不记录具体的值，'Overclaim'等
                    if cveid[4:8] == '2019':
                        cve_overall_loose_match_true_cnt_2019 = cve_overall_loose_match_true_cnt_2019 + 1
                    elif cveid[4:8] == '2018':
                        cve_overall_loose_match_true_cnt_2018 = cve_overall_loose_match_true_cnt_2018 + 1
                    elif cveid[4:8] == '2017':
                        cve_overall_loose_match_true_cnt_2017 = cve_overall_loose_match_true_cnt_2017 + 1
                    elif cveid[4:8] == '2016':
                        cve_overall_loose_match_true_cnt_2016 = cve_overall_loose_match_true_cnt_2016 + 1
                    elif cveid[4:8] == '2015':
                        cve_overall_loose_match_true_cnt_2015 = cve_overall_loose_match_true_cnt_2015 + 1
                    elif cveid[4:8] == '2014':
                        cve_overall_loose_match_true_cnt_2014 = cve_overall_loose_match_true_cnt_2014 + 1
                    elif cveid[4:8] == '2013':
                        cve_overall_loose_match_true_cnt_2013 = cve_overall_loose_match_true_cnt_2013 + 1
                    elif cveid[4:8] == '2012':
                        cve_overall_loose_match_true_cnt_2012 = cve_overall_loose_match_true_cnt_2012 + 1
                    elif cveid[4:8] == '2011':
                        cve_overall_loose_match_true_cnt_2011 = cve_overall_loose_match_true_cnt_2011 + 1
                    elif cveid[4:8] == '2010':
                        cve_overall_loose_match_true_cnt_2010 = cve_overall_loose_match_true_cnt_2010 + 1
                    elif cveid[4:8] == '2009':
                        cve_overall_loose_match_true_cnt_2009 = cve_overall_loose_match_true_cnt_2009 + 1
                    elif cveid[4:8] == '2008':
                        cve_overall_loose_match_true_cnt_2008 = cve_overall_loose_match_true_cnt_2008 + 1
                    elif cveid[4:8] == '2007':
                        cve_overall_loose_match_true_cnt_2007 = cve_overall_loose_match_true_cnt_2007 + 1
                    elif cveid[4:8] == '2006':
                        cve_overall_loose_match_true_cnt_2006 = cve_overall_loose_match_true_cnt_2006 + 1
                    elif cveid[4:8] == '2005':
                        cve_overall_loose_match_true_cnt_2005 = cve_overall_loose_match_true_cnt_2005 + 1
                    elif cveid[4:8] == '2004':
                        cve_overall_loose_match_true_cnt_2004 = cve_overall_loose_match_true_cnt_2004 + 1
                    elif cveid[4:8] == '2003':
                        cve_overall_loose_match_true_cnt_2003 = cve_overall_loose_match_true_cnt_2003 + 1
                    elif cveid[4:8] == '2002':
                        cve_overall_loose_match_true_cnt_2002 = cve_overall_loose_match_true_cnt_2002 + 1
                    elif cveid[4:8] == '2001':
                        cve_overall_loose_match_true_cnt_2001 = cve_overall_loose_match_true_cnt_2001 + 1
                    elif cveid[4:8] == '2000':
                        cve_overall_loose_match_true_cnt_2000 = cve_overall_loose_match_true_cnt_2000 + 1
                    elif cveid[4:8] == '1999':
                        cve_overall_loose_match_true_cnt_1999 = cve_overall_loose_match_true_cnt_1999 + 1
                elif cve_overall_loose_match[0] is False:  # 暂时不记录具体的值，'Overclaim'等
                    if cveid[4:8] == '2019':
                        cve_overall_loose_match_false_cnt_2019 = cve_overall_loose_match_false_cnt_2019 + 1
                    elif cveid[4:8] == '2018':
                        cve_overall_loose_match_false_cnt_2018 = cve_overall_loose_match_false_cnt_2018 + 1
                    elif cveid[4:8] == '2017':
                        cve_overall_loose_match_false_cnt_2017 = cve_overall_loose_match_false_cnt_2017 + 1
                    elif cveid[4:8] == '2016':
                        cve_overall_loose_match_false_cnt_2016 = cve_overall_loose_match_false_cnt_2016 + 1
                    elif cveid[4:8] == '2015':
                        cve_overall_loose_match_false_cnt_2015 = cve_overall_loose_match_false_cnt_2015 + 1
                    elif cveid[4:8] == '2014':
                        cve_overall_loose_match_false_cnt_2014 = cve_overall_loose_match_false_cnt_2014 + 1
                    elif cveid[4:8] == '2013':
                        cve_overall_loose_match_false_cnt_2013 = cve_overall_loose_match_false_cnt_2013 + 1
                    elif cveid[4:8] == '2012':
                        cve_overall_loose_match_false_cnt_2012 = cve_overall_loose_match_false_cnt_2012 + 1
                    elif cveid[4:8] == '2011':
                        cve_overall_loose_match_false_cnt_2011 = cve_overall_loose_match_false_cnt_2011 + 1
                    elif cveid[4:8] == '2010':
                        cve_overall_loose_match_false_cnt_2010 = cve_overall_loose_match_false_cnt_2010 + 1
                    elif cveid[4:8] == '2009':
                        cve_overall_loose_match_false_cnt_2009 = cve_overall_loose_match_false_cnt_2009 + 1
                    elif cveid[4:8] == '2008':
                        cve_overall_loose_match_false_cnt_2008 = cve_overall_loose_match_false_cnt_2008 + 1
                    elif cveid[4:8] == '2007':
                        cve_overall_loose_match_false_cnt_2007 = cve_overall_loose_match_false_cnt_2007 + 1
                    elif cveid[4:8] == '2006':
                        cve_overall_loose_match_false_cnt_2006 = cve_overall_loose_match_false_cnt_2006 + 1
                    elif cveid[4:8] == '2005':
                        cve_overall_loose_match_false_cnt_2005 = cve_overall_loose_match_false_cnt_2005 + 1
                    elif cveid[4:8] == '2004':
                        cve_overall_loose_match_false_cnt_2004 = cve_overall_loose_match_false_cnt_2004 + 1
                    elif cveid[4:8] == '2003':
                        cve_overall_loose_match_false_cnt_2003 = cve_overall_loose_match_false_cnt_2003 + 1
                    elif cveid[4:8] == '2002':
                        cve_overall_loose_match_false_cnt_2002 = cve_overall_loose_match_false_cnt_2002 + 1
                    elif cveid[4:8] == '2001':
                        cve_overall_loose_match_false_cnt_2001 = cve_overall_loose_match_false_cnt_2001 + 1
                    elif cveid[4:8] == '2000':
                        cve_overall_loose_match_false_cnt_2000 = cve_overall_loose_match_false_cnt_2000 + 1
                    elif cveid[4:8] == '1999':
                        cve_overall_loose_match_false_cnt_1999 = cve_overall_loose_match_false_cnt_1999 + 1

    # 严格匹配
    cve_overall_strict_match_sum_cnt_2019 = cve_overall_strict_match_true_cnt_2019 + cve_overall_strict_match_false_cnt_2019
    cve_overall_strict_match_sum_cnt_2018 = cve_overall_strict_match_true_cnt_2018 + cve_overall_strict_match_false_cnt_2018
    cve_overall_strict_match_sum_cnt_2017 = cve_overall_strict_match_true_cnt_2017 + cve_overall_strict_match_false_cnt_2017
    cve_overall_strict_match_sum_cnt_2016 = cve_overall_strict_match_true_cnt_2016 + cve_overall_strict_match_false_cnt_2016
    cve_overall_strict_match_sum_cnt_2015 = cve_overall_strict_match_true_cnt_2015 + cve_overall_strict_match_false_cnt_2015
    cve_overall_strict_match_sum_cnt_2014 = cve_overall_strict_match_true_cnt_2014 + cve_overall_strict_match_false_cnt_2014
    cve_overall_strict_match_sum_cnt_2013 = cve_overall_strict_match_true_cnt_2013 + cve_overall_strict_match_false_cnt_2013
    cve_overall_strict_match_sum_cnt_2012 = cve_overall_strict_match_true_cnt_2012 + cve_overall_strict_match_false_cnt_2012
    cve_overall_strict_match_sum_cnt_2011 = cve_overall_strict_match_true_cnt_2011 + cve_overall_strict_match_false_cnt_2011
    cve_overall_strict_match_sum_cnt_2010 = cve_overall_strict_match_true_cnt_2010 + cve_overall_strict_match_false_cnt_2010
    cve_overall_strict_match_sum_cnt_2009 = cve_overall_strict_match_true_cnt_2009 + cve_overall_strict_match_false_cnt_2009
    cve_overall_strict_match_sum_cnt_2008 = cve_overall_strict_match_true_cnt_2008 + cve_overall_strict_match_false_cnt_2008
    cve_overall_strict_match_sum_cnt_2007 = cve_overall_strict_match_true_cnt_2007 + cve_overall_strict_match_false_cnt_2007
    cve_overall_strict_match_sum_cnt_2006 = cve_overall_strict_match_true_cnt_2006 + cve_overall_strict_match_false_cnt_2006
    cve_overall_strict_match_sum_cnt_2005 = cve_overall_strict_match_true_cnt_2005 + cve_overall_strict_match_false_cnt_2005
    cve_overall_strict_match_sum_cnt_2004 = cve_overall_strict_match_true_cnt_2004 + cve_overall_strict_match_false_cnt_2004
    cve_overall_strict_match_sum_cnt_2003 = cve_overall_strict_match_true_cnt_2003 + cve_overall_strict_match_false_cnt_2003
    cve_overall_strict_match_sum_cnt_2002 = cve_overall_strict_match_true_cnt_2002 + cve_overall_strict_match_false_cnt_2002
    cve_overall_strict_match_sum_cnt_2001 = cve_overall_strict_match_true_cnt_2001 + cve_overall_strict_match_false_cnt_2001
    cve_overall_strict_match_sum_cnt_2000 = cve_overall_strict_match_true_cnt_2000 + cve_overall_strict_match_false_cnt_2000
    cve_overall_strict_match_sum_cnt_1999 = cve_overall_strict_match_true_cnt_1999 + cve_overall_strict_match_false_cnt_1999

    # 松散匹配
    cve_overall_loose_match_sum_cnt_2019 = cve_overall_loose_match_true_cnt_2019 + cve_overall_loose_match_false_cnt_2019
    cve_overall_loose_match_sum_cnt_2018 = cve_overall_loose_match_true_cnt_2018 + cve_overall_loose_match_false_cnt_2018
    cve_overall_loose_match_sum_cnt_2017 = cve_overall_loose_match_true_cnt_2017 + cve_overall_loose_match_false_cnt_2017
    cve_overall_loose_match_sum_cnt_2016 = cve_overall_loose_match_true_cnt_2016 + cve_overall_loose_match_false_cnt_2016
    cve_overall_loose_match_sum_cnt_2015 = cve_overall_loose_match_true_cnt_2015 + cve_overall_loose_match_false_cnt_2015
    cve_overall_loose_match_sum_cnt_2014 = cve_overall_loose_match_true_cnt_2014 + cve_overall_loose_match_false_cnt_2014
    cve_overall_loose_match_sum_cnt_2013 = cve_overall_loose_match_true_cnt_2013 + cve_overall_loose_match_false_cnt_2013
    cve_overall_loose_match_sum_cnt_2012 = cve_overall_loose_match_true_cnt_2012 + cve_overall_loose_match_false_cnt_2012
    cve_overall_loose_match_sum_cnt_2011 = cve_overall_loose_match_true_cnt_2011 + cve_overall_loose_match_false_cnt_2011
    cve_overall_loose_match_sum_cnt_2010 = cve_overall_loose_match_true_cnt_2010 + cve_overall_loose_match_false_cnt_2010
    cve_overall_loose_match_sum_cnt_2009 = cve_overall_loose_match_true_cnt_2009 + cve_overall_loose_match_false_cnt_2009
    cve_overall_loose_match_sum_cnt_2008 = cve_overall_loose_match_true_cnt_2008 + cve_overall_loose_match_false_cnt_2008
    cve_overall_loose_match_sum_cnt_2007 = cve_overall_loose_match_true_cnt_2007 + cve_overall_loose_match_false_cnt_2007
    cve_overall_loose_match_sum_cnt_2006 = cve_overall_loose_match_true_cnt_2006 + cve_overall_loose_match_false_cnt_2006
    cve_overall_loose_match_sum_cnt_2005 = cve_overall_loose_match_true_cnt_2005 + cve_overall_loose_match_false_cnt_2005
    cve_overall_loose_match_sum_cnt_2004 = cve_overall_loose_match_true_cnt_2004 + cve_overall_loose_match_false_cnt_2004
    cve_overall_loose_match_sum_cnt_2003 = cve_overall_loose_match_true_cnt_2003 + cve_overall_loose_match_false_cnt_2003
    cve_overall_loose_match_sum_cnt_2002 = cve_overall_loose_match_true_cnt_2002 + cve_overall_loose_match_false_cnt_2002
    cve_overall_loose_match_sum_cnt_2001 = cve_overall_loose_match_true_cnt_2001 + cve_overall_loose_match_false_cnt_2001
    cve_overall_loose_match_sum_cnt_2000 = cve_overall_loose_match_true_cnt_2000 + cve_overall_loose_match_false_cnt_2000
    cve_overall_loose_match_sum_cnt_1999 = cve_overall_loose_match_true_cnt_1999 + cve_overall_loose_match_false_cnt_1999

    # 保存在本地
    cve_and_nvd_soft_path = os.getcwd() + '/data/softname_version_compare/'  # 文件夹
    cve_and_nvd_soft_filename = '9_get_result_by_year.txt'  # 这样命名方便查看
    cve_and_nvd_soft_file_path = os.path.join('%s%s' % (cve_and_nvd_soft_path, cve_and_nvd_soft_filename))
    # 字典原始格式保存在本地
    with open(cve_and_nvd_soft_file_path, 'w', encoding='utf-8') as name_and_version_f:  # 用w而非a，用于覆盖
        name_and_version_f.write('一致性随年份的变化情况：\n\n')
        name_and_version_f.write('严格匹配：\n')  # 写入数据
        name_and_version_f.write('2019年严格匹配正确的CVEID数量：' + str(cve_overall_strict_match_true_cnt_2019) + '\n')
        if cve_overall_strict_match_true_cnt_2019 != 0:
            name_and_version_f.write('2019年严格匹配正确率：' + str(cve_overall_strict_match_true_cnt_2019 / cve_overall_strict_match_sum_cnt_2019) + '\n')
        else:
            name_and_version_f.write('2019年严格匹配正确率：0\n')
        name_and_version_f.write('2019年严格匹配错误的CVEID数量：' + str(cve_overall_strict_match_false_cnt_2019) + '\n')
        if cve_overall_strict_match_true_cnt_2019 != 0:
            name_and_version_f.write('2019年严格匹配错误率：' + str(cve_overall_strict_match_false_cnt_2019 / cve_overall_strict_match_sum_cnt_2019) + '\n')
        else:
            name_and_version_f.write('2019年严格匹配错误率：0\n')

        name_and_version_f.write('2018年严格匹配正确的CVEID数量：' + str(cve_overall_strict_match_true_cnt_2018) + '\n')
        if cve_overall_strict_match_true_cnt_2018 != 0:
            name_and_version_f.write('2018年严格匹配正确率：' + str(cve_overall_strict_match_true_cnt_2018 / cve_overall_strict_match_sum_cnt_2018) + '\n')
        else:
            name_and_version_f.write('2018年严格匹配正确率：0\n')
        name_and_version_f.write('2018年严格匹配错误的CVEID数量：' + str(cve_overall_strict_match_false_cnt_2018) + '\n')
        if cve_overall_strict_match_true_cnt_2018 != 0:
            name_and_version_f.write('2018年严格匹配错误率：' + str(cve_overall_strict_match_false_cnt_2018 / cve_overall_strict_match_sum_cnt_2018) + '\n')
        else:
            name_and_version_f.write('2018年严格匹配错误率：0\n')

        name_and_version_f.write('2017年严格匹配正确的CVEID数量：' + str(cve_overall_strict_match_true_cnt_2017) + '\n')
        if cve_overall_strict_match_true_cnt_2017 != 0:
            name_and_version_f.write('2017年严格匹配正确率：' + str(cve_overall_strict_match_true_cnt_2017 / cve_overall_strict_match_sum_cnt_2017) + '\n')
        else:
            name_and_version_f.write('2017年严格匹配正确率：0\n')
        name_and_version_f.write('2017年严格匹配错误的CVEID数量：' + str(cve_overall_strict_match_false_cnt_2017) + '\n')
        if cve_overall_strict_match_true_cnt_2017 != 0:
            name_and_version_f.write('2017年严格匹配错误率：' + str(cve_overall_strict_match_false_cnt_2017 / cve_overall_strict_match_sum_cnt_2017) + '\n')
        else:
            name_and_version_f.write('2017年严格匹配错误率：0\n')

        name_and_version_f.write('2016年严格匹配正确的CVEID数量：' + str(cve_overall_strict_match_true_cnt_2016) + '\n')
        if cve_overall_strict_match_true_cnt_2016 != 0:
            name_and_version_f.write('2016年严格匹配正确率：' + str(cve_overall_strict_match_true_cnt_2016 / cve_overall_strict_match_sum_cnt_2016) + '\n')
        else:
            name_and_version_f.write('2016年严格匹配正确率：0\n')
        name_and_version_f.write('2016年严格匹配错误的CVEID数量：' + str(cve_overall_strict_match_false_cnt_2016) + '\n')
        if cve_overall_strict_match_true_cnt_2016 != 0:
            name_and_version_f.write('2016年严格匹配错误率：' + str(cve_overall_strict_match_false_cnt_2016 / cve_overall_strict_match_sum_cnt_2016) + '\n')
        else:
            name_and_version_f.write('2016年严格匹配错误率：0\n')

        name_and_version_f.write('2015年严格匹配正确的CVEID数量：' + str(cve_overall_strict_match_true_cnt_2015) + '\n')
        if cve_overall_strict_match_true_cnt_2015 != 0:
            name_and_version_f.write('2015年严格匹配正确率：' + str(cve_overall_strict_match_true_cnt_2015 / cve_overall_strict_match_sum_cnt_2015) + '\n')
        else:
            name_and_version_f.write('2015年严格匹配正确率：0\n')
        name_and_version_f.write('2015年严格匹配错误的CVEID数量：' + str(cve_overall_strict_match_false_cnt_2015) + '\n')
        if cve_overall_strict_match_true_cnt_2015 != 0:
            name_and_version_f.write('2015年严格匹配错误率：' + str(cve_overall_strict_match_false_cnt_2015 / cve_overall_strict_match_sum_cnt_2015) + '\n')
        else:
            name_and_version_f.write('2015年严格匹配错误率：0\n')

        name_and_version_f.write('2014年严格匹配正确的CVEID数量：' + str(cve_overall_strict_match_true_cnt_2014) + '\n')
        if cve_overall_strict_match_true_cnt_2014 != 0:
            name_and_version_f.write('2014年严格匹配正确率：' + str(cve_overall_strict_match_true_cnt_2014 / cve_overall_strict_match_sum_cnt_2014) + '\n')
        else:
            name_and_version_f.write('2014年严格匹配正确率：0\n')
        name_and_version_f.write('2014年严格匹配错误的CVEID数量：' + str(cve_overall_strict_match_false_cnt_2014) + '\n')
        if cve_overall_strict_match_true_cnt_2014 != 0:
            name_and_version_f.write('2014年严格匹配错误率：' + str(cve_overall_strict_match_false_cnt_2014 / cve_overall_strict_match_sum_cnt_2014) + '\n')
        else:
            name_and_version_f.write('2014年严格匹配错误率：0\n')

        name_and_version_f.write('2013年严格匹配正确的CVEID数量：' + str(cve_overall_strict_match_true_cnt_2013) + '\n')
        if cve_overall_strict_match_true_cnt_2013 != 0:
            name_and_version_f.write('2013年严格匹配正确率：' + str(cve_overall_strict_match_true_cnt_2013 / cve_overall_strict_match_sum_cnt_2013) + '\n')
        else:
            name_and_version_f.write('2013年严格匹配正确率：0\n')
        name_and_version_f.write('2013年严格匹配错误的CVEID数量：' + str(cve_overall_strict_match_false_cnt_2013) + '\n')
        if cve_overall_strict_match_true_cnt_2013 != 0:
            name_and_version_f.write('2013年严格匹配错误率：' + str(cve_overall_strict_match_false_cnt_2013 / cve_overall_strict_match_sum_cnt_2013) + '\n')
        else:
            name_and_version_f.write('2013年严格匹配错误率：0\n')

        name_and_version_f.write('2012年严格匹配正确的CVEID数量：' + str(cve_overall_strict_match_true_cnt_2012) + '\n')
        if cve_overall_strict_match_true_cnt_2012 != 0:
            name_and_version_f.write('2012年严格匹配正确率：' + str(cve_overall_strict_match_true_cnt_2012 / cve_overall_strict_match_sum_cnt_2012) + '\n')
        else:
            name_and_version_f.write('2012年严格匹配正确率：0\n')
        name_and_version_f.write('2012年严格匹配错误的CVEID数量：' + str(cve_overall_strict_match_false_cnt_2012) + '\n')
        if cve_overall_strict_match_true_cnt_2012 != 0:
            name_and_version_f.write('2012年严格匹配错误率：' + str(cve_overall_strict_match_false_cnt_2012 / cve_overall_strict_match_sum_cnt_2012) + '\n')
        else:
            name_and_version_f.write('2012年严格匹配错误率：0\n')

        name_and_version_f.write('2011年严格匹配正确的CVEID数量：' + str(cve_overall_strict_match_true_cnt_2011) + '\n')
        if cve_overall_strict_match_true_cnt_2011 != 0:
            name_and_version_f.write('2011年严格匹配正确率：' + str(cve_overall_strict_match_true_cnt_2011 / cve_overall_strict_match_sum_cnt_2011) + '\n')
        else:
            name_and_version_f.write('2011年严格匹配正确率：0\n')
        name_and_version_f.write('2011年严格匹配错误的CVEID数量：' + str(cve_overall_strict_match_false_cnt_2011) + '\n')
        if cve_overall_strict_match_true_cnt_2011 != 0:
            name_and_version_f.write('2011年严格匹配错误率：' + str(cve_overall_strict_match_false_cnt_2011 / cve_overall_strict_match_sum_cnt_2011) + '\n')
        else:
            name_and_version_f.write('2011年严格匹配错误率：0\n')

        name_and_version_f.write('2010年严格匹配正确的CVEID数量：' + str(cve_overall_strict_match_true_cnt_2010) + '\n')
        if cve_overall_strict_match_true_cnt_2010 != 0:
            name_and_version_f.write('2010年严格匹配正确率：' + str(cve_overall_strict_match_true_cnt_2010 / cve_overall_strict_match_sum_cnt_2010) + '\n')
        else:
            name_and_version_f.write('2010年严格匹配正确率：0\n')
        name_and_version_f.write('2010年严格匹配错误的CVEID数量：' + str(cve_overall_strict_match_false_cnt_2010) + '\n')
        if cve_overall_strict_match_true_cnt_2010 != 0:
            name_and_version_f.write('2010年严格匹配错误率：' + str(cve_overall_strict_match_false_cnt_2010 / cve_overall_strict_match_sum_cnt_2010) + '\n')
        else:
            name_and_version_f.write('2010年严格匹配错误率：0\n')

        name_and_version_f.write('2009年严格匹配正确的CVEID数量：' + str(cve_overall_strict_match_true_cnt_2009) + '\n')
        if cve_overall_strict_match_true_cnt_2009 != 0:
            name_and_version_f.write('2009年严格匹配正确率：' + str(cve_overall_strict_match_true_cnt_2009 / cve_overall_strict_match_sum_cnt_2009) + '\n')
        else:
            name_and_version_f.write('2009年严格匹配正确率：0\n')
        name_and_version_f.write('2009年严格匹配错误的CVEID数量：' + str(cve_overall_strict_match_false_cnt_2009) + '\n')
        if cve_overall_strict_match_true_cnt_2009 != 0:
            name_and_version_f.write('2009年严格匹配错误率：' + str(cve_overall_strict_match_false_cnt_2009 / cve_overall_strict_match_sum_cnt_2009) + '\n')
        else:
            name_and_version_f.write('2009年严格匹配错误率：0\n')

        name_and_version_f.write('2008年严格匹配正确的CVEID数量：' + str(cve_overall_strict_match_true_cnt_2008) + '\n')
        if cve_overall_strict_match_true_cnt_2008 != 0:
            name_and_version_f.write('2008年严格匹配正确率：' + str(cve_overall_strict_match_true_cnt_2008 / cve_overall_strict_match_sum_cnt_2008) + '\n')
        else:
            name_and_version_f.write('2008年严格匹配正确率：0\n')
        name_and_version_f.write('2008年严格匹配错误的CVEID数量：' + str(cve_overall_strict_match_false_cnt_2008) + '\n')
        if cve_overall_strict_match_true_cnt_2008 != 0:
            name_and_version_f.write('2008年严格匹配错误率：' + str(cve_overall_strict_match_false_cnt_2008 / cve_overall_strict_match_sum_cnt_2008) + '\n')
        else:
            name_and_version_f.write('2008年严格匹配错误率：0\n')

        name_and_version_f.write('2007年严格匹配正确的CVEID数量：' + str(cve_overall_strict_match_true_cnt_2007) + '\n')
        if cve_overall_strict_match_true_cnt_2007 != 0:
            name_and_version_f.write('2007年严格匹配正确率：' + str(cve_overall_strict_match_true_cnt_2007 / cve_overall_strict_match_sum_cnt_2007) + '\n')
        else:
            name_and_version_f.write('2007年严格匹配正确率：0\n')
        name_and_version_f.write('2007年严格匹配错误的CVEID数量：' + str(cve_overall_strict_match_false_cnt_2007) + '\n')
        if cve_overall_strict_match_true_cnt_2007 != 0:
            name_and_version_f.write('2007年严格匹配错误率：' + str(cve_overall_strict_match_false_cnt_2007 / cve_overall_strict_match_sum_cnt_2007) + '\n')
        else:
            name_and_version_f.write('2007年严格匹配错误率：0\n')

        name_and_version_f.write('2006年严格匹配正确的CVEID数量：' + str(cve_overall_strict_match_true_cnt_2006) + '\n')
        if cve_overall_strict_match_true_cnt_2006 != 0:
            name_and_version_f.write('2006年严格匹配正确率：' + str(cve_overall_strict_match_true_cnt_2006 / cve_overall_strict_match_sum_cnt_2006) + '\n')
        else:
            name_and_version_f.write('2006年严格匹配正确率：0\n')
        name_and_version_f.write('2006年严格匹配错误的CVEID数量：' + str(cve_overall_strict_match_false_cnt_2006) + '\n')
        if cve_overall_strict_match_true_cnt_2006 != 0:
            name_and_version_f.write('2006年严格匹配错误率：' + str(cve_overall_strict_match_false_cnt_2006 / cve_overall_strict_match_sum_cnt_2006) + '\n')
        else:
            name_and_version_f.write('2006年严格匹配错误率：0\n')

        name_and_version_f.write('2005年严格匹配正确的CVEID数量：' + str(cve_overall_strict_match_true_cnt_2005) + '\n')
        if cve_overall_strict_match_true_cnt_2005 != 0:
            name_and_version_f.write('2005年严格匹配正确率：' + str(cve_overall_strict_match_true_cnt_2005 / cve_overall_strict_match_sum_cnt_2005) + '\n')
        else:
            name_and_version_f.write('2005年严格匹配正确率：0\n')
        name_and_version_f.write('2005年严格匹配错误的CVEID数量：' + str(cve_overall_strict_match_false_cnt_2005) + '\n')
        if cve_overall_strict_match_true_cnt_2005 != 0:
            name_and_version_f.write('2005年严格匹配错误率：' + str(cve_overall_strict_match_false_cnt_2005 / cve_overall_strict_match_sum_cnt_2005) + '\n')
        else:
            name_and_version_f.write('2005年严格匹配错误率：0\n')

        name_and_version_f.write('2004年严格匹配正确的CVEID数量：' + str(cve_overall_strict_match_true_cnt_2004) + '\n')
        if cve_overall_strict_match_true_cnt_2004 != 0:
            name_and_version_f.write('2004年严格匹配正确率：' + str(cve_overall_strict_match_true_cnt_2004 / cve_overall_strict_match_sum_cnt_2004) + '\n')
        else:
            name_and_version_f.write('2004年严格匹配正确率：0\n')
        name_and_version_f.write('2004年严格匹配错误的CVEID数量：' + str(cve_overall_strict_match_false_cnt_2004) + '\n')
        if cve_overall_strict_match_true_cnt_2004 != 0:
            name_and_version_f.write('2004年严格匹配错误率：' + str(cve_overall_strict_match_false_cnt_2004 / cve_overall_strict_match_sum_cnt_2004) + '\n')
        else:
            name_and_version_f.write('2004年严格匹配错误率：0\n')

        name_and_version_f.write('2003年严格匹配正确的CVEID数量：' + str(cve_overall_strict_match_true_cnt_2003) + '\n')
        if cve_overall_strict_match_true_cnt_2003 != 0:
            name_and_version_f.write('2003年严格匹配正确率：' + str(cve_overall_strict_match_true_cnt_2003 / cve_overall_strict_match_sum_cnt_2003) + '\n')
        else:
            name_and_version_f.write('2003年严格匹配正确率：0\n')
        name_and_version_f.write('2003年严格匹配错误的CVEID数量：' + str(cve_overall_strict_match_false_cnt_2003) + '\n')
        if cve_overall_strict_match_true_cnt_2003 != 0:
            name_and_version_f.write('2003年严格匹配错误率：' + str(cve_overall_strict_match_false_cnt_2003 / cve_overall_strict_match_sum_cnt_2003) + '\n')
        else:
            name_and_version_f.write('2003年严格匹配错误率：0\n')

        name_and_version_f.write('2002年严格匹配正确的CVEID数量：' + str(cve_overall_strict_match_true_cnt_2002) + '\n')
        if cve_overall_strict_match_true_cnt_2002 != 0:
            name_and_version_f.write('2002年严格匹配正确率：' + str(cve_overall_strict_match_true_cnt_2002 / cve_overall_strict_match_sum_cnt_2002) + '\n')
        else:
            name_and_version_f.write('2002年严格匹配正确率：0\n')
        name_and_version_f.write('2002年严格匹配错误的CVEID数量：' + str(cve_overall_strict_match_false_cnt_2002) + '\n')
        if cve_overall_strict_match_true_cnt_2002 != 0:
            name_and_version_f.write('2002年严格匹配错误率：' + str(cve_overall_strict_match_false_cnt_2002 / cve_overall_strict_match_sum_cnt_2002) + '\n')
        else:
            name_and_version_f.write('2002年严格匹配错误率：0\n')

        name_and_version_f.write('2001年严格匹配正确的CVEID数量：' + str(cve_overall_strict_match_true_cnt_2001) + '\n')
        if cve_overall_strict_match_true_cnt_2001 != 0:
            name_and_version_f.write('2001年严格匹配正确率：' + str(cve_overall_strict_match_true_cnt_2001 / cve_overall_strict_match_sum_cnt_2001) + '\n')
        else:
            name_and_version_f.write('2001年严格匹配正确率：0\n')
        name_and_version_f.write('2001年严格匹配错误的CVEID数量：' + str(cve_overall_strict_match_false_cnt_2001) + '\n')
        if cve_overall_strict_match_true_cnt_2001 != 0:
            name_and_version_f.write('2001年严格匹配错误率：' + str(cve_overall_strict_match_false_cnt_2001 / cve_overall_strict_match_sum_cnt_2001) + '\n')
        else:
            name_and_version_f.write('2001年严格匹配错误率：0\n')

        name_and_version_f.write('2000年严格匹配正确的CVEID数量：' + str(cve_overall_strict_match_true_cnt_2000) + '\n')
        if cve_overall_strict_match_true_cnt_2000 != 0:
            name_and_version_f.write('2000年严格匹配正确率：' + str(cve_overall_strict_match_true_cnt_2000 / cve_overall_strict_match_sum_cnt_2000) + '\n')
        else:
            name_and_version_f.write('2000年严格匹配正确率：0\n')
        name_and_version_f.write('2000年严格匹配错误的CVEID数量：' + str(cve_overall_strict_match_false_cnt_2000) + '\n')
        if cve_overall_strict_match_true_cnt_2000 != 0:
            name_and_version_f.write('2000年严格匹配错误率：' + str(cve_overall_strict_match_false_cnt_2000 / cve_overall_strict_match_sum_cnt_2000) + '\n')
        else:
            name_and_version_f.write('2000年严格匹配错误率：0\n')

        name_and_version_f.write('1999年严格匹配正确的CVEID数量：' + str(cve_overall_strict_match_true_cnt_1999) + '\n')
        if cve_overall_strict_match_true_cnt_1999 != 0:
            name_and_version_f.write('1999年严格匹配正确率：' + str(cve_overall_strict_match_true_cnt_1999 / cve_overall_strict_match_sum_cnt_1999) + '\n')
        else:
            name_and_version_f.write('1999年严格匹配正确率：0\n')
        name_and_version_f.write('1999年严格匹配错误的CVEID数量：' + str(cve_overall_strict_match_false_cnt_1999) + '\n')
        if cve_overall_strict_match_true_cnt_1999 != 0:
            name_and_version_f.write('1999年严格匹配错误率：' + str(cve_overall_strict_match_false_cnt_1999 / cve_overall_strict_match_sum_cnt_1999) + '\n')
        else:
            name_and_version_f.write('1999年严格匹配错误率：0\n')


        name_and_version_f.write('\n松散匹配：\n')
        name_and_version_f.write('2019年松散匹配正确的CVEID数量：' + str(cve_overall_strict_match_true_cnt_2019) + '\n')
        if cve_overall_strict_match_true_cnt_2019 != 0:
            name_and_version_f.write('2019年松散匹配正确率：' + str(
                cve_overall_strict_match_true_cnt_2019 / cve_overall_strict_match_sum_cnt_2019) + '\n')
        else:
            name_and_version_f.write('2019年松散匹配正确率：0\n')
        name_and_version_f.write('2019年松散匹配错误的CVEID数量：' + str(cve_overall_loose_match_false_cnt_2019) + '\n')
        if cve_overall_loose_match_true_cnt_2019 != 0:
            name_and_version_f.write('2019年松散匹配错误率：' + str(
                cve_overall_loose_match_false_cnt_2019 / cve_overall_loose_match_sum_cnt_2019) + '\n')
        else:
            name_and_version_f.write('2019年松散匹配错误率：0\n')

        name_and_version_f.write('2018年松散匹配正确的CVEID数量：' + str(cve_overall_loose_match_true_cnt_2018) + '\n')
        if cve_overall_loose_match_true_cnt_2018 != 0:
            name_and_version_f.write('2018年松散匹配正确率：' + str(
                cve_overall_loose_match_true_cnt_2018 / cve_overall_loose_match_sum_cnt_2018) + '\n')
        else:
            name_and_version_f.write('2018年松散匹配正确率：0\n')
        name_and_version_f.write('2018年松散匹配错误的CVEID数量：' + str(cve_overall_loose_match_false_cnt_2018) + '\n')
        if cve_overall_loose_match_true_cnt_2018 != 0:
            name_and_version_f.write('2018年松散匹配错误率：' + str(
                cve_overall_loose_match_false_cnt_2018 / cve_overall_loose_match_sum_cnt_2018) + '\n')
        else:
            name_and_version_f.write('2018年松散匹配错误率：0\n')

        name_and_version_f.write('2017年松散匹配正确的CVEID数量：' + str(cve_overall_loose_match_true_cnt_2017) + '\n')
        if cve_overall_loose_match_true_cnt_2017 != 0:
            name_and_version_f.write('2017年松散匹配正确率：' + str(
                cve_overall_loose_match_true_cnt_2017 / cve_overall_loose_match_sum_cnt_2017) + '\n')
        else:
            name_and_version_f.write('2017年松散匹配正确率：0\n')
        name_and_version_f.write('2017年松散匹配错误的CVEID数量：' + str(cve_overall_loose_match_false_cnt_2017) + '\n')
        if cve_overall_loose_match_true_cnt_2017 != 0:
            name_and_version_f.write('2017年松散匹配错误率：' + str(
                cve_overall_loose_match_false_cnt_2017 / cve_overall_loose_match_sum_cnt_2017) + '\n')
        else:
            name_and_version_f.write('2017年松散匹配错误率：0\n')

        name_and_version_f.write('2016年松散匹配正确的CVEID数量：' + str(cve_overall_loose_match_true_cnt_2016) + '\n')
        if cve_overall_loose_match_true_cnt_2016 != 0:
            name_and_version_f.write('2016年松散匹配正确率：' + str(
                cve_overall_loose_match_true_cnt_2016 / cve_overall_loose_match_sum_cnt_2016) + '\n')
        else:
            name_and_version_f.write('2016年松散匹配正确率：0\n')
        name_and_version_f.write('2016年松散匹配错误的CVEID数量：' + str(cve_overall_loose_match_false_cnt_2016) + '\n')
        if cve_overall_loose_match_true_cnt_2016 != 0:
            name_and_version_f.write('2016年松散匹配错误率：' + str(
                cve_overall_loose_match_false_cnt_2016 / cve_overall_loose_match_sum_cnt_2016) + '\n')
        else:
            name_and_version_f.write('2016年松散匹配错误率：0\n')

        name_and_version_f.write('2015年松散匹配正确的CVEID数量：' + str(cve_overall_loose_match_true_cnt_2015) + '\n')
        if cve_overall_loose_match_true_cnt_2015 != 0:
            name_and_version_f.write('2015年松散匹配正确率：' + str(
                cve_overall_loose_match_true_cnt_2015 / cve_overall_loose_match_sum_cnt_2015) + '\n')
        else:
            name_and_version_f.write('2015年松散匹配正确率：0\n')
        name_and_version_f.write('2015年松散匹配错误的CVEID数量：' + str(cve_overall_loose_match_false_cnt_2015) + '\n')
        if cve_overall_loose_match_true_cnt_2015 != 0:
            name_and_version_f.write('2015年松散匹配错误率：' + str(
                cve_overall_loose_match_false_cnt_2015 / cve_overall_loose_match_sum_cnt_2015) + '\n')
        else:
            name_and_version_f.write('2015年松散匹配错误率：0\n')

        name_and_version_f.write('2014年松散匹配正确的CVEID数量：' + str(cve_overall_loose_match_true_cnt_2014) + '\n')
        if cve_overall_loose_match_true_cnt_2014 != 0:
            name_and_version_f.write('2014年松散匹配正确率：' + str(
                cve_overall_loose_match_true_cnt_2014 / cve_overall_loose_match_sum_cnt_2014) + '\n')
        else:
            name_and_version_f.write('2014年松散匹配正确率：0\n')
        name_and_version_f.write('2014年松散匹配错误的CVEID数量：' + str(cve_overall_loose_match_false_cnt_2014) + '\n')
        if cve_overall_loose_match_true_cnt_2014 != 0:
            name_and_version_f.write('2014年松散匹配错误率：' + str(
                cve_overall_loose_match_false_cnt_2014 / cve_overall_loose_match_sum_cnt_2014) + '\n')
        else:
            name_and_version_f.write('2014年松散匹配错误率：0\n')

        name_and_version_f.write('2013年松散匹配正确的CVEID数量：' + str(cve_overall_loose_match_true_cnt_2013) + '\n')
        if cve_overall_loose_match_true_cnt_2013 != 0:
            name_and_version_f.write('2013年松散匹配正确率：' + str(
                cve_overall_loose_match_true_cnt_2013 / cve_overall_loose_match_sum_cnt_2013) + '\n')
        else:
            name_and_version_f.write('2013年松散匹配正确率：0\n')
        name_and_version_f.write('2013年松散匹配错误的CVEID数量：' + str(cve_overall_loose_match_false_cnt_2013) + '\n')
        if cve_overall_loose_match_true_cnt_2013 != 0:
            name_and_version_f.write('2013年松散匹配错误率：' + str(
                cve_overall_loose_match_false_cnt_2013 / cve_overall_loose_match_sum_cnt_2013) + '\n')
        else:
            name_and_version_f.write('2013年松散匹配错误率：0\n')

        name_and_version_f.write('2012年松散匹配正确的CVEID数量：' + str(cve_overall_loose_match_true_cnt_2012) + '\n')
        if cve_overall_loose_match_true_cnt_2012 != 0:
            name_and_version_f.write('2012年松散匹配正确率：' + str(
                cve_overall_loose_match_true_cnt_2012 / cve_overall_loose_match_sum_cnt_2012) + '\n')
        else:
            name_and_version_f.write('2012年松散匹配正确率：0\n')
        name_and_version_f.write('2012年松散匹配错误的CVEID数量：' + str(cve_overall_loose_match_false_cnt_2012) + '\n')
        if cve_overall_loose_match_true_cnt_2012 != 0:
            name_and_version_f.write('2012年松散匹配错误率：' + str(
                cve_overall_loose_match_false_cnt_2012 / cve_overall_loose_match_sum_cnt_2012) + '\n')
        else:
            name_and_version_f.write('2012年松散匹配错误率：0\n')

        name_and_version_f.write('2011年松散匹配正确的CVEID数量：' + str(cve_overall_loose_match_true_cnt_2011) + '\n')
        if cve_overall_loose_match_true_cnt_2011 != 0:
            name_and_version_f.write('2011年松散匹配正确率：' + str(
                cve_overall_loose_match_true_cnt_2011 / cve_overall_loose_match_sum_cnt_2011) + '\n')
        else:
            name_and_version_f.write('2011年松散匹配正确率：0\n')
        name_and_version_f.write('2011年松散匹配错误的CVEID数量：' + str(cve_overall_loose_match_false_cnt_2011) + '\n')
        if cve_overall_loose_match_true_cnt_2011 != 0:
            name_and_version_f.write('2011年松散匹配错误率：' + str(
                cve_overall_loose_match_false_cnt_2011 / cve_overall_loose_match_sum_cnt_2011) + '\n')
        else:
            name_and_version_f.write('2011年松散匹配错误率：0\n')

        name_and_version_f.write('2010年松散匹配正确的CVEID数量：' + str(cve_overall_loose_match_true_cnt_2010) + '\n')
        if cve_overall_loose_match_true_cnt_2010 != 0:
            name_and_version_f.write('2010年松散匹配正确率：' + str(
                cve_overall_loose_match_true_cnt_2010 / cve_overall_loose_match_sum_cnt_2010) + '\n')
        else:
            name_and_version_f.write('2010年松散匹配正确率：0\n')
        name_and_version_f.write('2010年松散匹配错误的CVEID数量：' + str(cve_overall_loose_match_false_cnt_2010) + '\n')
        if cve_overall_loose_match_true_cnt_2010 != 0:
            name_and_version_f.write('2010年松散匹配错误率：' + str(
                cve_overall_loose_match_false_cnt_2010 / cve_overall_loose_match_sum_cnt_2010) + '\n')
        else:
            name_and_version_f.write('2010年松散匹配错误率：0\n')

        name_and_version_f.write('2009年松散匹配正确的CVEID数量：' + str(cve_overall_loose_match_true_cnt_2009) + '\n')
        if cve_overall_loose_match_true_cnt_2009 != 0:
            name_and_version_f.write('2009年松散匹配正确率：' + str(
                cve_overall_loose_match_true_cnt_2009 / cve_overall_loose_match_sum_cnt_2009) + '\n')
        else:
            name_and_version_f.write('2009年松散匹配正确率：0\n')
        name_and_version_f.write('2009年松散匹配错误的CVEID数量：' + str(cve_overall_loose_match_false_cnt_2009) + '\n')
        if cve_overall_loose_match_true_cnt_2009 != 0:
            name_and_version_f.write('2009年松散匹配错误率：' + str(
                cve_overall_loose_match_false_cnt_2009 / cve_overall_loose_match_sum_cnt_2009) + '\n')
        else:
            name_and_version_f.write('2009年松散匹配错误率：0\n')

        name_and_version_f.write('2008年松散匹配正确的CVEID数量：' + str(cve_overall_loose_match_true_cnt_2008) + '\n')
        if cve_overall_loose_match_true_cnt_2008 != 0:
            name_and_version_f.write('2008年松散匹配正确率：' + str(
                cve_overall_loose_match_true_cnt_2008 / cve_overall_loose_match_sum_cnt_2008) + '\n')
        else:
            name_and_version_f.write('2008年松散匹配正确率：0\n')
        name_and_version_f.write('2008年松散匹配错误的CVEID数量：' + str(cve_overall_loose_match_false_cnt_2008) + '\n')
        if cve_overall_loose_match_true_cnt_2008 != 0:
            name_and_version_f.write('2008年松散匹配错误率：' + str(
                cve_overall_loose_match_false_cnt_2008 / cve_overall_loose_match_sum_cnt_2008) + '\n')
        else:
            name_and_version_f.write('2008年松散匹配错误率：0\n')

        name_and_version_f.write('2007年松散匹配正确的CVEID数量：' + str(cve_overall_loose_match_true_cnt_2007) + '\n')
        if cve_overall_loose_match_true_cnt_2007 != 0:
            name_and_version_f.write('2007年松散匹配正确率：' + str(
                cve_overall_loose_match_true_cnt_2007 / cve_overall_loose_match_sum_cnt_2007) + '\n')
        else:
            name_and_version_f.write('2007年松散匹配正确率：0\n')
        name_and_version_f.write('2007年松散匹配错误的CVEID数量：' + str(cve_overall_loose_match_false_cnt_2007) + '\n')
        if cve_overall_loose_match_true_cnt_2007 != 0:
            name_and_version_f.write('2007年松散匹配错误率：' + str(
                cve_overall_loose_match_false_cnt_2007 / cve_overall_loose_match_sum_cnt_2007) + '\n')
        else:
            name_and_version_f.write('2007年松散匹配错误率：0\n')

        name_and_version_f.write('2006年松散匹配正确的CVEID数量：' + str(cve_overall_loose_match_true_cnt_2006) + '\n')
        if cve_overall_loose_match_true_cnt_2006 != 0:
            name_and_version_f.write('2006年松散匹配正确率：' + str(
                cve_overall_loose_match_true_cnt_2006 / cve_overall_loose_match_sum_cnt_2006) + '\n')
        else:
            name_and_version_f.write('2006年松散匹配正确率：0\n')
        name_and_version_f.write('2006年松散匹配错误的CVEID数量：' + str(cve_overall_loose_match_false_cnt_2006) + '\n')
        if cve_overall_loose_match_true_cnt_2006 != 0:
            name_and_version_f.write('2006年松散匹配错误率：' + str(
                cve_overall_loose_match_false_cnt_2006 / cve_overall_loose_match_sum_cnt_2006) + '\n')
        else:
            name_and_version_f.write('2006年松散匹配错误率：0\n')

        name_and_version_f.write('2005年松散匹配正确的CVEID数量：' + str(cve_overall_loose_match_true_cnt_2005) + '\n')
        if cve_overall_loose_match_true_cnt_2005 != 0:
            name_and_version_f.write('2005年松散匹配正确率：' + str(
                cve_overall_loose_match_true_cnt_2005 / cve_overall_loose_match_sum_cnt_2005) + '\n')
        else:
            name_and_version_f.write('2005年松散匹配正确率：0\n')
        name_and_version_f.write('2005年松散匹配错误的CVEID数量：' + str(cve_overall_loose_match_false_cnt_2005) + '\n')
        if cve_overall_loose_match_true_cnt_2005 != 0:
            name_and_version_f.write('2005年松散匹配错误率：' + str(
                cve_overall_loose_match_false_cnt_2005 / cve_overall_loose_match_sum_cnt_2005) + '\n')
        else:
            name_and_version_f.write('2005年松散匹配错误率：0\n')

        name_and_version_f.write('2004年松散匹配正确的CVEID数量：' + str(cve_overall_loose_match_true_cnt_2004) + '\n')
        if cve_overall_loose_match_true_cnt_2004 != 0:
            name_and_version_f.write('2004年松散匹配正确率：' + str(
                cve_overall_loose_match_true_cnt_2004 / cve_overall_loose_match_sum_cnt_2004) + '\n')
        else:
            name_and_version_f.write('2004年松散匹配正确率：0\n')
        name_and_version_f.write('2004年松散匹配错误的CVEID数量：' + str(cve_overall_loose_match_false_cnt_2004) + '\n')
        if cve_overall_loose_match_true_cnt_2004 != 0:
            name_and_version_f.write('2004年松散匹配错误率：' + str(
                cve_overall_loose_match_false_cnt_2004 / cve_overall_loose_match_sum_cnt_2004) + '\n')
        else:
            name_and_version_f.write('2004年松散匹配错误率：0\n')

        name_and_version_f.write('2003年松散匹配正确的CVEID数量：' + str(cve_overall_loose_match_true_cnt_2003) + '\n')
        if cve_overall_loose_match_true_cnt_2003 != 0:
            name_and_version_f.write('2003年松散匹配正确率：' + str(
                cve_overall_loose_match_true_cnt_2003 / cve_overall_loose_match_sum_cnt_2003) + '\n')
        else:
            name_and_version_f.write('2003年松散匹配正确率：0\n')
        name_and_version_f.write('2003年松散匹配错误的CVEID数量：' + str(cve_overall_loose_match_false_cnt_2003) + '\n')
        if cve_overall_loose_match_true_cnt_2003 != 0:
            name_and_version_f.write('2003年松散匹配错误率：' + str(
                cve_overall_loose_match_false_cnt_2003 / cve_overall_loose_match_sum_cnt_2003) + '\n')
        else:
            name_and_version_f.write('2003年松散匹配错误率：0\n')

        name_and_version_f.write('2002年松散匹配正确的CVEID数量：' + str(cve_overall_loose_match_true_cnt_2002) + '\n')
        if cve_overall_loose_match_true_cnt_2002 != 0:
            name_and_version_f.write('2002年松散匹配正确率：' + str(
                cve_overall_loose_match_true_cnt_2002 / cve_overall_loose_match_sum_cnt_2002) + '\n')
        else:
            name_and_version_f.write('2002年松散匹配正确率：0\n')
        name_and_version_f.write('2002年松散匹配错误的CVEID数量：' + str(cve_overall_loose_match_false_cnt_2002) + '\n')
        if cve_overall_loose_match_true_cnt_2002 != 0:
            name_and_version_f.write('2002年松散匹配错误率：' + str(
                cve_overall_loose_match_false_cnt_2002 / cve_overall_loose_match_sum_cnt_2002) + '\n')
        else:
            name_and_version_f.write('2002年松散匹配错误率：0\n')

        name_and_version_f.write('2001年松散匹配正确的CVEID数量：' + str(cve_overall_loose_match_true_cnt_2001) + '\n')
        if cve_overall_loose_match_true_cnt_2001 != 0:
            name_and_version_f.write('2001年松散匹配正确率：' + str(
                cve_overall_loose_match_true_cnt_2001 / cve_overall_loose_match_sum_cnt_2001) + '\n')
        else:
            name_and_version_f.write('2001年松散匹配正确率：0\n')
        name_and_version_f.write('2001年松散匹配错误的CVEID数量：' + str(cve_overall_loose_match_false_cnt_2001) + '\n')
        if cve_overall_loose_match_true_cnt_2001 != 0:
            name_and_version_f.write('2001年松散匹配错误率：' + str(
                cve_overall_loose_match_false_cnt_2001 / cve_overall_loose_match_sum_cnt_2001) + '\n')
        else:
            name_and_version_f.write('2001年松散匹配错误率：0\n')

        name_and_version_f.write('2000年松散匹配正确的CVEID数量：' + str(cve_overall_loose_match_true_cnt_2000) + '\n')
        if cve_overall_loose_match_true_cnt_2000 != 0:
            name_and_version_f.write('2000年松散匹配正确率：' + str(
                cve_overall_loose_match_true_cnt_2000 / cve_overall_loose_match_sum_cnt_2000) + '\n')
        else:
            name_and_version_f.write('2000年松散匹配正确率：0\n')
        name_and_version_f.write('2000年松散匹配错误的CVEID数量：' + str(cve_overall_loose_match_false_cnt_2000) + '\n')
        if cve_overall_loose_match_true_cnt_2000 != 0:
            name_and_version_f.write('2000年松散匹配错误率：' + str(
                cve_overall_loose_match_false_cnt_2000 / cve_overall_loose_match_sum_cnt_2000) + '\n')
        else:
            name_and_version_f.write('2000年松散匹配错误率：0\n')

        name_and_version_f.write('1999年松散匹配正确的CVEID数量：' + str(cve_overall_loose_match_true_cnt_1999) + '\n')
        if cve_overall_loose_match_true_cnt_1999 != 0:
            name_and_version_f.write('1999年松散匹配正确率：' + str(
                cve_overall_loose_match_true_cnt_1999 / cve_overall_loose_match_sum_cnt_1999) + '\n')
        else:
            name_and_version_f.write('1999年松散匹配正确率：0\n')
        name_and_version_f.write('1999年松散匹配错误的CVEID数量：' + str(cve_overall_loose_match_false_cnt_1999) + '\n')
        if cve_overall_loose_match_true_cnt_1999 != 0:
            name_and_version_f.write('1999年松散匹配错误率：' + str(
                cve_overall_loose_match_false_cnt_1999 / cve_overall_loose_match_sum_cnt_1999) + '\n')
        else:
            name_and_version_f.write('1999年松散匹配错误率：0\n')


# 获取不同漏洞类别的一致性的结果，在服务器运行该代码
def get_result_by_vulnerability_kind():
    # 获取softname和version内容
    soft_dic_path = os.getcwd() + '/data/softname_version_compare/'  # 存放的文件夹
    soft_dic_filename = '8_measure_inconsistency.txt'
    soft_dic_name = os.path.join('%s%s' % (soft_dic_path, soft_dic_filename))
    soft_dict = dict()

    # 获取每个漏洞类别包括的CVEID
    # 漏洞类别为httprs
    cveid_httprs = []
    cveid_by_kind_path = os.getcwd() + '/data/cveid_by_kind/'  # 存放的文件夹
    cveid_by_kind_filename = 'cveid_httprs.txt'
    cveid_by_kind_name = os.path.join('%s%s' % (cveid_by_kind_path, cveid_by_kind_filename))
    with open(cveid_by_kind_name, 'r', encoding='UTF-8') as cveid_by_kind_f:  # 打开文件
        cveid_by_kind_lines = cveid_by_kind_f.readlines()  # 获取文件的所有行
        for cveid_by_kind_line in cveid_by_kind_lines:
            id = cveid_by_kind_line.rstrip('\n')
            cveid_httprs.append(id)

    # 漏洞类别为csrf
    cveid_csrf = []
    cveid_by_kind_path = os.getcwd() + '/data/cveid_by_kind/'  # 存放的文件夹
    cveid_by_kind_filename = 'cveid_csrf.txt'
    cveid_by_kind_name = os.path.join('%s%s' % (cveid_by_kind_path, cveid_by_kind_filename))
    with open(cveid_by_kind_name, 'r', encoding='UTF-8') as cveid_by_kind_f:  # 打开文件
        cveid_by_kind_lines = cveid_by_kind_f.readlines()  # 获取文件的所有行
        for cveid_by_kind_line in cveid_by_kind_lines:
            id = cveid_by_kind_line.rstrip('\n')
            cveid_csrf.append(id)

    # 漏洞类别为fileinc
    cveid_fileinc = []
    cveid_by_kind_path = os.getcwd() + '/data/cveid_by_kind/'  # 存放的文件夹
    cveid_by_kind_filename = 'cveid_fileinc.txt'
    cveid_by_kind_name = os.path.join('%s%s' % (cveid_by_kind_path, cveid_by_kind_filename))
    with open(cveid_by_kind_name, 'r', encoding='UTF-8') as cveid_by_kind_f:  # 打开文件
        cveid_by_kind_lines = cveid_by_kind_f.readlines()  # 获取文件的所有行
        for cveid_by_kind_line in cveid_by_kind_lines:
            id = cveid_by_kind_line.rstrip('\n')
            cveid_fileinc.append(id)

    # 漏洞类别为dirtra
    cveid_dirtra = []
    cveid_by_kind_path = os.getcwd() + '/data/cveid_by_kind/'  # 存放的文件夹
    cveid_by_kind_filename = 'cveid_dirtra.txt'
    cveid_by_kind_name = os.path.join('%s%s' % (cveid_by_kind_path, cveid_by_kind_filename))
    with open(cveid_by_kind_name, 'r', encoding='UTF-8') as cveid_by_kind_f:  # 打开文件
        cveid_by_kind_lines = cveid_by_kind_f.readlines()  # 获取文件的所有行
        for cveid_by_kind_line in cveid_by_kind_lines:
            id = cveid_by_kind_line.rstrip('\n')
            cveid_dirtra.append(id)

    # 漏洞类别为gainpre
    cveid_gainpre = []
    cveid_by_kind_path = os.getcwd() + '/data/cveid_by_kind/'  # 存放的文件夹
    cveid_by_kind_filename = 'cveid_gainpre.txt'
    cveid_by_kind_name = os.path.join('%s%s' % (cveid_by_kind_path, cveid_by_kind_filename))
    with open(cveid_by_kind_name, 'r', encoding='UTF-8') as cveid_by_kind_f:  # 打开文件
        cveid_by_kind_lines = cveid_by_kind_f.readlines()  # 获取文件的所有行
        for cveid_by_kind_line in cveid_by_kind_lines:
            id = cveid_by_kind_line.rstrip('\n')
            cveid_gainpre.append(id)

    # 漏洞类别为memc
    cveid_memc = []
    cveid_by_kind_path = os.getcwd() + '/data/cveid_by_kind/'  # 存放的文件夹
    cveid_by_kind_filename = 'cveid_memc.txt'
    cveid_by_kind_name = os.path.join('%s%s' % (cveid_by_kind_path, cveid_by_kind_filename))
    with open(cveid_by_kind_name, 'r', encoding='UTF-8') as cveid_by_kind_f:  # 打开文件
        cveid_by_kind_lines = cveid_by_kind_f.readlines()  # 获取文件的所有行
        for cveid_by_kind_line in cveid_by_kind_lines:
            id = cveid_by_kind_line.rstrip('\n')
            cveid_memc.append(id)

    # 漏洞类别为bypass
    cveid_bypass = []
    cveid_by_kind_path = os.getcwd() + '/data/cveid_by_kind/'  # 存放的文件夹
    cveid_by_kind_filename = 'cveid_bypass.txt'
    cveid_by_kind_name = os.path.join('%s%s' % (cveid_by_kind_path, cveid_by_kind_filename))
    with open(cveid_by_kind_name, 'r', encoding='UTF-8') as cveid_by_kind_f:  # 打开文件
        cveid_by_kind_lines = cveid_by_kind_f.readlines()  # 获取文件的所有行
        for cveid_by_kind_line in cveid_by_kind_lines:
            id = cveid_by_kind_line.rstrip('\n')
            cveid_bypass.append(id)

    # 漏洞类别为sqli
    cveid_sqli = []
    cveid_by_kind_path = os.getcwd() + '/data/cveid_by_kind/'  # 存放的文件夹
    cveid_by_kind_filename = 'cveid_sqli.txt'
    cveid_by_kind_name = os.path.join('%s%s' % (cveid_by_kind_path, cveid_by_kind_filename))
    with open(cveid_by_kind_name, 'r', encoding='UTF-8') as cveid_by_kind_f:  # 打开文件
        cveid_by_kind_lines = cveid_by_kind_f.readlines()  # 获取文件的所有行
        for cveid_by_kind_line in cveid_by_kind_lines:
            id = cveid_by_kind_line.rstrip('\n')
            cveid_sqli.append(id)

    # 漏洞类别为infor
    cveid_infor = []
    cveid_by_kind_path = os.getcwd() + '/data/cveid_by_kind/'  # 存放的文件夹
    cveid_by_kind_filename = 'cveid_infor.txt'
    cveid_by_kind_name = os.path.join('%s%s' % (cveid_by_kind_path, cveid_by_kind_filename))
    with open(cveid_by_kind_name, 'r', encoding='UTF-8') as cveid_by_kind_f:  # 打开文件
        cveid_by_kind_lines = cveid_by_kind_f.readlines()  # 获取文件的所有行
        for cveid_by_kind_line in cveid_by_kind_lines:
            id = cveid_by_kind_line.rstrip('\n')
            cveid_infor.append(id)

    # 漏洞类别为xss
    cveid_xss = []
    cveid_by_kind_path = os.getcwd() + '/data/cveid_by_kind/'  # 存放的文件夹
    cveid_by_kind_filename = 'cveid_xss.txt'
    cveid_by_kind_name = os.path.join('%s%s' % (cveid_by_kind_path, cveid_by_kind_filename))
    with open(cveid_by_kind_name, 'r', encoding='UTF-8') as cveid_by_kind_f:  # 打开文件
        cveid_by_kind_lines = cveid_by_kind_f.readlines()  # 获取文件的所有行
        for cveid_by_kind_line in cveid_by_kind_lines:
            id = cveid_by_kind_line.rstrip('\n')
            cveid_xss.append(id)

    # 漏洞类别为overflow
    cveid_overflow = []
    cveid_by_kind_path = os.getcwd() + '/data/cveid_by_kind/'  # 存放的文件夹
    cveid_by_kind_filename = 'cveid_overflow.txt'
    cveid_by_kind_name = os.path.join('%s%s' % (cveid_by_kind_path, cveid_by_kind_filename))
    with open(cveid_by_kind_name, 'r', encoding='UTF-8') as cveid_by_kind_f:  # 打开文件
        cveid_by_kind_lines = cveid_by_kind_f.readlines()  # 获取文件的所有行
        for cveid_by_kind_line in cveid_by_kind_lines:
            id = cveid_by_kind_line.rstrip('\n')
            cveid_overflow.append(id)

    # 漏洞类别为dos
    cveid_dos = []
    cveid_by_kind_path = os.getcwd() + '/data/cveid_by_kind/'  # 存放的文件夹
    cveid_by_kind_filename = 'cveid_dos.txt'
    cveid_by_kind_name = os.path.join('%s%s' % (cveid_by_kind_path, cveid_by_kind_filename))
    with open(cveid_by_kind_name, 'r', encoding='UTF-8') as cveid_by_kind_f:  # 打开文件
        cveid_by_kind_lines = cveid_by_kind_f.readlines()  # 获取文件的所有行
        for cveid_by_kind_line in cveid_by_kind_lines:
            id = cveid_by_kind_line.rstrip('\n')
            cveid_dos.append(id)

    # 漏洞类别为execution
    cveid_execution = []
    cveid_by_kind_path = os.getcwd() + '/data/cveid_by_kind/'  # 存放的文件夹
    cveid_by_kind_filename = 'cveid_execution.txt'
    cveid_by_kind_name = os.path.join('%s%s' % (cveid_by_kind_path, cveid_by_kind_filename))
    with open(cveid_by_kind_name, 'r', encoding='UTF-8') as cveid_by_kind_f:  # 打开文件
        cveid_by_kind_lines = cveid_by_kind_f.readlines()  # 获取文件的所有行
        for cveid_by_kind_line in cveid_by_kind_lines:
            id = cveid_by_kind_line.rstrip('\n')
            cveid_execution.append(id)

    # 严格匹配参数
    cve_overall_strict_match_true_cnt_httprs = 0
    cve_overall_strict_match_false_cnt_httprs = 0
    cve_overall_strict_match_true_cnt_csrf = 0
    cve_overall_strict_match_false_cnt_csrf = 0
    cve_overall_strict_match_true_cnt_fileinc = 0
    cve_overall_strict_match_false_cnt_fileinc = 0
    cve_overall_strict_match_true_cnt_dirtra = 0
    cve_overall_strict_match_false_cnt_dirtra = 0
    cve_overall_strict_match_true_cnt_gainpre = 0
    cve_overall_strict_match_false_cnt_gainpre = 0
    cve_overall_strict_match_true_cnt_memc = 0
    cve_overall_strict_match_false_cnt_memc = 0
    cve_overall_strict_match_true_cnt_bypass = 0
    cve_overall_strict_match_false_cnt_bypass = 0
    cve_overall_strict_match_true_cnt_sqli = 0
    cve_overall_strict_match_false_cnt_sqli = 0
    cve_overall_strict_match_true_cnt_infor = 0
    cve_overall_strict_match_false_cnt_infor = 0
    cve_overall_strict_match_true_cnt_xss = 0
    cve_overall_strict_match_false_cnt_xss = 0
    cve_overall_strict_match_true_cnt_overflow = 0
    cve_overall_strict_match_false_cnt_overflow = 0
    cve_overall_strict_match_true_cnt_dos = 0
    cve_overall_strict_match_false_cnt_dos = 0
    cve_overall_strict_match_true_cnt_execution = 0
    cve_overall_strict_match_false_cnt_execution = 0

    # 松散匹配参数
    cve_overall_loose_match_true_cnt_httprs = 0
    cve_overall_loose_match_false_cnt_httprs = 0
    cve_overall_loose_match_true_cnt_csrf = 0
    cve_overall_loose_match_false_cnt_csrf = 0
    cve_overall_loose_match_true_cnt_fileinc = 0
    cve_overall_loose_match_false_cnt_fileinc = 0
    cve_overall_loose_match_true_cnt_dirtra = 0
    cve_overall_loose_match_false_cnt_dirtra = 0
    cve_overall_loose_match_true_cnt_gainpre = 0
    cve_overall_loose_match_false_cnt_gainpre = 0
    cve_overall_loose_match_true_cnt_memc = 0
    cve_overall_loose_match_false_cnt_memc = 0
    cve_overall_loose_match_true_cnt_bypass = 0
    cve_overall_loose_match_false_cnt_bypass = 0
    cve_overall_loose_match_true_cnt_sqli = 0
    cve_overall_loose_match_false_cnt_sqli = 0
    cve_overall_loose_match_true_cnt_infor = 0
    cve_overall_loose_match_false_cnt_infor = 0
    cve_overall_loose_match_true_cnt_xss = 0
    cve_overall_loose_match_false_cnt_xss = 0
    cve_overall_loose_match_true_cnt_overflow = 0
    cve_overall_loose_match_false_cnt_overflow = 0
    cve_overall_loose_match_true_cnt_dos = 0
    cve_overall_loose_match_false_cnt_dos = 0
    cve_overall_loose_match_true_cnt_execution = 0
    cve_overall_loose_match_false_cnt_execution = 0


    with open(soft_dic_name, 'r', encoding='UTF-8') as soft_f:  # 打开文件
        soft_lines = soft_f.readlines()  # 获取文件的所有行
        for soft_line in soft_lines:
            soft_raw = soft_line
            soft_raw = soft_raw.lstrip('name_and_version_dict=')
            # json格式加载失败，https://www.json.cn/提示RangeError: Invalid array length
            # soft_replace = re.sub('\'', '\"', soft_raw)
            # soft_dict = json.loads(soft_replace)
            soft_dict = ast.literal_eval(soft_raw)

            cveid_cnt = 0
            for cveid in soft_dict:
                cveid_cnt = cveid_cnt + 1
                print('CVEID：' + str(cveid) + '    CVEID的数量：' + str(cveid_cnt) + '\n')
                cve_overall_soft = soft_dict[cveid]

                # 严格匹配
                cve_overall_strict_match = cve_overall_soft['overall_strict_match']
                if cve_overall_strict_match is True:
                    if cveid in cveid_httprs:
                        cve_overall_strict_match_true_cnt_httprs = cve_overall_strict_match_true_cnt_httprs + 1
                    elif cveid in cveid_csrf:
                        cve_overall_strict_match_true_cnt_csrf = cve_overall_strict_match_true_cnt_csrf + 1
                    elif cveid in cveid_fileinc:
                        cve_overall_strict_match_true_cnt_fileinc = cve_overall_strict_match_true_cnt_fileinc + 1
                    elif cveid in cveid_dirtra:
                        cve_overall_strict_match_true_cnt_dirtra = cve_overall_strict_match_true_cnt_dirtra + 1
                    elif cveid in cveid_gainpre:
                        cve_overall_strict_match_true_cnt_gainpre = cve_overall_strict_match_true_cnt_gainpre + 1
                    elif cveid in cveid_memc:
                        cve_overall_strict_match_true_cnt_memc = cve_overall_strict_match_true_cnt_memc + 1
                    elif cveid in cveid_bypass:
                        cve_overall_strict_match_true_cnt_bypass = cve_overall_strict_match_true_cnt_bypass + 1
                    elif cveid in cveid_sqli:
                        cve_overall_strict_match_true_cnt_sqli = cve_overall_strict_match_true_cnt_sqli + 1
                    elif cveid in cveid_infor:
                        cve_overall_strict_match_true_cnt_infor = cve_overall_strict_match_true_cnt_infor + 1
                    elif cveid in cveid_xss:
                        cve_overall_strict_match_true_cnt_xss = cve_overall_strict_match_true_cnt_xss + 1
                    elif cveid in cveid_overflow:
                        cve_overall_strict_match_true_cnt_overflow = cve_overall_strict_match_true_cnt_overflow + 1
                    elif cveid in cveid_dos:
                        cve_overall_strict_match_true_cnt_dos = cve_overall_strict_match_true_cnt_dos + 1
                    elif cveid in cveid_execution:
                        cve_overall_strict_match_true_cnt_execution = cve_overall_strict_match_true_cnt_execution + 1
                elif cve_overall_strict_match is False:
                    if cveid in cveid_httprs:
                        cve_overall_strict_match_false_cnt_httprs = cve_overall_strict_match_false_cnt_httprs + 1
                    elif cveid in cveid_csrf:
                        cve_overall_strict_match_false_cnt_csrf = cve_overall_strict_match_false_cnt_csrf + 1
                    elif cveid in cveid_fileinc:
                        cve_overall_strict_match_false_cnt_fileinc = cve_overall_strict_match_false_cnt_fileinc + 1
                    elif cveid in cveid_dirtra:
                        cve_overall_strict_match_false_cnt_dirtra = cve_overall_strict_match_false_cnt_dirtra + 1
                    elif cveid in cveid_gainpre:
                        cve_overall_strict_match_false_cnt_gainpre = cve_overall_strict_match_false_cnt_gainpre + 1
                    elif cveid in cveid_memc:
                        cve_overall_strict_match_false_cnt_memc = cve_overall_strict_match_false_cnt_memc + 1
                    elif cveid in cveid_bypass:
                        cve_overall_strict_match_false_cnt_bypass = cve_overall_strict_match_false_cnt_bypass + 1
                    elif cveid in cveid_sqli:
                        cve_overall_strict_match_false_cnt_sqli = cve_overall_strict_match_false_cnt_sqli + 1
                    elif cveid in cveid_infor:
                        cve_overall_strict_match_false_cnt_infor = cve_overall_strict_match_false_cnt_infor + 1
                    elif cveid in cveid_xss:
                        cve_overall_strict_match_false_cnt_xss = cve_overall_strict_match_false_cnt_xss + 1
                    elif cveid in cveid_overflow:
                        cve_overall_strict_match_false_cnt_overflow = cve_overall_strict_match_false_cnt_overflow + 1
                    elif cveid in cveid_dos:
                        cve_overall_strict_match_false_cnt_dos = cve_overall_strict_match_false_cnt_dos + 1
                    elif cveid in cveid_execution:
                        cve_overall_strict_match_false_cnt_execution = cve_overall_strict_match_false_cnt_execution + 1

                # 松散匹配
                cve_overall_loose_match = cve_overall_soft['overall_loose_match']
                if cve_overall_loose_match[0] is True:  # 暂时不记录具体的值，'Overclaim'等
                    if cveid in cveid_httprs:
                        cve_overall_loose_match_true_cnt_httprs = cve_overall_loose_match_true_cnt_httprs + 1
                    elif cveid in cveid_csrf:
                        cve_overall_loose_match_true_cnt_csrf = cve_overall_loose_match_true_cnt_csrf + 1
                    elif cveid in cveid_fileinc:
                        cve_overall_loose_match_true_cnt_fileinc = cve_overall_loose_match_true_cnt_fileinc + 1
                    elif cveid in cveid_dirtra:
                        cve_overall_loose_match_true_cnt_dirtra = cve_overall_loose_match_true_cnt_dirtra + 1
                    elif cveid in cveid_gainpre:
                        cve_overall_loose_match_true_cnt_gainpre = cve_overall_loose_match_true_cnt_gainpre + 1
                    elif cveid in cveid_memc:
                        cve_overall_loose_match_true_cnt_memc = cve_overall_loose_match_true_cnt_memc + 1
                    elif cveid in cveid_bypass:
                        cve_overall_loose_match_true_cnt_bypass = cve_overall_loose_match_true_cnt_bypass + 1
                    elif cveid in cveid_sqli:
                        cve_overall_loose_match_true_cnt_sqli = cve_overall_loose_match_true_cnt_sqli + 1
                    elif cveid in cveid_infor:
                        cve_overall_loose_match_true_cnt_infor = cve_overall_loose_match_true_cnt_infor + 1
                    elif cveid in cveid_xss:
                        cve_overall_loose_match_true_cnt_xss = cve_overall_loose_match_true_cnt_xss + 1
                    elif cveid in cveid_overflow:
                        cve_overall_loose_match_true_cnt_overflow = cve_overall_loose_match_true_cnt_overflow + 1
                    elif cveid in cveid_dos:
                        cve_overall_loose_match_true_cnt_dos = cve_overall_loose_match_true_cnt_dos + 1
                    elif cveid in cveid_execution:
                        cve_overall_loose_match_true_cnt_execution = cve_overall_loose_match_true_cnt_execution + 1
                elif cve_overall_loose_match[0] is False:  # 暂时不记录具体的值，'Overclaim'等
                    if cveid in cveid_httprs:
                        cve_overall_loose_match_false_cnt_httprs = cve_overall_loose_match_false_cnt_httprs + 1
                    elif cveid in cveid_csrf:
                        cve_overall_loose_match_false_cnt_csrf = cve_overall_loose_match_false_cnt_csrf + 1
                    elif cveid in cveid_fileinc:
                        cve_overall_loose_match_false_cnt_fileinc = cve_overall_loose_match_false_cnt_fileinc + 1
                    elif cveid in cveid_dirtra:
                        cve_overall_loose_match_false_cnt_dirtra = cve_overall_loose_match_false_cnt_dirtra + 1
                    elif cveid in cveid_gainpre:
                        cve_overall_loose_match_false_cnt_gainpre = cve_overall_loose_match_false_cnt_gainpre + 1
                    elif cveid in cveid_memc:
                        cve_overall_loose_match_false_cnt_memc = cve_overall_loose_match_false_cnt_memc + 1
                    elif cveid in cveid_bypass:
                        cve_overall_loose_match_false_cnt_bypass = cve_overall_loose_match_false_cnt_bypass + 1
                    elif cveid in cveid_sqli:
                        cve_overall_loose_match_false_cnt_sqli = cve_overall_loose_match_false_cnt_sqli + 1
                    elif cveid in cveid_infor:
                        cve_overall_loose_match_false_cnt_infor = cve_overall_loose_match_false_cnt_infor + 1
                    elif cveid in cveid_xss:
                        cve_overall_loose_match_false_cnt_xss = cve_overall_loose_match_false_cnt_xss + 1
                    elif cveid in cveid_overflow:
                        cve_overall_loose_match_false_cnt_overflow = cve_overall_loose_match_false_cnt_overflow + 1
                    elif cveid in cveid_dos:
                        cve_overall_loose_match_false_cnt_dos = cve_overall_loose_match_false_cnt_dos + 1
                    elif cveid in cveid_execution:
                        cve_overall_loose_match_false_cnt_execution = cve_overall_loose_match_false_cnt_execution + 1


    # 严格匹配
    cve_overall_strict_match_sum_cnt_httprs = cve_overall_strict_match_true_cnt_httprs + cve_overall_strict_match_false_cnt_httprs
    cve_overall_strict_match_sum_cnt_csrf = cve_overall_strict_match_true_cnt_csrf + cve_overall_strict_match_false_cnt_csrf
    cve_overall_strict_match_sum_cnt_fileinc = cve_overall_strict_match_true_cnt_fileinc + cve_overall_strict_match_false_cnt_fileinc
    cve_overall_strict_match_sum_cnt_dirtra = cve_overall_strict_match_true_cnt_dirtra + cve_overall_strict_match_false_cnt_dirtra
    cve_overall_strict_match_sum_cnt_gainpre = cve_overall_strict_match_true_cnt_gainpre + cve_overall_strict_match_false_cnt_gainpre
    cve_overall_strict_match_sum_cnt_memc = cve_overall_strict_match_true_cnt_memc + cve_overall_strict_match_false_cnt_memc
    cve_overall_strict_match_sum_cnt_bypass = cve_overall_strict_match_true_cnt_bypass + cve_overall_strict_match_false_cnt_bypass
    cve_overall_strict_match_sum_cnt_sqli = cve_overall_strict_match_true_cnt_sqli + cve_overall_strict_match_false_cnt_sqli
    cve_overall_strict_match_sum_cnt_infor = cve_overall_strict_match_true_cnt_infor + cve_overall_strict_match_false_cnt_infor
    cve_overall_strict_match_sum_cnt_xss = cve_overall_strict_match_true_cnt_xss + cve_overall_strict_match_false_cnt_xss
    cve_overall_strict_match_sum_cnt_overflow = cve_overall_strict_match_true_cnt_overflow + cve_overall_strict_match_false_cnt_overflow
    cve_overall_strict_match_sum_cnt_dos = cve_overall_strict_match_true_cnt_dos + cve_overall_strict_match_false_cnt_dos
    cve_overall_strict_match_sum_cnt_execution = cve_overall_strict_match_true_cnt_execution + cve_overall_strict_match_false_cnt_execution

    # 松散匹配
    cve_overall_loose_match_sum_cnt_httprs = cve_overall_loose_match_true_cnt_httprs + cve_overall_loose_match_false_cnt_httprs
    cve_overall_loose_match_sum_cnt_csrf = cve_overall_loose_match_true_cnt_csrf + cve_overall_loose_match_false_cnt_csrf
    cve_overall_loose_match_sum_cnt_fileinc = cve_overall_loose_match_true_cnt_fileinc + cve_overall_loose_match_false_cnt_fileinc
    cve_overall_loose_match_sum_cnt_dirtra = cve_overall_loose_match_true_cnt_dirtra + cve_overall_loose_match_false_cnt_dirtra
    cve_overall_loose_match_sum_cnt_gainpre = cve_overall_loose_match_true_cnt_gainpre + cve_overall_loose_match_false_cnt_gainpre
    cve_overall_loose_match_sum_cnt_memc = cve_overall_loose_match_true_cnt_memc + cve_overall_loose_match_false_cnt_memc
    cve_overall_loose_match_sum_cnt_bypass = cve_overall_loose_match_true_cnt_bypass + cve_overall_loose_match_false_cnt_bypass
    cve_overall_loose_match_sum_cnt_sqli = cve_overall_loose_match_true_cnt_sqli + cve_overall_loose_match_false_cnt_sqli
    cve_overall_loose_match_sum_cnt_infor = cve_overall_loose_match_true_cnt_infor + cve_overall_loose_match_false_cnt_infor
    cve_overall_loose_match_sum_cnt_xss = cve_overall_loose_match_true_cnt_xss + cve_overall_loose_match_false_cnt_xss
    cve_overall_loose_match_sum_cnt_overflow = cve_overall_loose_match_true_cnt_overflow + cve_overall_loose_match_false_cnt_overflow
    cve_overall_loose_match_sum_cnt_dos = cve_overall_loose_match_true_cnt_dos + cve_overall_loose_match_false_cnt_dos
    cve_overall_loose_match_sum_cnt_execution = cve_overall_loose_match_true_cnt_execution + cve_overall_loose_match_false_cnt_execution

    # 保存在本地
    cve_and_nvd_soft_path = os.getcwd() + '/data/softname_version_compare/'  # 文件夹
    cve_and_nvd_soft_filename = '9_get_result_by_vulnerability_kind.txt'  # 这样命名方便查看
    cve_and_nvd_soft_file_path = os.path.join('%s%s' % (cve_and_nvd_soft_path, cve_and_nvd_soft_filename))
    # 字典原始格式保存在本地
    with open(cve_and_nvd_soft_file_path, 'w', encoding='utf-8') as name_and_version_f:  # 用w而非a，用于覆盖
        name_and_version_f.write('不同漏洞类别的一致性情况：\n\n')
        name_and_version_f.write('严格匹配：\n')  # 写入数据
        name_and_version_f.write('httprs类别严格匹配正确的CVEID数量：' + str(cve_overall_strict_match_true_cnt_httprs) + '\n')
        if cve_overall_strict_match_sum_cnt_httprs != 0:
            name_and_version_f.write('httprs类别严格匹配正确率：' + str(cve_overall_strict_match_true_cnt_httprs / cve_overall_strict_match_sum_cnt_httprs) + '\n')
        else:
            name_and_version_f.write('httprs类别严格匹配正确率：0\n')
        name_and_version_f.write('httprs类别严格匹配错误的CVEID数量：' + str(cve_overall_strict_match_false_cnt_httprs) + '\n')
        if cve_overall_strict_match_sum_cnt_httprs != 0:
            name_and_version_f.write('httprs类别严格匹配错误率：' + str(cve_overall_strict_match_false_cnt_httprs / cve_overall_strict_match_sum_cnt_httprs) + '\n')
        else:
            name_and_version_f.write('httprs类别严格匹配错误率：0\n')

        name_and_version_f.write('csrf类别严格匹配正确的CVEID数量：' + str(cve_overall_strict_match_true_cnt_csrf) + '\n')
        if cve_overall_strict_match_sum_cnt_csrf != 0:
            name_and_version_f.write('csrf类别严格匹配正确率：' + str(cve_overall_strict_match_true_cnt_csrf / cve_overall_strict_match_sum_cnt_csrf) + '\n')
        else:
            name_and_version_f.write('csrf类别严格匹配正确率：0\n')
        name_and_version_f.write('csrf类别严格匹配错误的CVEID数量：' + str(cve_overall_strict_match_false_cnt_csrf) + '\n')
        if cve_overall_strict_match_sum_cnt_csrf != 0:
            name_and_version_f.write('csrf类别严格匹配错误率：' + str(cve_overall_strict_match_false_cnt_csrf / cve_overall_strict_match_sum_cnt_csrf) + '\n')
        else:
            name_and_version_f.write('csrf类别严格匹配错误率：0\n')

        name_and_version_f.write('fileinc类别严格匹配正确的CVEID数量：' + str(cve_overall_strict_match_true_cnt_fileinc) + '\n')
        if cve_overall_strict_match_sum_cnt_fileinc != 0:
            name_and_version_f.write('fileinc类别严格匹配正确率：' + str(cve_overall_strict_match_true_cnt_fileinc / cve_overall_strict_match_sum_cnt_fileinc) + '\n')
        else:
            name_and_version_f.write('fileinc类别严格匹配正确率：0\n')
        name_and_version_f.write('fileinc类别严格匹配错误的CVEID数量：' + str(cve_overall_strict_match_false_cnt_fileinc) + '\n')
        if cve_overall_strict_match_sum_cnt_fileinc != 0:
            name_and_version_f.write('fileinc类别严格匹配错误率：' + str(cve_overall_strict_match_false_cnt_fileinc / cve_overall_strict_match_sum_cnt_fileinc) + '\n')
        else:
            name_and_version_f.write('fileinc类别严格匹配错误率：0\n')

        name_and_version_f.write('dirtra类别严格匹配正确的CVEID数量：' + str(cve_overall_strict_match_true_cnt_dirtra) + '\n')
        if cve_overall_strict_match_sum_cnt_dirtra != 0:
            name_and_version_f.write('dirtra类别严格匹配正确率：' + str(cve_overall_strict_match_true_cnt_dirtra / cve_overall_strict_match_sum_cnt_dirtra) + '\n')
        else:
            name_and_version_f.write('dirtra类别严格匹配正确率：0\n')
        name_and_version_f.write('dirtra类别严格匹配错误的CVEID数量：' + str(cve_overall_strict_match_false_cnt_dirtra) + '\n')
        if cve_overall_strict_match_sum_cnt_dirtra != 0:
            name_and_version_f.write('dirtra类别严格匹配错误率：' + str(cve_overall_strict_match_false_cnt_dirtra / cve_overall_strict_match_sum_cnt_dirtra) + '\n')
        else:
            name_and_version_f.write('dirtra类别严格匹配错误率：0\n')

        name_and_version_f.write('gainpre类别严格匹配正确的CVEID数量：' + str(cve_overall_strict_match_true_cnt_gainpre) + '\n')
        if cve_overall_strict_match_sum_cnt_gainpre != 0:
            name_and_version_f.write('gainpre类别严格匹配正确率：' + str(cve_overall_strict_match_true_cnt_gainpre / cve_overall_strict_match_sum_cnt_gainpre) + '\n')
        else:
            name_and_version_f.write('gainpre类别严格匹配正确率：0\n')
        name_and_version_f.write('gainpre类别严格匹配错误的CVEID数量：' + str(cve_overall_strict_match_false_cnt_gainpre) + '\n')
        if cve_overall_strict_match_sum_cnt_gainpre != 0:
            name_and_version_f.write('gainpre类别严格匹配错误率：' + str(cve_overall_strict_match_false_cnt_gainpre / cve_overall_strict_match_sum_cnt_gainpre) + '\n')
        else:
            name_and_version_f.write('gainpre类别严格匹配错误率：0\n')

        name_and_version_f.write('memc类别严格匹配正确的CVEID数量：' + str(cve_overall_strict_match_true_cnt_memc) + '\n')
        if cve_overall_strict_match_sum_cnt_memc != 0:
            name_and_version_f.write('memc类别严格匹配正确率：' + str(cve_overall_strict_match_true_cnt_memc / cve_overall_strict_match_sum_cnt_memc) + '\n')
        else:
            name_and_version_f.write('memc类别严格匹配正确率：0\n')
        name_and_version_f.write('memc类别严格匹配错误的CVEID数量：' + str(cve_overall_strict_match_false_cnt_memc) + '\n')
        if cve_overall_strict_match_sum_cnt_memc != 0:
            name_and_version_f.write('memc类别严格匹配错误率：' + str(cve_overall_strict_match_false_cnt_memc / cve_overall_strict_match_sum_cnt_memc) + '\n')
        else:
            name_and_version_f.write('memc类别严格匹配错误率：0\n')

        name_and_version_f.write('bypass类别严格匹配正确的CVEID数量：' + str(cve_overall_strict_match_true_cnt_bypass) + '\n')
        if cve_overall_strict_match_sum_cnt_bypass != 0:
            name_and_version_f.write('bypass类别严格匹配正确率：' + str(cve_overall_strict_match_true_cnt_bypass / cve_overall_strict_match_sum_cnt_bypass) + '\n')
        else:
            name_and_version_f.write('bypass类别严格匹配正确率：0\n')
        name_and_version_f.write('bypass类别严格匹配错误的CVEID数量：' + str(cve_overall_strict_match_false_cnt_bypass) + '\n')
        if cve_overall_strict_match_sum_cnt_bypass != 0:
            name_and_version_f.write('bypass类别严格匹配错误率：' + str(cve_overall_strict_match_false_cnt_bypass / cve_overall_strict_match_sum_cnt_bypass) + '\n')
        else:
            name_and_version_f.write('bypass类别严格匹配错误率：0\n')

        name_and_version_f.write('sqli类别严格匹配正确的CVEID数量：' + str(cve_overall_strict_match_true_cnt_sqli) + '\n')
        if cve_overall_strict_match_sum_cnt_sqli != 0:
            name_and_version_f.write('sqli类别严格匹配正确率：' + str(cve_overall_strict_match_true_cnt_sqli / cve_overall_strict_match_sum_cnt_sqli) + '\n')
        else:
            name_and_version_f.write('sqli类别严格匹配正确率：0\n')
        name_and_version_f.write('sqli类别严格匹配错误的CVEID数量：' + str(cve_overall_strict_match_false_cnt_sqli) + '\n')
        if cve_overall_strict_match_sum_cnt_sqli != 0:
            name_and_version_f.write('sqli类别严格匹配错误率：' + str(cve_overall_strict_match_false_cnt_sqli / cve_overall_strict_match_sum_cnt_sqli) + '\n')
        else:
            name_and_version_f.write('sqli类别严格匹配错误率：0\n')

        name_and_version_f.write('infor类别严格匹配正确的CVEID数量：' + str(cve_overall_strict_match_true_cnt_infor) + '\n')
        if cve_overall_strict_match_sum_cnt_infor != 0:
            name_and_version_f.write('infor类别严格匹配正确率：' + str(cve_overall_strict_match_true_cnt_infor / cve_overall_strict_match_sum_cnt_infor) + '\n')
        else:
            name_and_version_f.write('infor类别严格匹配正确率：0\n')
        name_and_version_f.write('infor类别严格匹配错误的CVEID数量：' + str(cve_overall_strict_match_false_cnt_infor) + '\n')
        if cve_overall_strict_match_sum_cnt_infor != 0:
            name_and_version_f.write('infor类别严格匹配错误率：' + str(cve_overall_strict_match_false_cnt_infor / cve_overall_strict_match_sum_cnt_infor) + '\n')
        else:
            name_and_version_f.write('infor类别严格匹配错误率：0\n')

        name_and_version_f.write('xss类别严格匹配正确的CVEID数量：' + str(cve_overall_strict_match_true_cnt_xss) + '\n')
        if cve_overall_strict_match_sum_cnt_xss != 0:
            name_and_version_f.write('xss类别严格匹配正确率：' + str(cve_overall_strict_match_true_cnt_xss / cve_overall_strict_match_sum_cnt_xss) + '\n')
        else:
            name_and_version_f.write('xss类别严格匹配正确率：0\n')
        name_and_version_f.write('xss类别严格匹配错误的CVEID数量：' + str(cve_overall_strict_match_false_cnt_xss) + '\n')
        if cve_overall_strict_match_sum_cnt_xss != 0:
            name_and_version_f.write('xss类别严格匹配错误率：' + str(cve_overall_strict_match_false_cnt_xss / cve_overall_strict_match_sum_cnt_xss) + '\n')
        else:
            name_and_version_f.write('xss类别严格匹配错误率：0\n')

        name_and_version_f.write('overflow类别严格匹配正确的CVEID数量：' + str(cve_overall_strict_match_true_cnt_overflow) + '\n')
        if cve_overall_strict_match_sum_cnt_overflow != 0:
            name_and_version_f.write('overflow类别严格匹配正确率：' + str(cve_overall_strict_match_true_cnt_overflow / cve_overall_strict_match_sum_cnt_overflow) + '\n')
        else:
            name_and_version_f.write('overflow类别严格匹配正确率：0\n')
        name_and_version_f.write('overflow类别严格匹配错误的CVEID数量：' + str(cve_overall_strict_match_false_cnt_overflow) + '\n')
        if cve_overall_strict_match_sum_cnt_overflow != 0:
            name_and_version_f.write('overflow类别严格匹配错误率：' + str(cve_overall_strict_match_false_cnt_overflow / cve_overall_strict_match_sum_cnt_overflow) + '\n')
        else:
            name_and_version_f.write('overflow类别严格匹配错误率：0\n')

        name_and_version_f.write('dos类别严格匹配正确的CVEID数量：' + str(cve_overall_strict_match_true_cnt_dos) + '\n')
        if cve_overall_strict_match_sum_cnt_dos != 0:
            name_and_version_f.write('dos类别严格匹配正确率：' + str(cve_overall_strict_match_true_cnt_dos / cve_overall_strict_match_sum_cnt_dos) + '\n')
        else:
            name_and_version_f.write('dos类别严格匹配正确率：0\n')
        name_and_version_f.write('dos类别严格匹配错误的CVEID数量：' + str(cve_overall_strict_match_false_cnt_dos) + '\n')
        if cve_overall_strict_match_sum_cnt_dos != 0:
            name_and_version_f.write('dos类别严格匹配错误率：' + str(cve_overall_strict_match_false_cnt_dos / cve_overall_strict_match_sum_cnt_dos) + '\n')
        else:
            name_and_version_f.write('dos类别严格匹配错误率：0\n')

        name_and_version_f.write('execution类别严格匹配正确的CVEID数量：' + str(cve_overall_strict_match_true_cnt_execution) + '\n')
        if cve_overall_strict_match_sum_cnt_execution != 0:
            name_and_version_f.write('execution类别严格匹配正确率：' + str(cve_overall_strict_match_true_cnt_execution / cve_overall_strict_match_sum_cnt_execution) + '\n')
        else:
            name_and_version_f.write('execution类别严格匹配正确率：0\n')
        name_and_version_f.write('execution类别严格匹配错误的CVEID数量：' + str(cve_overall_strict_match_false_cnt_execution) + '\n')
        if cve_overall_strict_match_sum_cnt_execution != 0:
            name_and_version_f.write('execution类别严格匹配错误率：' + str(cve_overall_strict_match_false_cnt_execution / cve_overall_strict_match_sum_cnt_execution) + '\n')
        else:
            name_and_version_f.write('execution类别严格匹配错误率：0\n')


        name_and_version_f.write('\n松散匹配：\n')
        name_and_version_f.write('httprs类别松散匹配正确的CVEID数量：' + str(cve_overall_loose_match_true_cnt_httprs) + '\n')
        if cve_overall_loose_match_sum_cnt_httprs != 0:
            name_and_version_f.write('httprs类别松散匹配正确率：' + str(cve_overall_loose_match_true_cnt_httprs / cve_overall_loose_match_sum_cnt_httprs) + '\n')
        else:
            name_and_version_f.write('httprs类别松散匹配正确率：0\n')
        name_and_version_f.write('httprs类别松散匹配错误的CVEID数量：' + str(cve_overall_loose_match_false_cnt_httprs) + '\n')
        if cve_overall_loose_match_sum_cnt_httprs != 0:
            name_and_version_f.write('httprs类别松散匹配错误率：' + str(cve_overall_loose_match_false_cnt_httprs / cve_overall_loose_match_sum_cnt_httprs) + '\n')
        else:
            name_and_version_f.write('httprs类别松散匹配错误率：0\n')

        name_and_version_f.write('csrf类别松散匹配正确的CVEID数量：' + str(cve_overall_loose_match_true_cnt_csrf) + '\n')
        if cve_overall_loose_match_sum_cnt_csrf != 0:
            name_and_version_f.write('csrf类别松散匹配正确率：' + str(cve_overall_loose_match_true_cnt_csrf / cve_overall_loose_match_sum_cnt_csrf) + '\n')
        else:
            name_and_version_f.write('csrf类别松散匹配正确率：0\n')
        name_and_version_f.write('csrf类别松散匹配错误的CVEID数量：' + str(cve_overall_loose_match_false_cnt_csrf) + '\n')
        if cve_overall_loose_match_sum_cnt_csrf != 0:
            name_and_version_f.write('csrf类别松散匹配错误率：' + str(cve_overall_loose_match_false_cnt_csrf / cve_overall_loose_match_sum_cnt_csrf) + '\n')
        else:
            name_and_version_f.write('csrf类别松散匹配错误率：0\n')

        name_and_version_f.write('fileinc类别松散匹配正确的CVEID数量：' + str(cve_overall_loose_match_true_cnt_fileinc) + '\n')
        if cve_overall_loose_match_sum_cnt_fileinc != 0:
            name_and_version_f.write('fileinc类别松散匹配正确率：' + str(cve_overall_loose_match_true_cnt_fileinc / cve_overall_loose_match_sum_cnt_fileinc) + '\n')
        else:
            name_and_version_f.write('fileinc类别松散匹配正确率：0\n')
        name_and_version_f.write('fileinc类别松散匹配错误的CVEID数量：' + str(cve_overall_loose_match_false_cnt_fileinc) + '\n')
        if cve_overall_loose_match_sum_cnt_fileinc != 0:
            name_and_version_f.write('fileinc类别松散匹配错误率：' + str(cve_overall_loose_match_false_cnt_fileinc / cve_overall_loose_match_sum_cnt_fileinc) + '\n')
        else:
            name_and_version_f.write('fileinc类别松散匹配错误率：0\n')

        name_and_version_f.write('dirtra类别松散匹配正确的CVEID数量：' + str(cve_overall_loose_match_true_cnt_dirtra) + '\n')
        if cve_overall_loose_match_sum_cnt_dirtra != 0:
            name_and_version_f.write('dirtra类别松散匹配正确率：' + str(cve_overall_loose_match_true_cnt_dirtra / cve_overall_loose_match_sum_cnt_dirtra) + '\n')
        else:
            name_and_version_f.write('dirtra类别松散匹配正确率：0\n')
        name_and_version_f.write('dirtra类别松散匹配错误的CVEID数量：' + str(cve_overall_loose_match_false_cnt_dirtra) + '\n')
        if cve_overall_loose_match_sum_cnt_dirtra != 0:
            name_and_version_f.write('dirtra类别松散匹配错误率：' + str(cve_overall_loose_match_false_cnt_dirtra / cve_overall_loose_match_sum_cnt_dirtra) + '\n')
        else:
            name_and_version_f.write('dirtra类别松散匹配错误率：0\n')

        name_and_version_f.write('gainpre类别松散匹配正确的CVEID数量：' + str(cve_overall_loose_match_true_cnt_gainpre) + '\n')
        if cve_overall_loose_match_sum_cnt_gainpre != 0:
            name_and_version_f.write('gainpre类别松散匹配正确率：' + str(cve_overall_loose_match_true_cnt_gainpre / cve_overall_loose_match_sum_cnt_gainpre) + '\n')
        else:
            name_and_version_f.write('gainpre类别松散匹配正确率：0\n')
        name_and_version_f.write('gainpre类别松散匹配错误的CVEID数量：' + str(cve_overall_loose_match_false_cnt_gainpre) + '\n')
        if cve_overall_loose_match_sum_cnt_gainpre != 0:
            name_and_version_f.write('gainpre类别松散匹配错误率：' + str(cve_overall_loose_match_false_cnt_gainpre / cve_overall_loose_match_sum_cnt_gainpre) + '\n')
        else:
            name_and_version_f.write('gainpre类别松散匹配错误率：0\n')

        name_and_version_f.write('memc类别松散匹配正确的CVEID数量：' + str(cve_overall_loose_match_true_cnt_memc) + '\n')
        if cve_overall_loose_match_sum_cnt_memc != 0:
            name_and_version_f.write('memc类别松散匹配正确率：' + str(cve_overall_loose_match_true_cnt_memc / cve_overall_loose_match_sum_cnt_memc) + '\n')
        else:
            name_and_version_f.write('memc类别松散匹配正确率：0\n')
        name_and_version_f.write('memc类别松散匹配错误的CVEID数量：' + str(cve_overall_loose_match_false_cnt_memc) + '\n')
        if cve_overall_loose_match_sum_cnt_memc != 0:
            name_and_version_f.write('memc类别松散匹配错误率：' + str(cve_overall_loose_match_false_cnt_memc / cve_overall_loose_match_sum_cnt_memc) + '\n')
        else:
            name_and_version_f.write('memc类别松散匹配错误率：0\n')

        name_and_version_f.write('bypass类别松散匹配正确的CVEID数量：' + str(cve_overall_loose_match_true_cnt_bypass) + '\n')
        if cve_overall_loose_match_sum_cnt_bypass != 0:
            name_and_version_f.write('bypass类别松散匹配正确率：' + str(cve_overall_loose_match_true_cnt_bypass / cve_overall_loose_match_sum_cnt_bypass) + '\n')
        else:
            name_and_version_f.write('bypass类别松散匹配正确率：0\n')
        name_and_version_f.write('bypass类别松散匹配错误的CVEID数量：' + str(cve_overall_loose_match_false_cnt_bypass) + '\n')
        if cve_overall_loose_match_sum_cnt_bypass != 0:
            name_and_version_f.write('bypass类别松散匹配错误率：' + str(cve_overall_loose_match_false_cnt_bypass / cve_overall_loose_match_sum_cnt_bypass) + '\n')
        else:
            name_and_version_f.write('bypass类别松散匹配错误率：0\n')

        name_and_version_f.write('sqli类别松散匹配正确的CVEID数量：' + str(cve_overall_loose_match_true_cnt_sqli) + '\n')
        if cve_overall_loose_match_sum_cnt_sqli != 0:
            name_and_version_f.write('sqli类别松散匹配正确率：' + str(cve_overall_loose_match_true_cnt_sqli / cve_overall_loose_match_sum_cnt_sqli) + '\n')
        else:
            name_and_version_f.write('sqli类别松散匹配正确率：0\n')
        name_and_version_f.write('sqli类别松散匹配错误的CVEID数量：' + str(cve_overall_loose_match_false_cnt_sqli) + '\n')
        if cve_overall_loose_match_sum_cnt_sqli != 0:
            name_and_version_f.write('sqli类别松散匹配错误率：' + str(cve_overall_loose_match_false_cnt_sqli / cve_overall_loose_match_sum_cnt_sqli) + '\n')
        else:
            name_and_version_f.write('sqli类别松散匹配错误率：0\n')

        name_and_version_f.write('infor类别松散匹配正确的CVEID数量：' + str(cve_overall_loose_match_true_cnt_infor) + '\n')
        if cve_overall_loose_match_sum_cnt_infor != 0:
            name_and_version_f.write('infor类别松散匹配正确率：' + str(cve_overall_loose_match_true_cnt_infor / cve_overall_loose_match_sum_cnt_infor) + '\n')
        else:
            name_and_version_f.write('infor类别松散匹配正确率：0\n')
        name_and_version_f.write('infor类别松散匹配错误的CVEID数量：' + str(cve_overall_loose_match_false_cnt_infor) + '\n')
        if cve_overall_loose_match_sum_cnt_infor != 0:
            name_and_version_f.write('infor类别松散匹配错误率：' + str(cve_overall_loose_match_false_cnt_infor / cve_overall_loose_match_sum_cnt_infor) + '\n')
        else:
            name_and_version_f.write('infor类别松散匹配错误率：0\n')

        name_and_version_f.write('xss类别松散匹配正确的CVEID数量：' + str(cve_overall_loose_match_true_cnt_xss) + '\n')
        if cve_overall_loose_match_sum_cnt_xss != 0:
            name_and_version_f.write('xss类别松散匹配正确率：' + str(cve_overall_loose_match_true_cnt_xss / cve_overall_loose_match_sum_cnt_xss) + '\n')
        else:
            name_and_version_f.write('xss类别松散匹配正确率：0\n')
        name_and_version_f.write('xss类别松散匹配错误的CVEID数量：' + str(cve_overall_loose_match_false_cnt_xss) + '\n')
        if cve_overall_loose_match_sum_cnt_xss != 0:
            name_and_version_f.write('xss类别松散匹配错误率：' + str(cve_overall_loose_match_false_cnt_xss / cve_overall_loose_match_sum_cnt_xss) + '\n')
        else:
            name_and_version_f.write('xss类别松散匹配错误率：0\n')

        name_and_version_f.write('overflow类别松散匹配正确的CVEID数量：' + str(cve_overall_loose_match_true_cnt_overflow) + '\n')
        if cve_overall_loose_match_sum_cnt_overflow != 0:
            name_and_version_f.write('overflow类别松散匹配正确率：' + str(cve_overall_loose_match_true_cnt_overflow / cve_overall_loose_match_sum_cnt_overflow) + '\n')
        else:
            name_and_version_f.write('overflow类别松散匹配正确率：0\n')
        name_and_version_f.write('overflow类别松散匹配错误的CVEID数量：' + str(cve_overall_loose_match_false_cnt_overflow) + '\n')
        if cve_overall_loose_match_sum_cnt_overflow != 0:
            name_and_version_f.write('overflow类别松散匹配错误率：' + str(cve_overall_loose_match_false_cnt_overflow / cve_overall_loose_match_sum_cnt_overflow) + '\n')
        else:
            name_and_version_f.write('overflow类别松散匹配错误率：0\n')

        name_and_version_f.write('dos类别松散匹配正确的CVEID数量：' + str(cve_overall_loose_match_true_cnt_dos) + '\n')
        if cve_overall_loose_match_sum_cnt_dos != 0:
            name_and_version_f.write('dos类别松散匹配正确率：' + str(cve_overall_loose_match_true_cnt_dos / cve_overall_loose_match_sum_cnt_dos) + '\n')
        else:
            name_and_version_f.write('dos类别松散匹配正确率：0\n')
        name_and_version_f.write('dos类别松散匹配错误的CVEID数量：' + str(cve_overall_loose_match_false_cnt_dos) + '\n')
        if cve_overall_loose_match_sum_cnt_dos != 0:
            name_and_version_f.write('dos类别松散匹配错误率：' + str(cve_overall_loose_match_false_cnt_dos / cve_overall_loose_match_sum_cnt_dos) + '\n')
        else:
            name_and_version_f.write('dos类别松散匹配错误率：0\n')

        name_and_version_f.write('execution类别松散匹配正确的CVEID数量：' + str(cve_overall_loose_match_true_cnt_execution) + '\n')
        if cve_overall_loose_match_sum_cnt_execution != 0:
            name_and_version_f.write('execution类别松散匹配正确率：' + str(cve_overall_loose_match_true_cnt_execution / cve_overall_loose_match_sum_cnt_execution) + '\n')
        else:
            name_and_version_f.write('execution类别松散匹配正确率：0\n')
        name_and_version_f.write('execution类别松散匹配错误的CVEID数量：' + str(cve_overall_loose_match_false_cnt_execution) + '\n')
        if cve_overall_loose_match_sum_cnt_execution != 0:
            name_and_version_f.write('execution类别松散匹配错误率：' + str(cve_overall_loose_match_false_cnt_execution / cve_overall_loose_match_sum_cnt_execution) + '\n')
        else:
            name_and_version_f.write('execution类别松散匹配错误率：0\n')
