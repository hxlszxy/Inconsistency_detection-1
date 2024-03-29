#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import ast
import re
import json
import re
import copy

'''
获取匹配错误的数据，便于手工分析
'''



# 查看cnnvd与nvd匹配正确但cnvd与nvd匹配错误的数据，在服务器运行该代码
# 分析cnnvd匹配率比cnvd高的原因
def get_diff_of_cnnvd_and_cnvd():
    # 获取softname和version内容
    soft_dic_path = os.getcwd() + '/data/reason_of_inconsistency/'  # 存放的文件夹
    cnvd_soft_dic_filename = '0_cnvd_measure_inconsistency.txt'
    cnnvd_soft_dic_filename = '0_cnnvd_measure_inconsistency.txt'
    cnvd_soft_dic_name = os.path.join('%s%s' % (soft_dic_path, cnvd_soft_dic_filename))
    cnnvd_soft_dic_name = os.path.join('%s%s' % (soft_dic_path, cnnvd_soft_dic_filename))
    cnvd_strict_match_dict = dict()
    cnvd_loose_match_dict = dict()
    cnnvd_soft_dict = dict()
    new_soft_dict = dict()

    # cnnvd
    with open(cnnvd_soft_dic_name, 'r', encoding='UTF-8') as cnnvd_soft_f:  # 打开文件
        cnnvd_soft_lines = cnnvd_soft_f.readlines()  # 获取文件的所有行
        for cnnvd_soft_line in cnnvd_soft_lines:
            cnnvd_soft_raw = cnnvd_soft_line
            cnnvd_soft_raw = cnnvd_soft_raw.lstrip('name_and_version_dict=')
            # json格式加载失败，https://www.json.cn/提示RangeError: Invalid array length
            # cnnvd_soft_replace = re.sub('\'', '\"', cnnvd_soft_raw)
            # cnnvd_soft_dict = json.loads(cnnvd_soft_replace)
            cnnvd_soft_dict = ast.literal_eval(cnnvd_soft_raw)

    # cnvd
    with open(cnvd_soft_dic_name, 'r', encoding='UTF-8') as cnvd_soft_f:  # 打开文件
        cnvd_soft_lines = cnvd_soft_f.readlines()  # 获取文件的所有行
        for cnvd_soft_line in cnvd_soft_lines:
            cnvd_soft_raw = cnvd_soft_line
            cnvd_soft_raw = cnvd_soft_raw.lstrip('name_and_version_dict=')
            # json格式加载失败，https://www.json.cn/提示RangeError: Invalid array length
            # cnvd_soft_replace = re.sub('\'', '\"', cnvd_soft_raw)
            # cnvd_soft_dict = json.loads(cnvd_soft_replace)
            cnvd_soft_dict = ast.literal_eval(cnvd_soft_raw)

            for cveid in cnvd_soft_dict:
                print(cveid + '\n')
                cnvd_overall_soft = cnvd_soft_dict[cveid]

                # 严格匹配
                cnvd_overall_strict_match = cnvd_overall_soft['overall_strict_match']
                if cnvd_overall_strict_match is False:
                    if cveid in cnnvd_soft_dict:
                        cnnvd_overall_soft = cnnvd_soft_dict[cveid]
                        cnnvd_overall_strict_match = cnnvd_overall_soft['overall_strict_match']
                        if cnnvd_overall_strict_match is True:
                            if cveid not in cnvd_strict_match_dict:
                                cnvd_strict_match_dict[cveid] = {}
                                cnvd_strict_match_dict[cveid]['CNNVD'] = cnnvd_soft_dict[cveid]
                                cnvd_strict_match_dict[cveid]['CNVD'] = cnvd_soft_dict[cveid]

                # 松散匹配
                cnvd_overall_loose_match = cnvd_overall_soft['overall_loose_match']
                if cnvd_overall_loose_match[0] is False:
                    if cveid in cnnvd_soft_dict:
                        cnnvd_overall_soft = cnnvd_soft_dict[cveid]
                        cnnvd_overall_strict_match = cnnvd_overall_soft['overall_loose_match'][0]
                        if cnnvd_overall_strict_match is True:
                            if cveid not in cnvd_loose_match_dict:
                                cnvd_loose_match_dict[cveid] = {}
                                cnvd_loose_match_dict[cveid]['CNNVD'] = cnnvd_soft_dict[cveid]
                                cnvd_loose_match_dict[cveid]['CNVD'] = cnvd_soft_dict[cveid]

    # 保存在本地，strict_match
    cnvd_and_nvd_soft_path = os.getcwd() + '/data/reason_of_inconsistency/'  # 文件夹
    strict_match_cnvd_and_nvd_soft_filename = '1_strict_match_diff_of_cnnvd_and_cnvd.txt'
    strict_match_print_name_and_version_filename = '1_strict_match_diff_of_cnnvd_and_cnvd_print.txt'
    strict_match_cnvd_and_nvd_soft_file_path = os.path.join('%s%s' % (cnvd_and_nvd_soft_path, strict_match_cnvd_and_nvd_soft_filename))
    strict_match_print_name_and_version_file_path = os.path.join(
        '%s%s' % (cnvd_and_nvd_soft_path, strict_match_print_name_and_version_filename))
    # 字典原始格式保存在本地
    with open(strict_match_cnvd_and_nvd_soft_file_path, 'w', encoding='utf-8') as name_and_version_f:  # 用w而非a，用于覆盖
        name_and_version_f.write('name_and_version_dict=' + str(cnvd_strict_match_dict))  # 写入数据
    # 为了方便观察，以较好的格式另外保存到一个文件中
    for j in cnvd_strict_match_dict:
        with open(strict_match_print_name_and_version_file_path, 'a', encoding='utf-8') as print_name_and_version_f:  # 用a，用于追加
            print_name_and_version_f.write(j + ' ' + str(cnvd_strict_match_dict[j]) + '\n')  # 写入数据


    # 保存在本地,loose_match
    cnvd_and_nvd_soft_path = os.getcwd() + '/data/reason_of_inconsistency/'  # 文件夹
    loose_match_cnvd_and_nvd_soft_filename = '1_loose_match_diff_of_cnnvd_and_cnvd.txt'
    loose_match_print_name_and_version_filename = '1_loose_match_diff_of_cnnvd_and_cnvd_print.txt'
    loose_match_cnvd_and_nvd_soft_file_path = os.path.join('%s%s' % (cnvd_and_nvd_soft_path, loose_match_cnvd_and_nvd_soft_filename))
    loose_match_print_name_and_version_file_path = os.path.join(
        '%s%s' % (cnvd_and_nvd_soft_path, loose_match_print_name_and_version_filename))
    # 字典原始格式保存在本地
    with open(loose_match_cnvd_and_nvd_soft_file_path, 'w', encoding='utf-8') as name_and_version_f:  # 用w而非a，用于覆盖
        name_and_version_f.write('name_and_version_dict=' + str(cnvd_loose_match_dict))  # 写入数据
    # 为了方便观察，以较好的格式另外保存到一个文件中
    for j in cnvd_loose_match_dict:
        with open(loose_match_print_name_and_version_file_path, 'a', encoding='utf-8') as print_name_and_version_f:  # 用a，用于追加
            print_name_and_version_f.write(j + ' ' + str(cnvd_loose_match_dict[j]) + '\n')  # 写入数据
    print('strict_match对应的字典长度为：' + str(len(cnvd_strict_match_dict)) + '\n')
    print('loose_match对应的字典长度为：' + str(len(cnvd_loose_match_dict)))
    # strict_match对应的字典长度为：3226
    # loose_match对应的字典长度为：7584



# 分析不一致的具体原因
# 查看cnnvd与nvd匹配错误同时cnvd与nvd也匹配错误的数据，在服务器运行该代码
def get_match_false_of_cnnvd():
    # 获取softname和version内容
    soft_dic_path = os.getcwd() + '/data/reason_of_inconsistency/'  # 存放的文件夹
    cnvd_soft_dic_filename = '0_cnvd_measure_inconsistency.txt'
    cnnvd_soft_dic_filename = '0_cnnvd_measure_inconsistency.txt'
    cnvd_soft_dic_name = os.path.join('%s%s' % (soft_dic_path, cnvd_soft_dic_filename))
    cnnvd_soft_dic_name = os.path.join('%s%s' % (soft_dic_path, cnnvd_soft_dic_filename))
    cnvd_strict_match_dict = dict()
    cnvd_loose_match_dict = dict()
    cnnvd_soft_dict = dict()
    new_soft_dict = dict()

    # cnnvd
    with open(cnnvd_soft_dic_name, 'r', encoding='UTF-8') as cnnvd_soft_f:  # 打开文件
        cnnvd_soft_lines = cnnvd_soft_f.readlines()  # 获取文件的所有行
        for cnnvd_soft_line in cnnvd_soft_lines:
            cnnvd_soft_raw = cnnvd_soft_line
            cnnvd_soft_raw = cnnvd_soft_raw.lstrip('name_and_version_dict=')
            # json格式加载失败，https://www.json.cn/提示RangeError: Invalid array length
            # cnnvd_soft_replace = re.sub('\'', '\"', cnnvd_soft_raw)
            # cnnvd_soft_dict = json.loads(cnnvd_soft_replace)
            cnnvd_soft_dict = ast.literal_eval(cnnvd_soft_raw)

    # cnvd
    with open(cnvd_soft_dic_name, 'r', encoding='UTF-8') as cnvd_soft_f:  # 打开文件
        cnvd_soft_lines = cnvd_soft_f.readlines()  # 获取文件的所有行
        for cnvd_soft_line in cnvd_soft_lines:
            cnvd_soft_raw = cnvd_soft_line
            cnvd_soft_raw = cnvd_soft_raw.lstrip('name_and_version_dict=')
            # json格式加载失败，https://www.json.cn/提示RangeError: Invalid array length
            # cnvd_soft_replace = re.sub('\'', '\"', cnvd_soft_raw)
            # cnvd_soft_dict = json.loads(cnvd_soft_replace)
            cnvd_soft_dict = ast.literal_eval(cnvd_soft_raw)

            for cveid in cnvd_soft_dict:
                print(cveid + '\n')
                cnvd_overall_soft = cnvd_soft_dict[cveid]

                # 严格匹配
                cnvd_overall_strict_match = cnvd_overall_soft['overall_strict_match']
                if cnvd_overall_strict_match is False:
                    if cveid in cnnvd_soft_dict:
                        cnnvd_overall_soft = cnnvd_soft_dict[cveid]
                        cnnvd_overall_strict_match = cnnvd_overall_soft['overall_strict_match']
                        if cnnvd_overall_strict_match is False:
                            if cveid not in cnvd_strict_match_dict:
                                cnvd_strict_match_dict[cveid] = {}
                                cnvd_strict_match_dict[cveid]['CNNVD'] = cnnvd_soft_dict[cveid]
                                cnvd_strict_match_dict[cveid]['CNVD'] = cnvd_soft_dict[cveid]

                # 松散匹配
                cnvd_overall_loose_match = cnvd_overall_soft['overall_loose_match']
                if cnvd_overall_loose_match[0] is False:
                    if cveid in cnnvd_soft_dict:
                        cnnvd_overall_soft = cnnvd_soft_dict[cveid]
                        cnnvd_overall_strict_match = cnnvd_overall_soft['overall_loose_match'][0]
                        if cnnvd_overall_strict_match is False:
                            if cveid not in cnvd_loose_match_dict:
                                cnvd_loose_match_dict[cveid] = {}
                                cnvd_loose_match_dict[cveid]['CNNVD'] = cnnvd_soft_dict[cveid]
                                cnvd_loose_match_dict[cveid]['CNVD'] = cnvd_soft_dict[cveid]

    # 保存在本地，strict_match
    cnvd_and_nvd_soft_path = os.getcwd() + '/data/reason_of_inconsistency/'  # 文件夹
    strict_match_cnvd_and_nvd_soft_filename = '2_strict_match_false_of_cnnvd_and_cnvd.txt'
    strict_match_print_name_and_version_filename = '2_strict_match_false_of_cnnvd_and_cnvd_print.txt'
    strict_match_cnvd_and_nvd_soft_file_path = os.path.join('%s%s' % (cnvd_and_nvd_soft_path, strict_match_cnvd_and_nvd_soft_filename))
    strict_match_print_name_and_version_file_path = os.path.join(
        '%s%s' % (cnvd_and_nvd_soft_path, strict_match_print_name_and_version_filename))
    # 字典原始格式保存在本地
    with open(strict_match_cnvd_and_nvd_soft_file_path, 'w', encoding='utf-8') as name_and_version_f:  # 用w而非a，用于覆盖
        name_and_version_f.write('name_and_version_dict=' + str(cnvd_strict_match_dict))  # 写入数据
    # 为了方便观察，以较好的格式另外保存到一个文件中
    for j in cnvd_strict_match_dict:
        with open(strict_match_print_name_and_version_file_path, 'a', encoding='utf-8') as print_name_and_version_f:  # 用a，用于追加
            print_name_and_version_f.write(j + ' ' + str(cnvd_strict_match_dict[j]) + '\n')  # 写入数据


    # 保存在本地,loose_match
    cnvd_and_nvd_soft_path = os.getcwd() + '/data/reason_of_inconsistency/'  # 文件夹
    loose_match_cnvd_and_nvd_soft_filename = '2_loose_match_false_of_cnnvd_and_cnvd.txt'
    loose_match_print_name_and_version_filename = '2_loose_match_false_of_cnnvd_and_cnvd_print.txt'
    loose_match_cnvd_and_nvd_soft_file_path = os.path.join('%s%s' % (cnvd_and_nvd_soft_path, loose_match_cnvd_and_nvd_soft_filename))
    loose_match_print_name_and_version_file_path = os.path.join(
        '%s%s' % (cnvd_and_nvd_soft_path, loose_match_print_name_and_version_filename))
    # 字典原始格式保存在本地
    with open(loose_match_cnvd_and_nvd_soft_file_path, 'w', encoding='utf-8') as name_and_version_f:  # 用w而非a，用于覆盖
        name_and_version_f.write('name_and_version_dict=' + str(cnvd_loose_match_dict))  # 写入数据
    # 为了方便观察，以较好的格式另外保存到一个文件中
    for j in cnvd_loose_match_dict:
        with open(loose_match_print_name_and_version_file_path, 'a', encoding='utf-8') as print_name_and_version_f:  # 用a，用于追加
            print_name_and_version_f.write(j + ' ' + str(cnvd_loose_match_dict[j]) + '\n')  # 写入数据
    print('strict_match对应的字典长度为：' + str(len(cnvd_strict_match_dict)) + '\n')
    print('loose_match对应的字典长度为：' + str(len(cnvd_loose_match_dict)))
    # strict_match对应的字典长度为：13193
    # loose_match对应的字典长度为：3954



# ppt中举例
# 对于cnvd，查看某CVEID的软件有多个，其中有得严格匹配，有的而不严格匹配，在服务器运行该代码
def get_multiple_match_of_cnvd():
    # 获取softname和version内容
    soft_dic_path = os.getcwd() + '/data/reason_of_inconsistency/'  # 存放的文件夹
    cnvd_soft_dic_filename = '0_cnvd_measure_inconsistency.txt'
    cnvd_soft_dic_name = os.path.join('%s%s' % (soft_dic_path, cnvd_soft_dic_filename))
    cnvd_strict_match_dict = dict()
    cnvd_loose_match_dict = dict()
    new_soft_dict = dict()

    # cnvd
    with open(cnvd_soft_dic_name, 'r', encoding='UTF-8') as cnvd_soft_f:  # 打开文件
        cnvd_soft_lines = cnvd_soft_f.readlines()  # 获取文件的所有行
        for cnvd_soft_line in cnvd_soft_lines:
            cnvd_soft_raw = cnvd_soft_line
            cnvd_soft_raw = cnvd_soft_raw.lstrip('name_and_version_dict=')
            # json格式加载失败，https://www.json.cn/提示RangeError: Invalid array length
            # cnvd_soft_replace = re.sub('\'', '\"', cnvd_soft_raw)
            # cnvd_soft_dict = json.loads(cnvd_soft_replace)
            cnvd_soft_dict = ast.literal_eval(cnvd_soft_raw)

            for cveid in cnvd_soft_dict:
                print(cveid + '\n')
                cnvd_overall_soft = cnvd_soft_dict[cveid]

                # 严格匹配
                cnvd_overall_strict_match_dict = cnvd_overall_soft['cnvd']['detail_strict_match']
                cnvd_overall_strict_match_list = list(cnvd_overall_strict_match_dict.keys())
                if cnvd_overall_strict_match_list:
                    if len(cnvd_overall_strict_match_list) >= 2:
                        tmp_i = 0
                        strict_match_true=''
                        strict_match_false = ''
                        while tmp_i < len(cnvd_overall_strict_match_list):
                            key = cnvd_overall_strict_match_list[tmp_i]
                            value = cnvd_overall_strict_match_dict[key]
                            if value is True:
                                strict_match_true = True
                            elif value is False:
                                strict_match_false = False
                            tmp_i = tmp_i + 1

                # 保存在本地，strict_match
                cnvd_and_nvd_soft_path = os.getcwd() + '/data/reason_of_inconsistency/'  # 文件夹
                strict_match_cnvd_and_nvd_soft_filename = '3_get_multiple_match_of_cnvd.txt'
                strict_match_cnvd_and_nvd_soft_file_path = os.path.join('%s%s' % (cnvd_and_nvd_soft_path, strict_match_cnvd_and_nvd_soft_filename))
                # cveid保存在本地
                with open(strict_match_cnvd_and_nvd_soft_file_path, 'a', encoding='utf-8') as name_and_version_f:  # 用a而非w，用于追加
                    if strict_match_true is True and strict_match_false is False:
                        name_and_version_f.write(str(cveid)+'\n')  # 写入数据


