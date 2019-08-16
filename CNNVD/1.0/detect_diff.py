#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
功能：具体参考《软件名称差异性_v4_2019.8.13.docx》
“二”里面说到的2种情况I、II都是局限于：两个漏洞报告含有同一个软件的，只是对这个软件的叫法不一样的情况。
但是还有一种情况：有很多漏洞报告，描述的软件集合不一样，A报告描述了IE，但是B中压根没有描述IE
（既没有IE也没有Internet Explorer也没有 Microsoft Internet Explorer），这种情况较为常见。
"""

import os
import ast
import re
import json
import re
import copy


# 保留不相同软件名称的数据项
def keep_not_same_version_of_cnnvd_and_nvd():
    # 获取softname和version内容
    soft_dic_path = os.getcwd() + '/data/softname_version_compare/'  # 存放的文件夹
    soft_dic_filename = '2_clean_softname_version.txt'
    soft_dic_name = os.path.join('%s%s' % (soft_dic_path, soft_dic_filename))
    soft_dict = dict()
    not_same_version_set = set()  # 如果对于某CVEID，CNNVD和NVD如果软件名称不同的话，存储这个CVEID
    len_full_cveid = 0  # 所有cveid的数量
    with open(soft_dic_name, 'r', encoding='UTF-8') as soft_f:  # 打开文件
        soft_lines = soft_f.readlines()  # 获取文件的所有行
        for soft_line in soft_lines:
            soft_raw = soft_line
            soft_raw = soft_raw.lstrip('name_and_version_dict=')
            soft_dict = ast.literal_eval(soft_raw)  # 转化为字典，只有一行数据，可以不加break

            cveid_cnt = 0
            for cveid in soft_dict:
                cveid_cnt = cveid_cnt + 1
                print('CVEID：' + str(cveid) + '    CVEID的数量：' + str(cveid_cnt) + '\n')
                cnnvd_soft = soft_dict[cveid]['cnnvd']
                nvd_soft = soft_dict[cveid]['nvd']
                # 只保留不相同的软件名的数据项
                tmp_i = 0

                if isinstance(cnnvd_soft, dict):  # 只对字典处理，不对空的字符串处理
                    cnnvd_list = list(cnnvd_soft.keys())
                    while tmp_i < len(cnnvd_list):
                        if cnnvd_list[tmp_i] not in nvd_soft:
                            not_same_version_set.add(cveid)  # 该行原代码 del cnnvd_soft[cnnvd_list[tmp_i]]
                        tmp_i = tmp_i + 1

                tmp_j = 0

                if isinstance(nvd_soft, dict):  # 只对字典处理，不对空的字符串处理
                    nvd_list = list(nvd_soft.keys())
                    while tmp_j < len(nvd_list):
                        if nvd_list[tmp_j] not in cnnvd_soft:
                            not_same_version_set.add(cveid)  # 该行原代码 del nvd_soft[nvd_list[tmp_j]]
                        tmp_j = tmp_j + 1
            len_full_cveid = cveid_cnt  # 所有cveid的数量
    # 保留软件名称不相同的数据项
    tmp_k = 0
    soft_list = list(soft_dict.keys())
    while tmp_k < len(soft_list):
        if soft_list[tmp_k] not in not_same_version_set:
            del soft_dict[soft_list[tmp_k]]  # 把相同的数据项删除掉，只保留不相同的数据
        tmp_k = tmp_k + 1

    # 软件名称不相同的比例
    len_not_same_version_set = len(not_same_version_set)
    proportion = len_not_same_version_set/len_full_cveid
    print('总的CVEID数量：' + str(len_full_cveid) + '\n')
    print('软件名称不相同的CVEID占总的CVEID比例：' + str(proportion) + '\n')

    '''
    # 去除没有数据项的CVEID对应的数据
    tmp_k = 0
    soft_list = list(soft_dict.keys())
    while tmp_k < len(soft_list):
        cnnvd_soft = soft_dict[soft_list[tmp_k]]['cnnvd']
        nvd_soft = soft_dict[soft_list[tmp_k]]['nvd']
        if (not cnnvd_soft) or (nvd_soft == ''):  # 为空则去掉
            del soft_dict[soft_list[tmp_k]]
        tmp_k = tmp_k + 1
    '''

    # 保存在本地
    cnnvd_and_nvd_soft_path = os.getcwd() + '/data/softname_version_compare/'  # 文件夹
    cnnvd_and_nvd_soft_filename = '3_keep_not_same_version_of_cnnvd_and_nvd.txt'  # 这样命名方便查看
    print_name_and_version_filename = '3_keep_not_same_version_of_cnnvd_and_nvd_print.txt'
    cnnvd_and_nvd_soft_file_path = os.path.join('%s%s' % (cnnvd_and_nvd_soft_path, cnnvd_and_nvd_soft_filename))
    print_name_and_version_file_path = os.path.join('%s%s' % (cnnvd_and_nvd_soft_path, print_name_and_version_filename))
    # 字典原始格式保存在本地
    with open(cnnvd_and_nvd_soft_file_path, 'w', encoding='utf-8') as name_and_version_f:  # 用w而非a，用于覆盖
        name_and_version_f.write(str(soft_dict))  # 写入数据
    # 为了方便观察，以较好的格式另外保存到一个文件中
    for j in soft_dict:
        with open(print_name_and_version_file_path, 'a', encoding='utf-8') as print_name_and_version_f:  # 用a，用于追加
            print_name_and_version_f.write(j + ' ' + str(soft_dict[j]) + '\n')  # 写入数据
    # 上面的txt生成之后，如果要重新运行代码生成txt，应该先把原来的txt删除掉
