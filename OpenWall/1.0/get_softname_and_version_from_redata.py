#!/usr/bin/env python3
# coding: utf-8
"""
功能：把师姐的re_data中的软件名称、版本提取出来，把各个漏洞库的软件名称进行差异性测量
"""

import os


# 对原始的re_data剔除不需要的数据
def get_simple_data_from_redata():
    origin_data_path = os.getcwd() + '/data/re_data/0_origin'  # 存放re的文件夹
    origin_data_files = os.listdir(origin_data_path)  # 获取origin_data_path里的各个文件名称

    for origin_data_file in origin_data_files:  # 遍历origin_data_path里的各个文件
        each_file = os.path.join(origin_data_path, origin_data_file)
        with open(each_file, 'r', encoding='UTF-8') as origin_data_f:  # 打开文件
            origin_data_lines = origin_data_f.readlines()  # 获取文件的所有行
            for origin_data_line in origin_data_lines:
                raw_data = origin_data_line.split()  # 按空格作为分隔符号切割字符串
                if raw_data[2] == 'Y':
                    softname_index = 3 + int(raw_data[0])
                    softname = raw_data[softname_index]  # 软件名称
                    version_index = 3 + int(raw_data[1])
                    version = raw_data[version_index]  # 软件版本
                    tmp_1 = raw_data[-1].split('_c_')  # 大部分是_c_来分隔的，有个别数据是_t_来分隔的
                    if len(tmp_1) == 1:
                        tmp_1 = raw_data[-1].split('_t_')
                    cveid = tmp_1[0]  # cveid
                    tmp_2 = tmp_1[1].split('|')
                    site = tmp_2[0]  # 漏洞库网站名称
                    url = tmp_2[1]  # 具体url
                    print(url, '\n')
                    simple_data = softname + ' ' + version + ' ' + cveid + ' ' + site + ' ' + url + '\n'

                    # 保存新数据在本地
                    simple_data_path = os.getcwd() + '/data/re_data/1_simple_data'  # 存放简化后的新数据的文件夹
                    new_filename = 'simple_data_of_' + origin_data_file.replace('_full_dup', '')
                    simple_data_file_path = os.path.join('%s\%s' % (simple_data_path, new_filename))
                    with open(simple_data_file_path, 'a', encoding='utf-8') as simple_data_f:  # 用a而非w，用于追加数据
                        simple_data_f.write(simple_data)
                    # 上面的txt生成之后，如果要重新运行代码生成新的txt，应该先把原来的txt删除掉


# 按照漏洞库把数据分隔开
def split_data_by_database():
    origin_data_path = os.getcwd() + '/data/re_data/1_simple_data'  # 存放re的文件夹
    origin_data_files = os.listdir(origin_data_path)  # 获取origin_data_path里的各个文件名称

    for origin_data_file in origin_data_files:  # 遍历origin_data_path里的各个文件
        each_file = os.path.join(origin_data_path, origin_data_file)
        with open(each_file, 'r', encoding='UTF-8') as origin_data_f:  # 打开文件
            origin_data_lines = origin_data_f.readlines()  # 获取文件的所有行
            for origin_data_line in origin_data_lines:
                raw_data = origin_data_line.split()  # 按空格作为分隔符号切割字符串
                database_name = raw_data[3]
                url = raw_data[-1]  # 具体url
                print(url, '\n')
                simple_data = origin_data_line

                # 保存新数据在本地
                simple_data_path = os.getcwd() + '/data/re_data/2_by_database'  # 存放简化后的新数据的文件夹
                new_filename = 'simple_data_of_' + database_name + '.txt'
                simple_data_file_path = os.path.join('%s\%s' % (simple_data_path, new_filename))
                with open(simple_data_file_path, 'a', encoding='utf-8') as simple_data_f:  # 用a而非w，用于追加数据
                    simple_data_f.write(simple_data)
                # 上面的txt生成之后，如果要重新运行代码生成新的txt，应该先把原来的txt删除掉


