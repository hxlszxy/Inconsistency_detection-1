#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
功能：获取CVE数据
"""



import os
import pymysql
import ast
import re


# 判断是否为汉字
def is_chinese(uchar):
    # 判断一个unicode是否是汉字
    if (uchar >= u'\u4e00') and (uchar <= u'\u9fa5'):
        return True
    else:
        return False


# 获取cve的CVE和affect_software属性的值
def get_origin_cve():
    try:
        cve_dict = dict()  # 初始化
        # 连接数据库
        # host不写ip地址，否则会报错
        conn = pymysql.connect(host='localhost', port=3306, user='root', passwd='oglhao123', db='sfo')  # db：库名，修改为真实密码
        # 设置游标类型，默认游标类型为元祖形式，将游标类型设置为字典形式
        cur = conn.cursor(cursor=pymysql.cursors.DictCursor)
        cur.execute("select CVE,affect_software from sfo_v1 where affect_software!='(暂无)' and affect_software not like '% 无;%' and \
        affect_software is not null and cve is not null and cve like 'CVE%'")
        cve_data = cur.fetchall()
        # cve_data = cur.fetchmany(3) 测试3条数据
        for i in cve_data:
            cve_dict[i['CVE']] = i['affect_software']
            # print(i)

        # 提交
        conn.commit()
        # 关闭指针对象
        cur.close()
        # 关闭连接对象
        conn.close()

        # 保存在本地
        cve_data_path = os.getcwd() + '/data/cve/'  # 存放cvnvd的文件夹
        cve_data_filename = 'cve_origin.txt'
        print_name_and_version_filename = 'cve_origin_print.txt'
        cve_data_file_path = os.path.join('%s\%s' % (cve_data_path, cve_data_filename))
        print_name_and_version_file_path = os.path.join('%s\%s' % (cve_data_path, print_name_and_version_filename))
        with open(cve_data_file_path, 'w', encoding='utf-8') as cvnvd_data_f:  # 用w而非a，用于覆盖
            cvnvd_data_f.write('cve_dict=' + str(cve_dict))  # 写入数据
        # 为了方便观察，以较好的格式另外保存到一个文件中
        for j in cve_dict:
            with open(print_name_and_version_file_path, 'a', encoding='utf-8') as print_name_and_version_f:  # 用a，用于追加
                print_name_and_version_f.write(j + ' ' + str(cve_dict[j]) + '\n')  # 写入数据
    except Exception as e:
        print(e)


# 代码来源于CNNVD的函数split_cve_by_colon
# 按照逗号分隔affect_software属性的值，观察数据以便编写函数get_softname_and_version_of_cve()
def split_cve_by_comma():
    cve_data_path = os.getcwd() + '/data/cve/'  # 存放cvnvd的文件夹
    comma_cve_path = os.getcwd() + '/data/cve/split_cve_by_comma'  # 存放split_cve_by_comma的文件夹
    cve_data_filename = 'cve_' + 'origin.txt'
    zero_comma_filename = 'cve_' + 'zero_comma.txt'
    zero_comma_file_path = os.path.join('%s\%s' % (comma_cve_path, zero_comma_filename))
    one_comma_filename = 'cve_' + 'one_comma.txt'
    one_comma_file_path = os.path.join('%s\%s' % (comma_cve_path, one_comma_filename))
    two_comma_filename = 'cve_' + 'two_comma.txt'
    two_comma_file_path = os.path.join('%s\%s' % (comma_cve_path, two_comma_filename))
    three_comma_filename = 'cve_' + 'three_comma.txt'
    three_comma_file_path = os.path.join('%s\%s' % (comma_cve_path, three_comma_filename))
    four_comma_filename = 'cve_' + 'four_comma.txt'
    four_comma_file_path = os.path.join('%s\%s' % (comma_cve_path, four_comma_filename))
    five_comma_filename = 'cve_' + 'five_comma.txt'
    five_comma_file_path = os.path.join('%s\%s' % (comma_cve_path, five_comma_filename))

    cve_data_file_path = os.path.join('%s\%s' % (cve_data_path, cve_data_filename))
    with open(cve_data_file_path, 'r', encoding='UTF-8') as cve_f:  # 打开文件
        cve_lines = cve_f.readlines()  # 获取文件的所有行
        for cve_line in cve_lines:
            cve_data_raw = cve_line
            cve_data_raw = cve_data_raw.lstrip('cve_dict=')
            cve_data_dict = ast.literal_eval(cve_data_raw)  # 转化为字典，只有一行数据，可以不加break
            for i in cve_data_dict:
                cnt = 0
                for j in cve_data_dict[i]:  # 修改了该部分代码
                    if j == '，':  # 中文的分号
                        cnt = cnt + 1
                if cnt == 0:
                    print(i + ' ' + cve_data_dict[i] + '\n')
                    with open(zero_comma_file_path, 'a', encoding='utf-8') as zero_comma_write:  # 用a而非w，用于追加
                        zero_comma_write.write(i + ' ' + cve_data_dict[i] + '\n')
                if cnt == 1:
                    print(i + ' ' + cve_data_dict[i] + '\n')
                    with open(one_comma_file_path, 'a', encoding='utf-8') as one_comma_write:  # 用a而非w，用于追加
                        one_comma_write.write(i + ' ' + cve_data_dict[i] + '\n')
                if cnt == 2:
                    print(i + ' ' + cve_data_dict[i] + '\n')
                    with open(two_comma_file_path, 'a', encoding='utf-8') as two_comma_write:  # 用a而非w，用于追加
                        two_comma_write.write(i + ' ' + cve_data_dict[i] + '\n')
                if cnt == 3:
                    print(i + ' ' + cve_data_dict[i] + '\n')
                    with open(three_comma_file_path, 'a', encoding='utf-8') as three_comma_write:  # 用a而非w，用于追加
                        three_comma_write.write(i + ' ' + cve_data_dict[i] + '\n')
                if cnt == 4:
                    print(i + ' ' + cve_data_dict[i] + '\n')
                    with open(four_comma_file_path, 'a', encoding='utf-8') as four_comma_write:  # 用a而非w，用于追加
                        four_comma_write.write(i + ' ' + cve_data_dict[i] + '\n')
                if cnt == 5:
                    print(i + ' ' + cve_data_dict[i] + '\n')
                    with open(five_comma_file_path, 'a', encoding='utf-8') as five_comma_write:  # 用a而非w，用于追加
                        five_comma_write.write(i + ' ' + cve_data_dict[i] + '\n')


# 代码来源于CNNVD的函数split_cve_by_colon
# 非字母而且非汉字的字符分隔affect_software属性的值，观察数据以便编写函数get_softname_and_version_of_cve()
def split_cve_by_nonalpha():
    cve_data_path = os.getcwd() + '/data/cve/'  # 存放cvnvd的文件夹
    nonalpha_cve_path = os.getcwd() + '/data/cve/split_cve_by_nonalpha'  # 存放nonalpha的文件夹
    cve_data_filename = 'cve_' + 'origin.txt'
    nonalpha_comma_filename = 'cve_' + 'nonalpha.txt'
    nonalpha_comma_file_path = os.path.join('%s\%s' % (nonalpha_cve_path, nonalpha_comma_filename))

    cve_data_file_path = os.path.join('%s\%s' % (cve_data_path, cve_data_filename))
    with open(cve_data_file_path, 'r', encoding='UTF-8') as cve_f:  # 打开文件
        cve_lines = cve_f.readlines()  # 获取文件的所有行
        for cve_line in cve_lines:
            cve_data_raw = cve_line
            cve_data_raw = cve_data_raw.lstrip('cve_dict=')
            cve_data_dict = ast.literal_eval(cve_data_raw)  # 转化为字典，只有一行数据，可以不加break
            for i in cve_data_dict:
                soft_parts = cve_data_dict[i].replace(r'\t', '').replace(r'\n', '')
                soft_parts = soft_parts.split(';')
                for j in soft_parts:
                    j = j.strip()
                    if j == '':
                        continue
                    parts = re.split(" |，", j)  # 若上一个函数的猜测正确
                    flag_version_start = False  # 第一个包含非字母而且非汉字的字符及之后的字符均为版本
                    name = ''
                    version = ''
                    version_start_list = ['<', '>', '=', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9']
                    for part in parts:
                        part = part.strip().replace('_', ' ').replace('~', ' ').strip()
                        if part == '':
                            continue
                        if flag_version_start:
                            version = version + ' ' + part
                        else:
                            if part[0] in version_start_list:
                                version = part
                                flag_version_start = True
                            else:
                                if name == '':
                                    name = part
                                else:
                                    name = name + ' ' + part
                            continue

                            # 开始找第一个包含非字母而且非汉字的字符
                            part_len = len(part)
                            tmp_i = 0
                            flag_name_changed = False  # 是否在下面的while循环中修改了名字，默认没有
                            while tmp_i < part_len:
                                if (not part[tmp_i].isalpha()) and (not is_chinese(part[tmp_i])):  # 非字母且非汉字
                                    version = part[tmp_i:]  # 保存版本
                                    if tmp_i != 0:  # 保存名字
                                        if name == '':
                                            name = part[0:tmp_i]
                                        else:
                                            name = name + ' ' + part[0:tmp_i]
                                        flag_name_changed = True
                                    flag_version_start = True
                                    break
                                tmp_i = tmp_i + 1
                            if not flag_name_changed:  # 没有在上面的while循环中修改名字
                                if name == '':
                                    name = part
                                else:
                                    name = name + ' ' + part
                    # 比cnnvd的该部分代码增加了缩进
                    print(i + '\n' + name + '    ' + version + '\n')
                    with open(nonalpha_comma_file_path, 'a', encoding='utf-8') as nonalpha_comma_write:  # 用a而非w，用于追加
                        nonalpha_comma_write.write(i + '\n' + name + '        ' + version + '\n')  # 8个空格分隔软件名和版本


# 分隔出软件名和版本
def get_softname_and_version_of_openwall():
    openwall_data_path = os.getcwd() + '/data/openwall/'  # 存放openwall的文件夹
    openwall_data_filename = 'simple_data_of_openwall.txt'
    openwall_data_file_path = os.path.join('%s\%s' % (openwall_data_path, openwall_data_filename))
    name_and_version_dict = dict()  # 初始化
    with open(openwall_data_file_path, 'r', encoding='UTF-8') as openwall_f:  # 打开文件
        openwall_lines = openwall_f.readlines()  # 获取文件的所有行
        for openwall_line in openwall_lines:
            raw_data = openwall_line.split()  # 按空格作为分隔符号切割字符串
            cveid = raw_data[2]  # 获取cveid，cveid作为字典的键
            print(cveid, '\n')
            name = raw_data[0].replace('_', ' ')  # 对于师姐标记的re_data里的软件名称/版本，如果某个软件名称/版本是多个word组成的，就用_连接
            name = name.replace('**', ' ')
            version = raw_data[1].replace('_', ' ')
            version = version.replace('**', ' ')
            if (cveid.split() != '') and (cveid not in name_and_version_dict):
                name_and_version_dict[cveid] = {}
            if (name.split() != '') and (name not in name_and_version_dict[cveid]):
                name_and_version_dict[cveid][name] = []
            if version:  # version不为空
                if version not in name_and_version_dict[cveid][name]:
                    name_and_version_dict[cveid][name].append(version)
    # 保存在本地
    name_and_version_filename = 'openwall_' + 'softname_and_version.txt'
    print_name_and_version_filename = 'openwall_' + 'softname_and_version_print.txt'
    name_and_version_file_path = os.path.join('%s\%s' % (openwall_data_path, name_and_version_filename))
    print_name_and_version_file_path = os.path.join('%s\%s' % (openwall_data_path, print_name_and_version_filename))
    with open(name_and_version_file_path, 'w', encoding='utf-8') as name_and_version_f:  # 用w而非a，用于覆盖
        name_and_version_f.write('name_and_version_dict=' + str(name_and_version_dict))  # 写入数据
    # 为了方便观察，以较好的格式另外保存到一个文件中
    for j in name_and_version_dict:
        with open(print_name_and_version_file_path, 'a', encoding='utf-8') as print_name_and_version_f:  # 用a，用于追加
            print_name_and_version_f.write(j + ' ' + str(name_and_version_dict[j]) + '\n')  # 写入数据

