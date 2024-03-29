#!/usr/bin/env python3
# coding: utf-8

import sys
import pandas as pd

"""
功能：进行一些数据处理
"""

# 代码来自师姐发过来的cve.py
'''This is a simple script to download an NVD CVE feed, extract interesting bits
from the XML and import/update a mongo db - or optionally print it to screen'''
#from __future__ import unicode_literals, print_function
import os
import inspect
import sys
import zipfile
import urllib.request
import argparse
from io import BytesIO
import xml.etree.ElementTree as ET
import pprint
import program_utils as commons  # 换个别名

NVD_FEEDS = {
    'recent': 'https://nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-Recent.xml.zip',
    'modified': 'https://nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-Modified.xml.zip',
    'year': 'https://nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-%s.xml.zip'
}

NAMESPACE = '{http://scap.nist.gov/schema/feed/vulnerability/2.0}'
VULN = '{http://scap.nist.gov/schema/vulnerability/0.4}'
CVSS = '{http://scap.nist.gov/schema/cvss-v2/0.2}'
CVSS = '{http://scap.nist.gov/schema/cvss-v3/0.3}'

all_cveid_set = set()


# 把xls转化为csv格式
def convert_xls_to_csv():
    try:
        data_xls = pd.read_excel("sfo.xls")
        data_xls.to_csv("test_csv.csv", encoding='utf-8', index=False)
    except Exception as e:
        print(e)


def replace_char(file_path):
    try:
        f = open(file_path, 'r+', encoding='utf-8')
        all_lines = f.readlines()
        f.seek(0)
        f.truncate()
        for line in all_lines:
            # 交换大于小于符号
            line = line.replace('<', '$$').replace('>', '<').replace('$$', '>')
            # 不能像下面这样分成三行写
            # line = line.replace('<', '$$')
            # line = line.replace('>', '<')
            # line = line.replace('$$', '>')
            f.write(line)
        print(file_path + ' 该文件的大于小于符号互换成功\n')
        f.close()
    except Exception as e:
        print('detail error:'+ e +'\n')




# 师兄爬取的版本的大于小于符号反了，把错误数据替换为正确数据（输入要为错误数据哈，输出才会正确）
def exchange_more_less_of_cnvd():
    soft_dic_path = os.getcwd() + '/data/cnvd/'  # 存放的文件夹
    cnvd_soft_dic_filename_1 = 'cnvd_origin.txt'
    cnvd_print_soft_dic_filename_1 = 'cnvd_origin_print.txt'
    cnvd_soft_dic_name_1 = os.path.join('%s%s' % (soft_dic_path, cnvd_soft_dic_filename_1))
    cnvd_print_soft_dic_name_1 = os.path.join('%s%s' % (soft_dic_path, cnvd_print_soft_dic_filename_1))
    replace_char(cnvd_soft_dic_name_1)
    replace_char(cnvd_print_soft_dic_name_1)

    cnvd_soft_dic_filename_2 = 'cnvd_softname_and_version.txt'
    cnvd_print_soft_dic_filename_2 = 'cnvd_softname_and_version_print.txt'
    cnvd_soft_dic_name_2 = os.path.join('%s%s' % (soft_dic_path, cnvd_soft_dic_filename_2))
    cnvd_print_soft_dic_name_2 = os.path.join('%s%s' % (soft_dic_path, cnvd_print_soft_dic_filename_2))
    replace_char(cnvd_soft_dic_name_2)
    replace_char(cnvd_print_soft_dic_name_2)

    # 暂时没有替换'/data/cnvd/split_cnvd_by_comma' 和'split_cnvd_by_nonalpha'
    # 执行该函数生成新的文件后，从函数get_cnvd_and_nvd_soft_origin()开始执行重新映射






def download_nvd_feed(req_feed):
    retval = None
    # download the feed
    feed = None
    if req_feed in NVD_FEEDS and req_feed != 'year':
        feed = NVD_FEEDS[req_feed]
    else:
        try:
            feed = NVD_FEEDS['year'] % int(req_feed)
        except ValueError:
            pass  # not a number
    if feed is not None:
        print('info: downloading %s' % feed)
        retval = BytesIO(urllib.request.urlopen(feed).read())
    return retval


def get_nvd_feed_xml(req_feed, callback):
    retval = {}
    try:
        feed = download_nvd_feed(req_feed)
        try:
            zip = zipfile.ZipFile(feed)
            names = zip.namelist()
            for name in names:
                try:
                    f = zip.open(name)
                    retval.update(callback(f))
                finally:
                    f.close()
        finally:
            zip.close()
    finally:
        if feed:
            feed.close()
    return retval


def process_nvd_20_xml(xml):
    print('processing', xml, '...' )
    retval = {}
    tree = ET.parse(xml)
    root = tree.getroot()
    for entry in root.findall(NAMESPACE + 'entry'):
        cveid = entry.attrib['id']
        if cveid not in retval:
            cve = {'_id': cveid}
            summary = entry.find(VULN + 'summary')
            if summary is not None and summary.text:
                cve['summary'] = summary.text

            cve['published'] = entry.find(VULN + 'published-datetime').text
            cve['modified'] = entry.find(VULN + 'last-modified-datetime').text

            vsw = entry.find(VULN + 'vulnerable-software-list')
            if vsw is not None:
                products = []
                for sw in vsw.iter(VULN + 'product'):
                    products.append(sw.text)
                cve['products'] = products

            try:
                cvss = entry.find(VULN + 'cvss')
                base_metrics = cvss.find(CVSS + 'base_metrics')
                cve['cvss_score'] = base_metrics.find(CVSS + 'score').text
            except AttributeError:
                pass

            references = []
            for refs in entry.iter(VULN + 'references'):
                ref = refs.find(VULN + 'reference')
                if ref is not None and 'href' in ref.attrib:
                    href = ref.attrib['href']
                    text = ref.text
                    if href is not None:
                        if text is None:
                            text = href
                        references.append({'href': href, 'description': text})
            if len(references):
                cve['references'] = references
            retval[cveid] = cve
    return retval


def get_cve_version_dict(cve_dict_file_name):
    with commons.add_path(commons.version_dict_file_path):
        import_module = __import__(cve_dict_file_name)
        cve_dict = import_module.version_dict
        return cve_dict


def replace_cve_with_nvd(cve_version_dict, nvd_version_dict):
    cve_set = set()
    for category in cve_version_dict:
        for cve_id in cve_version_dict[category]:
            if cve_id in nvd_version_dict:
                # print(cve_version_dict[category][cve_id].keys())
                if 'cve' in cve_version_dict[category][cve_id]:
                    for k in cve_version_dict[category][cve_id]['cve']:
                        cve_set.add(cve_id)
                        cve_version_dict[category][cve_id]['cve'][k]['content'] = nvd_version_dict[cve_id]
    print(len(cve_set))
    return cve_version_dict


def add_nvd_standard_to_version_dict(cve_version_dict, nvd_version_dict):
    cve_set = set()
    for category in cve_version_dict:
        for cve_id in cve_version_dict[category]:
            if cve_id in nvd_version_dict:
                if nvd_version_dict[cve_id] == dict():
                    continue
                # print(cve_version_dict[category][cve_id].keys())
                cve_version_dict[category][cve_id]['nvd'] = dict()
                cve_set.add(cve_id)
                nvd_link = 'https://nvd.nist.gov/vuln/detail/' + cve_id
                cve_version_dict[category][cve_id]['nvd'][nvd_link] = dict()
                cve_version_dict[category][cve_id]['nvd'][nvd_link]['content'] = nvd_version_dict[cve_id]
    print('nvd standard # cvd id', len(cve_set))
    return cve_version_dict, cve_set


def add_cvss_to_version_dict(cve_version_dict, cvss_dict):
    cve_set = set()
    for category in cve_version_dict:
        for cve_id in cve_version_dict[category]:
            if cve_id in cvss_dict:
                if cvss_dict[cve_id] == dict():
                    print('ERROR!', cve_id)
                    continue
                cve_version_dict[category][cve_id]['cvss'] = cvss_dict[cve_id]
                # print(cve_version_dict[category][cve_id].keys())
    #             cve_version_dict[category][cve_id]['nvd'] = dict()
    #             cve_set.add(cve_id)
    #             nvd_link = 'https://nvd.nist.gov/vuln/detail/' + cve_id
    #             cve_version_dict[category][cve_id]['nvd'][nvd_link] = dict()
    #             cve_version_dict[category][cve_id]['nvd'][nvd_link]['content'] = nvd_version_dict[cve_id]
    # print('nvd standard # cvd id', len(cve_set))
    return cve_version_dict, cve_set


def write_nvd_instead_cve(version_dict):
    with open(commons.version_dict_file_path + 'nvd_2016_new.py', 'w') as f_write:
        f_write.write('version_dict = ' + str(version_dict))


def write_merged_version_dict(version_dict):
    # with open(commons.nvd_standard_json_version_dict_file_path_and_name, 'w') as f_write:
    with open(commons.nvd_standard_with_cvss_version_dict_file_path_and_name, 'w') as f_write:
        f_write.write('version_dict = ' + str(version_dict))


def get_nvd_version_dict(version_dict, retval):
    for cve_id in retval:
        all_cveid_set.add(cve_id)
        # if cve_id == 'CVE-2010-1177':
        #     print('CVE-2010-1177', retval[cve_id])
        if 'products' in retval[cve_id]:
            cpe_list = retval[cve_id]['products']
            for cpe in cpe_list:
                software, version = get_software_name_and_version_from_cpe(cpe)
                if software != '' and version != '':
                    if cve_id not in version_dict:
                        version_dict[cve_id] = dict()
                    if software not in version_dict[cve_id]:
                        version_dict[cve_id][software] = []
                    version_dict[cve_id][software].append(version)
        # if cve_id == 'CVE-2010-1177':
        #     print('CVE-2010-1177', version_dict[cve_id])
        # print(len(all_cveid_set))
    with open(commons.full_reports_path + 'all_cveid_nvd.py', 'w') as f_write:
        f_write.write('all_cveid_set = ' + str(all_cveid_set))
    return version_dict


def get_cvss_dict(cvss_dict, retval):
    for cve_id in retval:
        all_cveid_set.add(cve_id)
        # if cve_id == 'CVE-2010-1177':
        #     print('CVE-2010-1177', retval[cve_id])
        if 'cvss_score' in retval[cve_id]:
            cvss_score = retval[cve_id]['cvss_score']

            if cve_id not in cvss_dict:
                cvss_dict[cve_id] = dict()

            cvss_dict[cve_id]['cvss_score'] = cvss_score
    #         for cpe in cpe_list:
    #             software, version = get_software_name_and_version_from_cpe(cpe)
    #             if software != '' and version != '':
    #                 if cve_id not in version_dict:
    #                     version_dict[cve_id] = dict()
    #                 if software not in version_dict[cve_id]:
    #                     version_dict[cve_id][software] = []
    #                 version_dict[cve_id][software].append(version)
    #     # if cve_id == 'CVE-2010-1177':
    #     #     print('CVE-2010-1177', version_dict[cve_id])
    #     # print(len(all_cveid_set))
    # with open(commons.full_reports_path + 'all_cveid_nvd.py', 'w') as f_write:
    #     f_write.write('all_cveid_set = ' + str(all_cveid_set))
    return cvss_dict


def get_software_name_and_version_from_cpe(cpe):
    # print(cpe)
    parts = cpe.split(':')[2:]
    # print(parts)
    software, version = '', ''
    num_found = False
    idx = 0
    for part in parts:
        if not commons.contain_letter(part) and not commons.contain_number(part):
            break
        part = part.replace('_', ' ').replace('~', ' ')
        if part[0].isdigit():
            version += part + ' '
            num_found = True
        elif num_found:
            version += part + ' '
        else:
            software += part + ' '
        idx += 1
    software = software.strip()
    version = version.strip()

    word = 'windows '
    if word in software:
        new_software = software[:software.find(word) + len(word)]
        version = software[software.find(word) + len(word):].strip() + ' ' + version
        software = new_software

    # print(software)
    # print(version)
    # print()
    return software, version


def get_all_years_version_dict(get_cvss_score=False):
    cve_version_dict = get_cve_version_dict('cve_dict')

    nvd_version_dict = dict()
    cvss_dict = dict()

    xml_file_prefix = commons.pc_root_path + 'nvd_dump/nvdcve-2.0-'
    xml_file_suffix = '.xml'
    for year_xml_name in list(range(2002, 2019)):
    # for year_xml_name in [2002]:
        retval = process_nvd_20_xml(xml_file_prefix + str(year_xml_name) + xml_file_suffix)
        nvd_version_dict = get_nvd_version_dict(nvd_version_dict, retval)
        print(len(nvd_version_dict))

        if get_cvss_score:
            cvss_dict = get_cvss_dict(cvss_dict, retval)

    # cve_version_dict len is 47501
    # nvd standard # cvd id 66237

    cve_cve_set = compute_cveid_cnt(cve_version_dict)
    cve_version_dict, nvd_cve_set = add_nvd_standard_to_version_dict(cve_version_dict, nvd_version_dict)

    if get_cvss_score:
        cve_version_dict, _ = add_cvss_to_version_dict(cve_version_dict, cvss_dict)
        # category_score_dict = count_category_cvss_score(cve_version_dict)

    write_merged_version_dict(cve_version_dict)

    no_version_in_nvd_cve_cnt = 0
    for cve in cve_cve_set:
        if cve not in nvd_cve_set:
            no_version_in_nvd_cve_cnt += 1
            print(cve)
    print('no_version_in_nvd_cve_cnt', no_version_in_nvd_cve_cnt)

    # nvd_instead_cve_dict = replace_cve_with_nvd(cve_version_dict, nvd_version_dict)
    # write_nvd_instead_cve(nvd_instead_cve_dict)


def compute_cveid_cnt(cve_version_dict):
    cveid_set = set()
    for category in cve_version_dict:
        for cveid in cve_version_dict[category]:
            if len(cve_version_dict[category][cveid]) > 1:
                cveid_set.add(cveid)
    print('cve_version_dict len is ', len(cveid_set))
    return cveid_set


"""
def count_cvss_avg():
    # from nvd_standard_cvss_json_version_dict import version_dict

    print(type(version_dict))
    print(version_dict.keys())
    category_cvss_dict = dict()

    for category in version_dict:
        cve_id_cnt = 0
        cvss_score_sum = 0

        for cve_id in version_dict[category]:
            if 'cvss' in version_dict[category][cve_id]:
                if 'cvss_score' in version_dict[category][cve_id]['cvss']:
                    cvss_score_sum += float(version_dict[category][cve_id]['cvss']['cvss_score'])
                    cve_id_cnt += 1
        avg_cvss = cvss_score_sum / (cve_id_cnt + 0.1)
        # print(category, avg_cvss, cve_id_cnt, cvss_score_sum)
        category_cvss_dict[category] = avg_cvss

    sorted_by_value = sorted(category_cvss_dict.items(), key=lambda kv: kv[1])
    print(sorted_by_value.reverse())
    print(sorted_by_value)
"""

"""
if __name__ == '__main__':
    get_all_years_version_dict(get_cvss_score=True)
    # get_software_name_and_version_from_cpe('cpe:/o:microsoft:windows_10:1703')
"""