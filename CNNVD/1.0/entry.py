#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
功能：程序入口
依次执行main函数里的各函数即可
"""

from nvd_parser import download_nvd_data
 #from cpe_dic_parser import parse_cpe_xml
from compare import get_data_from_dict
from cnnvd_parser import get_origin_cnnvd
from cnnvd_parser import split_cnnvd_by_colon
from cnnvd_parser import get_softname_and_version_of_cnnvd
from nvd_parser import get_softname_and_version_of_nvd
from compare import get_cnnvd_and_nvd_soft_origin
from compare import clean_cnnvd_and_nvd_softname_version
from compare import keep_same_version_of_cnnvd_and_nvd
from compare import cpe_map_version_of_cnnvd_and_nvd
from compare import get_str_version_of_cnnvd_and_nvd
from compare import remove_bad_version_first
from compare import remove_bad_version_second
from compare import measure_inconsistency
from compare import get_result_overall
from compare import get_result_by_year
from compare import get_result_by_vulnerability_kind
from detect_diff import keep_not_same_version_of_cnnvd_and_nvd

if __name__ == "__main__":
    # download_nvd_data([])
    # parse_cpe_xml()
    # get_origin_cnnvd()

    # split_cnnvd_by_colon()
    # get_softname_and_version_of_cnnvd()
    # get_softname_and_version_of_nvd()
    # #get_data_from_dict()  # 查看字典的结构
    # get_cnnvd_and_nvd_soft_origin()
    # clean_cnnvd_and_nvd_softname_version()
    # keep_same_version_of_cnnvd_and_nvd()

    # cpe_map_version_of_cnnvd_and_nvd()  # 运行时间较长
    # get_str_version_of_cnnvd_and_nvd()
    # remove_bad_version_first()
    # remove_bad_version_second()

    # 函数measure_inconsistency()运行完成输出的CVEID的数量就是实际执行差异性测量的CVEID数量
    # measure_inconsistency()

    # 下面的代码必须在服务器，除非win内存够大
    # get_result_overall()
    # get_result_by_year()
    # get_result_by_vulnerability_kind()

    keep_not_same_version_of_cnnvd_and_nvd()

