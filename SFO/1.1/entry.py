#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
功能：程序入口
依次执行main函数里的各函数即可
"""

from nvd_parser import download_nvd_data
from cpe_dic_parser import parse_cpe_xml
from compare import get_data_from_dict
from cve_parser import get_origin_securityfocus
from cve_parser import get_softname_and_version_of_securityfocus
from nvd_parser import get_softname_and_version_of_nvd
from compare import get_securityfocus_and_nvd_soft_origin
from compare import clean_securityfocus_and_nvd_softname_version
from compare import keep_same_version_of_securityfocus_and_nvd
from compare import cpe_map_version_of_securityfocus_and_nvd
from compare import get_str_version_of_securityfocus_and_nvd
from compare import remove_bad_version_first
from compare import remove_bad_version_second
from compare import measure_inconsistency
from compare import get_result_overall
from compare import get_result_by_year
from compare import get_result_by_vulnerability_kind
import re
from cve_parser import split_securityfocus_by_comma
from cve_parser import split_securityfocus_by_nonalpha
from diff_of_cnnvd_and_securityfocus import get_diff_of_cnnvd_and_securityfocus
from diff_of_cnnvd_and_securityfocus import get_match_false_of_cnnvd
from get_data import exchange_more_less_of_securityfocus
from diff_of_cnnvd_and_securityfocus import get_multiple_match_of_securityfocus
from detect_diff import keep_not_same_version_of_securityfocus_and_nvd
from get_data import convert_xls_to_csv


if __name__ == "__main__":
    # get_origin_securityfocus()

    # split_securityfocus_by_nonalpha()
    # get_softname_and_version_of_securityfocus()

    # get_softname_and_version_of_nvd()
    # get_data_from_dict()  # 查看字典的结构

    # get_securityfocus_and_nvd_soft_origin()
    # clean_securityfocus_and_nvd_softname_version()

    keep_not_same_version_of_securityfocus_and_nvd()

