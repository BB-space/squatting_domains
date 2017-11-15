#!/usr/bin/env python
# -*- coding: utf-8 -*-

__author__ = 'ketian'
__version__ = '1.04b'
__email__ = 'ririhedou@gmail.com'


"""
I did not do the unit test
I just test the basic function
"""

from squatting.complete_squatting import *
from active_scan import recursively_analyze_avro_files
from history_scan import recursively_analyze_gz_files
import tldextract
import pprint


if __name__ == "__main__":

    test_domain = u'facebook.com'
    #test_domain = u'icbc.com.cn'
    #test_domain = u'paypal.com'

    #d = get_the_complete_list_of_squatting_domains(test_domain)
    #pprint.pprint(dict(d), indent=1)

    #test URL crazy
    #d = get_domains_from_url_crazy(test_domain)
    #pprint.pprint(dict(d), indent=1)

    alist = get_the_complete_list_of_squatting_domains(test_domain)

    filename = "/Users/ketian/Desktop/DNS_mobile_phishing/part-r-00018.avro"
    filename = "/home/datashare/dns/2week/20170901/part-r-00000.avro"

    direct = "/home/datashare/dns/2week/20170901/"
    direct = "/Users/ketian/Desktop/DNS_mobile_phishing/"

    compressive_file = "part-00000.gz"

    outputfile = "yy_test.txt"

    recursively_analyze_gz_files(direct,alist,test_domain,outputfile)