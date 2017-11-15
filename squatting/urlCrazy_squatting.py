#!/usr/bin/env python
# -*- coding: utf-8 -*-


import csv
import collections
import os
import subprocess
import tldextract

def purify_squatting_dic(dic):
    typo = u'typo'
    bit = u'bits'
    homo = u'homo'

    char = u'Character'
    bit_keyword = u'Bit Flipping'
    homo_keyword = u'Homoglyphs'

    new_squat_dic = collections.defaultdict(list)

    for key in dic:
        if char in key:
            new_squat_dic[typo].extend(dic[key])
        elif bit_keyword in key:
            new_squat_dic[bit].extend(dic[key])
        elif homo_keyword in key:
            new_squat_dic[homo].extend(dic[key])
        else:
            pass

    for i in new_squat_dic:
        new_squat_dic[i] = list(set(new_squat_dic[i]))
    return new_squat_dic

def get_domains_from_url_crazy(domain_name):
    """
    :param domain_name: e.g., facebook.com
    :return: a list
    """
    squat_dic = collections.defaultdict(list)
    csv_file = domain_name + u'.csv'

    if os.path.exists(u'./csv_files/'+csv_file):
        csv_file = u'./csv_files/' + csv_file
    elif os.path.exists(u'../csv_files/'+csv_file):
        csv_file = u'../csv_files/'+csv_file
        pass
    else:
        print ("there is no existing csv from URLcrazy, we begin to generate it")
        csv_file = u'./csv_files/' + csv_file
        command = u'./squatting/urlcrazy-0.5/urlcrazy -f CSV -o ' + csv_file + u' ' + domain_name
        process = subprocess.Popen(command,shell=True)
        process.wait()

    data_initial = open(csv_file, "rU")
    #import codecs
    #data_initial = codecs.open(csv_file, "rU", "utf-8")
    reader = csv.reader((line.replace('\0', '') for line in data_initial), delimiter=",", quotechar='|')

    rownum = 0
    header = None

    for row in reader:
        if rownum == 0:
            header = row
        else:
            if len(row) < 2:
                    continue

            category_squatting = row[0]
            domain = row[1]

            ext = tldextract.extract(domain)
            if ext.subdomain:
                domain = ext.subdomain + u'.' +ext.domain
            else:
                domain = ext.domain

            domain = domain.decode('utf-8')
            squat_dic[category_squatting].append(domain)

        rownum += 1

    squat_dic = purify_squatting_dic(squat_dic)

    return squat_dic
