#!/usr/bin/env python
# -*- coding: utf-8 -*-

__author__ = 'ketian'
__version__ = '1.04b'
__email__ = 'ririhedou@gmail.com'

import re
from os import path
import editdistance


import sys
reload(sys)
sys.setdefaultencoding('utf8')

EDIT_DISTANCE_THRESHOLD = 2
HYPHEN_DISTANCE_THRESHOLD = 4
DOMAIN_LENGTH_THRESHOLD = 20


candidates =[u'facebook', u'youtube', u'paypal', u'bankofamerica.com', u'chase', u'wellsfargo', u'citi' ]

FUZZER_CATEGORY = ['typo-squatting','homo-squatting','bits-squatting','combo-squatting', 'various']

DIR = path.abspath(path.dirname(sys.argv[0]))
DIR_DB = 'database'
FILE_TLD = path.join(DIR, DIR_DB, 'effective_tld_names.dat')
DB_TLD = path.exists(FILE_TLD)


#faster than tldextract
def __domain_tld(domain):
    domain = domain.rsplit('.', 2)

    if len(domain) == 2:
        return domain[0], domain[1]

    if DB_TLD:
        cc_tld = {}
        re_tld = re.compile('^[a-z]{2,4}\.[a-z]{2}$', re.IGNORECASE)

        for line in open(FILE_TLD):
            line = line[:-1]
            if re_tld.match(line):
                sld, tld = line.split('.')
                if not tld in cc_tld:
                    cc_tld[tld] = []
                cc_tld[tld].append(sld)

        sld_tld = cc_tld.get(domain[2])
        if sld_tld:
            if domain[1] in sld_tld:
                return domain[0], domain[1] + '.' + domain[2]

    return domain[0] + '.' + domain[1], domain[2]


################# FINE GRAINED MATCHING ################
def labeling_candidiates(input_domain_tld, squat_dict, original_domain_tld):
    try:
        domain, tld = __domain_tld(input_domain_tld)
        original_domain, original_tld = __domain_tld(original_domain_tld)

        if wrong_tld_squatting(domain,tld,original_domain,original_tld):
            return ('wrongTLD')

        if mobile_phishing_via_padding(domain,original_domain):
            return ('mobilePhishing')

        if combo_squatting_detection(domain,original_domain):
            return ('combo')

        key = typo_homo_bits_others_squatting(domain, squat_dict)
        if key:
            return key

        key2 = edit_distance_is_small_than_1(domain, original_domain)
        if key2:
            return key2

        return False

    except:
        f = open('log-error.log', 'a')
        f.write(input_domain_tld)
        f.write('\n')
        f.flush()
        f.close()

def wrong_tld_squatting(candidate_domain, tld, original_domain, original_tld):
    if (candidate_domain == original_domain) and (tld != original_tld):
        return True
    return False


def combo_squatting_detection(domain,original_domain):
    #combo = u'combo'

    combo1 = u'-'+original_domain
    combo2 = original_domain+u'-'

    if (combo1 in domain) or (combo2 in domain):
        return True
    return False

def typo_homo_bits_others_squatting(domain, squat_dic):
    """
    typo = u'typo'
    bit = u'bits'
    homo = u'homo'
    other = u'other'
    """
    for key in squat_dic:
        current_type = squat_dic[key]
        for item in current_type:
            if item == domain:
                return key

    return None

def edit_distance_is_small_than_1(domain, original_domain):
    # a small edit-distance
    # TODO this is the last step, if we did not find any match
    distance = editdistance.eval(domain, original_domain)
    if distance <= 1:
        return u'other'
    return False


def mobile_phishing_via_padding(domain, original_domain):
    def count_continous_hypens(domain):
        count = 0
        for i in domain:
            if i == u'-':
                count += 1
                if count > HYPHEN_DISTANCE_THRESHOLD:
                    return True
            else:
                count = 0
        if count > HYPHEN_DISTANCE_THRESHOLD:
            return True
        return False

    if original_domain in domain and count_continous_hypens(domain):
        return True
    return False


if __name__ == "__main__":

    domain  = 'xn--pfarmer-t2a.com'.decode("idna")
    print (domain)

    print (__domain_tld(u'facebook.com.py'))
    #print (__domain_tld("loging.facebook.----------sub-------------.facebook.com.cn"))
    #print (count_continous_hypens(domain))

    #print (editdistance.eval(domain,u'pfarmer.com'))
    #print (editdistance.eval(u'faceb\U0001d7b8ok',u'facebook'))

    #print (__domain_tld(u'sub.facebook.ru'))
