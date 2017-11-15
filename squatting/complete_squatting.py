#!/usr/bin/env python
# -*- coding: utf-8 -*-

#python 2.7.12

"""
This is used to get the most suspicious URLs
we mainly focuse on FOUR types:
-typosquatting
-homggraph squatting
-combo squatting
-mb squatting
"""

from CONSTANTS_homo_mapping import HOMO_MAP_UNICODE
from dnsTwist_squatting import get_squatting_domains_dict_from_dnstwist
from urlCrazy_squatting import get_domains_from_url_crazy

import tldextract

def test_constants_mappings():
    for key in HOMO_MAP_UNICODE:
        vals = HOMO_MAP_UNICODE[key]
        print ("KEY",key)
        for val in vals:
            print (val),
        print ("")
    return

def get_the_complete_list_of_squatting_domains(domain_name, base_domain=None):
    """
    :param domain_name: e.g., facebook.com
    :return:
    """
    dict_crazy = get_domains_from_url_crazy(domain_name)

    dict_dnsTwist = get_squatting_domains_dict_from_dnstwist(domain_name)

    for i in dict_dnsTwist:
        dict_crazy[i].extend(dict_dnsTwist[i])
        dict_crazy[i] = list(set(dict_crazy[i]))


    if base_domain is None:
        ext = tldextract.extract(domain_name)
        if ext.subdomain:
            domain = ext.subdomain + u'.' + ext.domain
        else:
            domain = ext.domain

        base_domain = domain.decode('utf-8')

    for i in dict_crazy:
        key = list(set(dict_crazy[i]))
        if base_domain in key:
            key.remove(base_domain)
        dict_crazy[i] = key

    return dict_crazy


if __name__ == "__main__":
    #test_constants_mappings()
    test_domain = u'facebook.com'
    d = get_the_complete_list_of_squatting_domains(test_domain, u'facebook')
    import pprint
    pprint.pprint(dict(d), indent=1)