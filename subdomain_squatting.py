#!/usr/bin/env python
# -*- coding: utf-8 -*-

__author__ = 'ketian'
__version__ = '1.04b'
__email__ = 'ririhedou@gmail.com'


from history_scan import recursively_analyze_gz_files,unicode_to_IDN_encoder,write_a_list_of_tuples_into_a_file
from squatting_detect import  __domain_tld

if __name__ == "__main__":

    directory = "/home/ketian/Desktop/toad_test_dataset/test/"
    subdomains = ['abcnews.go.com', 'abr.business.gov.au', 'answers.yahoo.com', 'auto.qq.com', 'auto.sina.com.cn',
                  'auto.sohu.com', 'baike.baidu.com', 'blog.csdn.net', 'blog.e-gold.com', 'blog.sina.com.cn',
                  'blog.sohu.com', 'citeseerx.ist.psu.edu', 'cn.bing.com', 'developer.android.com', 'dict.leo.org',
                  'dictionary.cambridge.org', 'docs.google.com', 'doctor.webmd.com', 'ec.europa.eu',
                  'economictimes.indiatimes.com', 'emedicine.medscape.com', 'en.wikipedia.org', 'en.wiktionary.org',
                  'fafsa.ed.gov', 'fallout.wikia.com', 'fantasy.nfl.com', 'finance.yahoo.com',
                  'football.fantasysports.yahoo.com', 'forms.netsuite.com', 'forum.gsmhosting.com', 'hao.360.cn',
                  'ibank.gtbank.com', 'login.live.com', 'mail.google.com', 'mail.qq.com', 'mail.yahoo.com',
                  'map.baidu.com', 'mlb.mlb.com', 'money.cnn.com', 'ncbi.nlm.nih.gov', 'news.baidu.com',
                  'news.google.com', 'news.qq.com', 'news.sina.com.cn', 'news.sohu.com', 'news.yahoo.com',
                  'niams.nih.gov', 'nichd.nih.gov', 'niddk.nih.gov', 'nimh.nih.gov', 'nlm.nih.gov', 'online.citi.com',
                  'onlinelibrary.wiley.com', 'outlook.live.com', 'pan.baidu.com', 'personal.natwest.com',
                  'personal.rbs.co.uk', 'play.google.com', 'plus.google.com', 'post.japanpost.jp',
                  'profootballtalk.nbcsports.com', 'runescape.wikia.com', 'scratch.mit.edu', 'search.yahoo.com',
                  'sports.qq.com', 'sports.sina.com.cn', 'sports.sohu.com', 'sports.yahoo.com',
                  'store.steampowered.com', 'support.microsoft.com', 'tech.sina.com.cn', 'timesofindia.indiatimes.com',
                  'translate.google.com', 'travel.state.gov', 'usa.visa.com', 'v.qq.com', 'wenku.baidu.com',
                  'www.tax.service.gov.uk', 'yule.sohu.com', 'zh.wikipedia.org']

    records = list()
    valid = 0
    for i in subdomains:
        original_domain_tld = i.decode('utf-8')
        squadict = recursively_analyze_gz_files(direcory=directory, original_domain_tld=original_domain_tld,
                                                output_dir=None)
        domain_tld = original_domain_tld.decode('utf-8')
        tps = list()
        base_domain_name, tld = __domain_tld(domain_tld)
        c, t, s = 0, 0, 0
        for i in squadict:
            type = i
            for j in squadict[i]:
                t += 1
                idn = unicode_to_IDN_encoder(j + u'.' + tld)
                if idn is None:
                    print ("error")
                    c += 1
                    continue
                idn = idn.decode('utf-8')
                if idn == domain_tld:
                    s += 1
                    print ("same")
                    continue
                tp = (original_domain_tld, type, j, idn)
                tps.append(tp)

        write_a_list_of_tuples_into_a_file(tps, "subdomain/" + domain_tld)
        r = ("orginial_domain_tld", domain_tld, "total", t, "error", c, "same", s)
        records.append(r)
        valid += t - s - c

    write_a_list_of_tuples_into_a_file(records, 'records')
    print ("total valid domains are", valid)