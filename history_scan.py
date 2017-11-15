#!/usr/bin/env python
# -*- coding: utf-8 -*-

__author__ = 'ketian'
__version__ = '1.04b'
__email__ = 'ririhedou@gmail.com'


import gzip
import idna
import warnings
import collections
import codecs
import os

from squatting.complete_squatting import get_the_complete_list_of_squatting_domains
from squatting_detect import labeling_candidiates, __domain_tld

import copy
from multiprocessing import Pool
import multiprocessing

"""
Scan the historical data
- gz compressed 
- it s a: [domain:IP] mapping 
"""

def decode_punycode(label):
    """helper function; decodes a section of the netloc from punycode."""
    try:
        return idna.decode(label.encode('ascii'))
    except UnicodeError:
        pass
    except ValueError as exc:
        # see https://github.com/john-kurkowski/tldextract/issues/122
        if "narrow Python build" in exc.args[0]:
            warnings.warn("can not decode punycode: %s" % exc.args[0], UnicodeWarning, stacklevel=2)
            return label
        raise
    return label


def analyze_compressed_domains(args):
    # The history data is in the GZ file.
    # compressed_gz_file,squat_dict,original_domain_tld, outputfile=None

    compressed_gz_file = args['gz_file']
    squat_dict = args['squat_dict']
    original_domain_tld = args['original_domain']

    output_dir = args['output_dir']

    f = gzip.open(compressed_gz_file, 'rb')

    print ("we are analyzing", compressed_gz_file)

    found_tps = list()
    c = 0

    for line in f.readlines():

        domain_array = line.strip().split()  # by tab or space

        if len(domain_array) > 1:

            domain = domain_array[0]
            IP = domain_array[1]

            if len(domain) == 0 or not domain.endswith('.'):
                continue
            try:
                old_qname = domain
                qname = domain

                if qname.endswith(u'.'):
                    qname = qname[:-1]

                if u'xn--' in qname:
                    qname = decode_punycode(qname)

                t = labeling_candidiates(qname, squat_dict, original_domain_tld)
                if t:
                    tuple = (old_qname, qname, t, IP)
                    print (tuple)
                    found_tps.append(tuple)

            except:
                f = open('unicode-log-history-error.log', 'a')
                f.write(domain)
                f.write('\n')
                f.flush()
                f.close()
        c += 1

    print ("total", c)
    print ("[STAT]total analysed records are {} in {}".format(c, compressed_gz_file))
    tp = (str(compressed_gz_file), str(c), str(len(found_tps)))
    write_tuple_into_a_file(tp, 'record.txt')
    return found_tps


def write_tuple_into_a_file(content, filename="candidate_domains.txt"):
    file = codecs.open(filename, "a", "utf-8")
    file.write(str(content))
    file.write("\n")
    file.flush()
    file.close()


def write_a_list_of_tuples_into_a_file(tp_list, filename="tps.txt"):
    file = codecs.open(filename, "a", "utf-8")
    for content in tp_list:
        file.write(str(content))
        file.write("\n")

    file.flush()
    file.close()
    print ("[Done]we finish recording the tuples")


def recursive_glob(rootdir='.', suffix=''):
    return [os.path.join(looproot, filename)
            for looproot, _, filenames in os.walk(rootdir)
            for filename in filenames if filename.endswith(suffix)]


def recursively_analyze_gz_files(direcory, original_domain_tld, output_dir=None):

    domain_tld = original_domain_tld.decode('utf-8')

    base_domain_name, tld = __domain_tld(domain_tld)

    print ("[Info]domain_tld is: ", domain_tld)

    print ("[Info]base_domain is: ", base_domain_name)

    print ("[Info]tld is: ", tld)

    squat_dict = get_the_complete_list_of_squatting_domains(domain_tld, base_domain_name)

    files = recursive_glob(direcory,'.gz')
    files.sort()

    print ("[Stat]TOTALLY we analyze {} files".format(len(files)))

    args_list = []
    for i in files:
        args = dict()
        args['gz_file'] = i
        args['squat_dict'] = squat_dict
        args['original_domain'] = original_domain_tld
        args['output_dir'] = output_dir
        args_list.append(copy.deepcopy(args))
        del args

    n_core = multiprocessing.cpu_count()
    print ("[Stat]The cores we use is {}".format(n_core))

    pool = Pool(n_core)
    res = pool.map(analyze_compressed_domains, args_list)

    print ("[Stat]We finish and record all results of", directory)

    total_sqautting_domains = list()
    for i in res:
        if len(i)>0:
            total_sqautting_domains.extend(i)

    if not output_dir:
        f_name = directory.replace(u'/', '_') + original_domain_tld + '.out'
    else:
        f_name = directory.replace(u'/', '_') + original_domain_tld + '.out'
        if os.path.isdir(output_dir):
            if output_dir.endswith('/'):
                f_name = output_dir + f_name
            else:
                f_name = output_dir + '/' + f_name
        else:
            print ("[Warn]Output dir do not exist, we use current dir")

    write_a_list_of_tuples_into_a_file(total_sqautting_domains, filename=f_name)
    print ("[Stat]we write the results into a file as {}".format(f_name))
    return


if __name__ == "__main__":
    directory = "/home/datashare/dns/history/20170906/"
    directory = "/home/ketian/Desktop/toad_test_dataset/test/"
    original_domain_tld = "amazon.co.jp"
    recursively_analyze_gz_files(direcory=directory, original_domain_tld=original_domain_tld, output_dir=None)
