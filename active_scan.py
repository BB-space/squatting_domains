#!/usr/bin/env python
# -*- coding: utf-8 -*-


"""
scan the active DNS
"""
__author__ = 'ketian'
__version__ = '0.01a'
__email__ = 'ririhedou@gmail.com'

from squatting.complete_squatting import get_the_complete_list_of_squatting_domains
from squatting_detect import labeling_candidiates, __domain_tld

import fastavro as avro
import idna
import warnings
from collections import defaultdict
import codecs
import os
import sys

import copy
from multiprocessing import Pool
import multiprocessing


def decode_punycode(label):
        """helper function; decodes a section of the netloc from punycode."""
        try:
            return idna.decode(label.encode('ascii'))
        except UnicodeError:
            pass
        except ValueError as exc:
            # see https://github.com/john-kurkowski/tldextract/issues/122
            if "narrow Python build" in exc.args[0]:
                warnings.warn("can not decode punycode: %s" % exc.args[0],UnicodeWarning, stacklevel=2)
                return label
            raise
        return label


def analyze_avro(args):
    avro_file = args['avro_file']
    squat_dict =args['squat_dict']
    original_domain_tld = args['original_domain']
    output_dir = args['output_dir']

    print ("We are analyzing " + str(avro_file))

    suspicious_domains = defaultdict(list)
    found_tps = list()

    with open(avro_file, 'r') as fo:

        reader = avro.reader(fo)
        # will raise a fastavro.reader.SchemaResolutionError in case of
        # incompatible schema
        # schema = reader.schema
        # print ("Schema is" + schema)
        c = 0
        for record in reader:

            old_qname = record['qname']
            qname = record['qname']
            IP = record['authority_ips']

            if len(qname) > 1:
                try:
                    old_qname = qname
                    qname = qname[:-1]

                    if u'xn--' in qname:
                        qname = decode_punycode(qname)
                    t = labeling_candidiates(qname, squat_dict, original_domain_tld)
                    if t:
                        tuple = (old_qname, qname, t, IP)
                        print (tuple)

                        found_tps.append(tuple)
                        suspicious_domains[t].append(tuple)

                except:
                    f = open('unicode-log-active-error.log', 'a')
                    f.write(qname)
                    f.write('\n')
                    f.flush()
                    f.close()
            else:
                continue

            c += 1

        f_name = avro_file.replace(u'/', '_') + '.out'
        if output_dir is None:
            pass
        else:
            if os.path.isdir(output_dir):
                if output_dir.endswith('/'):
                    f_name = output_dir + f_name
                else:
                    f_name = output_dir + '/' + f_name
            else:
                print ("[Warn]Output dir do not exist, we use current dir")

        write_a_list_of_tuples_into_a_file(found_tps, f_name)

        print ("[STAT]total analysed files are {}".format(c))
        print ("[STAT]total suspicious domains are {}".format(len(suspicious_domains)))
        tp = (str(avro_file), str(c), str(len(suspicious_domains)))
        write_tuple_into_a_file(tp, 'record.txt')


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


# TODO multiprocess this process
def recursively_analyze_avro_files(direcory, squat_dict, original_domain_tld, output_dir=None):
    files = recursive_glob(direcory, '.avro')
    files.sort()

    print ("[Stat]TOTALLY we analyze {} files".format(len(files)))

    args_list = []
    for i in files:
        args = dict()
        args['avro_file'] = i
        args['squat_dict'] = squat_dict
        args['original_domain'] = original_domain_tld
        args['output_dir'] = output_dir
        args_list.append(copy.deepcopy(args))
        del args

    n_core = multiprocessing.cpu_count()
    print ("[Stat]The cores we use is {}".format(n_core))

    pool = Pool(n_core)
    pool.map(analyze_avro, args_list)
    pool.close()
    pool.join()


def run_active_scan(input_dire, domain_tld, output_dir=None):

    domain_tld = domain_tld.decode('utf-8')

    base_domain_name, tld = __domain_tld(domain_tld)

    print ("[Info]domain_tld is: ", domain_tld)

    print ("[Info]base_domain is: ", base_domain_name)

    print ("[Info]tld is: ",tld)

    alist = get_the_complete_list_of_squatting_domains(domain_tld, base_domain_name)

    recursively_analyze_avro_files(input_dire, alist, domain_tld, output_dir)


if __name__ == "__main__":

    print ("Command Format")
    print ("python active_scan.py your_domain your_input_directory your_output_dir[optional, or cur_dir]")
    print ("example:")
    print ("python2 active_scan.py facebook.com /home/datashare/dns/2week/20170901/ /home/ketian/new_result/")
    print ("python2 active_scan.py facebook.com /home/datashare/dns/2week/20170901/")
    #domain_name = u'facebook.com'
    #base_domain_name = u'facebook'

    #python2 active_scan.py facebook.com /home/datashare/dns/2week/20170901/  /home/ketian/new_result/

    domain_tld = sys.argv[1]
    input_dir = sys.argv[2]
    try:
        output_dir = sys.argv[3]
    except:
        output_dir = None

    run_active_scan(input_dire=input_dir, domain_tld=domain_tld, output_dir=output_dir)