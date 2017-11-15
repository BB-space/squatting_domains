#!/usr/bin/env python
# -*- coding: utf-8 -*-

confuse_table = "confusablesSummary_revision06.txt"


#we focus on the small latin numbers
def get_the_homo_mapping_from_confusedSummarys(confuse_table, small_latin_number):
    arrow = u'←'
    start = u'#	'

    find_latin = False

    ans = []
    import codecs
    f = codecs.open(confuse_table, "r", "utf-8")
    #3f = open(confuse_table,'rb')
    for line in f.readlines():
        line = line.strip().rstrip()

        if line.startswith(start):
            find_latin = False
            try:
                identical = line[1:].split()[0]
            except:
                print  (identical)
                raw_input()
            if identical == small_latin_number:
                find_latin = True

        if find_latin:
            if line.startswith(arrow):
                tmp = line.split(')')[-1]
                tmp = tmp.split()[0]
                tmp = u'0'*(8-len(tmp))+tmp
                tmp = ('\U'+tmp).encode('utf_8').decode('unicode_escape')
                ans.append(tmp)

    f.flush()
    f.close()
    #for i in ans:
    #    print i

    return ans



if __name__ == "__main__":
    # get a to z unicode
    """
    alpha_homo ={}
    for i in range(97, 123):
        ans = get_the_homo_mapping_from_confusedSummarys(confuse_table,unichr(i))
        alpha_homo.update({unichr(i):ans})

    import pprint
    pprint.pprint(alpha_homo,indent=1)
    """
    from squatting.CONSTANTS_homo_mapping import  HOMO_MAP_UNICODE
    for key in HOMO_MAP_UNICODE:
        print (key)
        for i in HOMO_MAP_UNICODE[key]:
            print (i)

