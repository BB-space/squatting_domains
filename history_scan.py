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


def unicode_to_IDN_encoder(domain):
    try:
        d = domain.encode("idna")
        return d
    except UnicodeError:
        pass
    except ValueError as exc:
        # see https://github.com/john-kurkowski/tldextract/issues/122
        if "narrow Python build" in exc.args[0]:
            warnings.warn("can not decode punycode: %s" % exc.args[0], UnicodeWarning, stacklevel=2)
            return None
        raise
    return None

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
                    tuple = (original_domain_tld, old_qname, qname, t, IP)
                    #print (tuple)
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
    write_tuple_into_a_file(tp, 'record'+original_domain_tld+'.txt')
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
    #n_core = 50
    print ("[Stat]The cores we use is {}".format(n_core))

    pool = Pool(n_core)
    res = pool.map(analyze_compressed_domains, args_list)

    print ("[Stat]We finish and record all results of", directory)

    total_sqautting_domains = list()
    for i in res:
        if len(i) > 0:
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
    #directory = "/home/ketian/Desktop/toad_test_dataset/20170906/"

    domains = ['1688.com', '360.cn', '39.net', '4chan.org', '53.com', '6pm.com', '9gag.com', 'aa.com', 'aafp.org', 'aamc.org', 'aarp.org', 'abc.net.au', 'abcya.com', 'ablinc.com', 'absa.co.za', 'accurint.com', 'accuweather.com', 'acs.org', 'adam4adam.com', 'adobe.com', 'adp.com', 'adultdvdempire.com', 'adultdvdtalk.com', 'adultfriendfinder.com', 'adultwork.com', 'aetna.com', 'agoda.com', 'alaskaair.com', 'alibaba.com', 'alipay.com', 'allegro.pl', 'alliancebank.com', 'allrecipes.com', 'alotporn.com', 'amarillo.gov', 'amazon.ca', 'americanexpress.com', 'americangreetings.com', 'ana.co.jp', 'ancestry.com', 'android.com', 'answers.com', 'anz.com.au', 'aol.com', 'apa.org', 'apartmenttherapy.com', 'apple.com', 'archive.org', 'arena.net', 'arxiv.org', 'asb.co.nz', 'ask.com', 'asos.com', 'associatedbank.com', 'asstr.org', 'ato.gov.au', 'atpworldtour.com', 'att.com', 'autoblog.com', 'autodesk.com', 'autotrader.com', 'avclub.com', 'azlyrics.com', 'babycenter.com', 'babytree.com', 'backpage.com', 'baidu.com', 'banco.bradesco', 'bankmillennium.pl', 'bankofamerica.com', 'bankofthewest.com', 'bankrate.com', 'barclaycardus.com', 'barnesandnoble.com', 'baseball-reference.com', 'basketball-reference.com', 'battle.net', 'bbamericas.com', 'bbb.org', 'bbc.co.uk', 'bbt.com', 'behance.net', 'bendigo.vic.gov.au', 'berkeley.edu', 'bestbuy.com', 'bet-at-home.com', 'bgr.com', 'bhdleon.com.do', 'bhg.com', 'bhphotovideo.com', 'biblegateway.com', 'biblehub.com', 'billboard.com', 'bing.com', 'biomedcentral.com', 'bitcoin.com', 'bitcointalk.org', 'bitfinex.com', 'blackboard.com', 'bleacherreport.com', 'blizzard.com', 'blockchain.com', 'blogger.com', 'bloomberg.com', 'bloomspot.com', 'bmj.com', 'bmo.com', 'boardgamegeek.com', 'bodybuilding.com', 'bom.gov.au', 'bonappetit.com', 'bongacams.com', 'booking.com', 'border.gov.au', 'britannica.com', 'britishairways.com', 'bt.com', 'bulbagarden.net', 'bungie.net', 'business.gov.au', 'businessinsider.com', 'cafemom.com', 'cahoot.com', 'caijing.com.cn', 'cam4.com', 'cambridge.org', 'cams.com', 'cancer.gov', 'capitalone.com', 'capitecbank.co.za', 'caranddriver.com', 'careerbuilder.com', 'carfax.com', 'cbc.ca', 'cbsnews.com', 'cbssports.com', 'cc.com', 'cdc.gov', 'celebritymoviearchive.com', 'centurylink.com', 'change.org', 'chase.com', 'chaturbate.com', 'chess.com', 'china.com.cn', 'chinadaily.com.cn', 'chron.com', 'cibc.com', 'cielotalent.com', 'cimbclicks.com', 'cisco.com', 'citationmachine.net', 'citi.com', 'citizensbank.com', 'clevelandclinic.org', 'cliphunter.com', 'clips4sale.com', 'cnbc.com', 'cnblogs.com', 'cnet.com', 'cnn.com', 'co-operativebank.co.uk', 'codecademy.com', 'coinbase.com', 'coinmarketcap.com', 'cointelegraph.com', 'collegeboard.org', 'colorado.edu', 'columbia.edu', 'comerica.com', 'commbank.com.au', 'companieshouse.gov.uk', 'compass.co', 'complex.com', 'consumerreports.org', 'cornell.edu', 'correios.com.br', 'cosmopolitan.com', 'costco.com', 'couchsurfing.com', 'countryliving.com', 'coursera.org', 'cracked.com', 'craigslist.org', 'credit-agricole.it', 'creditkarma.com', 'cricbuzz.com', 'crownaudio.com', 'csdn.net', 'css-tricks.com', 'cua.com.au', 'curse.com', 'dailykos.com', 'dailymail.co.uk', 'db.com', 'dbs.com', 'deadspin.com', 'deezer.com', 'delta.com', 'deviantart.com', 'dhl.com', 'dict.cc', 'digg.com', 'digitalplayground.com', 'digitaltrends.com', 'dinersclubus.com', 'discogs.com', 'discover.com', 'discovery.com', 'dpreview.com', 'dropbox.com', 'drudgereport.com', 'drugs.com', 'duolingo.com', 'dw.com', 'e-gold.com', 'ea.com', 'easports.com', 'easybib.com', 'easyjet.com', 'ebaumsworld.com', 'ebay.co.uk', 'ebscohost.com', 'ecollege.com', 'economist.com', 'ed.gov', 'edmunds.com', 'edx.org', 'elsevier.com', 'emirates.com', 'engadget.com', 'epicgames.com', 'epicurious.com', 'eppicard.com', 'espn.com', 'espncricinfo.com', 'espnfc.us', 'esquire.com', 'etsy.com', 'eurogamer.net', 'europa.eu', 'eurosport.com', 'eventbrite.com', 'ew.com', 'expedia.com', 'express-scripts.com', 'f-list.net', 'facebook.com', 'fanfiction.net', 'fao.org', 'fda.gov', 'fdic.gov', 'fedex.com', 'fema.gov', 'fetlife.com', 'ffsavings.com', 'fhb.com', 'fidelity.com', 'fifa.com', 'filgoal.com', 'finalfantasyxiv.com', 'firstdirect.com', 'fixya.com', 'flashscore.com', 'flightradar24.com', 'flipkart.com', 'flirt4free.com', 'fnb.co.za', 'fontawesome.io', 'fontsquirrel.com', 'fool.com', 'football365.com', 'forbes.com', 'ford.com', 'forever21.com', 'foxnews.com', 'foxsports.com', 'fragrantica.com', 'franklintempleton.com', 'freeones.com', 'ftvgirls.com', 'furaffinity.net', 'gamefaqs.com', 'gamespot.com', 'gamesradar.com', 'gamestop.com', 'gap.com', 'gayboystube.com', 'giantbomb.com', 'github.com', 'gizmodo.com', 'globaltimes.cn', 'go.com', 'goal.com', 'gocomics.com', 'godaddy.com', 'goodhousekeeping.com', 'goodreads.com', 'google.com', 'gq.com', 'grammarly.com', 'groupon.com', 'grubhub.com', 'gruppocarige.it', 'gsmarena.com', 'gsmhosting.com', 'gtbank.com', 'guildwars2.com', 'habbo.com', 'halifax.co.uk', 'hao123.com', 'harvard.edu', 'hdfcbank.com', 'health.com', 'healthcare.gov', 'healthgrades.com', 'heart.org', 'hentai-foundry.com', 'hentai2read.com', 'hgtv.com', 'hi5.com', 'hilton.com', 'hindawi.com', 'hindustantimes.com', 'history.com', 'hkjc.com', 'hm.com', 'hollywoodreporter.com', 'homeaway.com', 'homedepot.com', 'hotels.com', 'howstuffworks.com', 'hp.com', 'hsbc.com', 'huffingtonpost.com', 'hulu.com', 'humblebundle.com', 'huntington.com', 'iafd.com', 'icicibank.com', 'icy-veins.com', 'ieee.org', 'ifixit.com', 'ign.com', 'iherb.com', 'ikea.com', 'illinois.edu', 'imdb.com', 'imgur.com', 'imlive.com', 'indeed.com', 'independentbank.com', 'indianexpress.com', 'indiatimes.com', 'infowars.com', 'ing.com', 'inkbunny.net', 'instructables.com', 'intel.com', 'interactivebrokers.com', 'interpals.net', 'intesasanpaolo.com', 'investing.com', 'investopedia.com', 'irctc.co.in', 'irs.gov', 'istockphoto.com', 'itau.com.br', 'itch.io', 'jal.co.jp', 'jalopnik.com', 'japanpost.jp', 'jcpenney.com', 'jd.com', 'jezebel.com', 'jma.go.jp', 'jstor.org', 'just-eat.co.uk', 'jw.org', 'kaiserpermanente.org', 'kayak.com', 'kbb.com', 'kcfcu.org', 'key.com', 'khanacademy.org', 'kidshealth.org', 'kiwibank.co.nz', 'kohls.com', 'kongregate.com', 'kraken.com', 'lasalle.com', 'latam.com', 'latimes.com', 'lds.org', 'leagueoflegends.com', 'legacy.com', 'lego.com', 'leo.org', 'lifehack.org', 'linkedin.com', 'literotica.com', 'littlewoods.com', 'live.com', 'livejasmin.com', 'livejournal.com', 'liveleak.com', 'livescience.com', 'livescore.com', 'livingsocial.com', 'lloydsbank.com', 'localbitcoins.com', 'lolcounter.com', 'lonelyplanet.com', 'lottomatica.it', 'lowes.com', 'lufthansa.com', 'luscious.net', 'lynda.com', 'macys.com', 'manhunt.net', 'marketwatch.com', 'marriott.com', 'marthastewart.com', 'mastercard.us', 'match.com', 'mathsisfun.com', 'mathworks.com', 'maxpreps.com', 'mayoclinic.org', 'mbtrading.com', 'mediafire.com', 'medicinenet.com', 'medlineplus.gov', 'medscape.com', 'mega.nz', 'mensfitness.com', 'menshealth.com', 'mercola.com', 'mergersandinquisitions.com', 'merriam-webster.com', 'metacritic.com', 'metrobankonline.co.uk', 'microsoft.com', 'minecraft.net', 'minecraftforum.net', 'miniclip.com', 'mint.com', 'mit.edu', 'mlb.com', 'mmo-champion.com', 'motorsport.com', 'mozilla.org', 'mrskin.com', 'msn.com', 'myetherwallet.com', 'myfitnesspal.com', 'myspace.com', 'myway.com', 'n-ram.co.uk', 'nab.com.au', 'nantucketbank.com', 'nationalcityca.gov', 'nationalgeographic.com', 'nationwide.com', 'nature.com', 'natwest.com', 'nba.com', 'nbcnews.com', 'nbcsports.com', 'nbkc.com', 'ndtv.com', 'nedbank.co.za', 'nejm.org', 'netflix.com', 'nets.eu', 'netsuite.com', 'newegg.com', 'news.com.au', 'newsweek.com', 'newyorker.com', 'nexi.it', 'nexon.net', 'nexusmods.com', 'nfl.com', 'nhentai.net', 'nhl.com', 'nifty.org', 'nih.gov', 'nike.com', 'nintendo.com', 'noaa.gov', 'nordea.com', 'nordstrom.com', 'npr.org', 'nudevista.com', 'nvidia.com', 'nypost.com', 'nytimes.com', 'nyu.edu', 'office.com', 'oglaf.com', 'opendns.com', 'opentable.com', 'oracle.com', 'orange.com', 'orbitz.com', 'orkut.com', 'otomoto.pl', 'oup.com', 'overstock.com', 'oxforddictionaries.com', 'pandora.com', 'patient.info', 'patreon.com', 'paxful.com', 'paypal.com', 'pbs.org', 'pbskids.org', 'pcgamer.com', 'pch.com', 'pcworld.com', 'people.com.cn', 'peoples.com', 'permanenttsb.ie', 'petmd.com', 'phonearena.com', 'pinterest.com', 'pkobp.pl', 'planetsuzy.org', 'playstation.com', 'plos.org', 'plumdistrict.com', 'pnc.com', 'poloniex.com', 'popsugar.com', 'popularmechanics.com', 'porn.com', 'poste.it', 'premierleague.com', 'prevention.com', 'priceline.com', 'psu.edu', 'psychologytoday.com', 'purdue.edu', 'qatarairways.com', 'qq.com', 'rabobank.com', 'rackspace.com', 'raspberrypi.org', 'rbcroyalbank.com', 'rbs.co.uk', 'realtor.com', 'redbubble.com', 'reddit.com', 'regions.com', 'rei.com', 'researchgate.net', 'reuters.com', 'reverso.net', 'rhymezone.com', 'rivals.com', 'roblox.com', 'rockstargames.com', 'rotoworld.com', 'rottentomatoes.com', 'royalmail.com', 'rt.com', 'runescape.com', 'rxlist.com', 'ryanair.com', 'safra.com', 'salemfive.com', 'salesforce.com', 'salon.com', 'samsung.com', 'santander.co.uk', 'sars.gov.za', 'sbnation.com', 'sciencedaily.com', 'sciencedirect.com', 'sciencemag.org', 'scientificamerican.com', 'scribd.com', 'sdsu.edu', 'seamless.com', 'self.com', 'sephora.com', 'service.gov.uk', 'sextvx.com', 'sfgate.com', 'shutterfly.com', 'shutterstock.com', 'si.com', 'sigmaaldrich.com', 'sina.com.cn', 'siteadvisor.com', 'sitepoint.com', 'sky.com', 'skyfinancial.com', 'skype.com', 'skyscanner.com', 'skysports.com', 'slate.com', 'slideshare.net', 'smile.co.uk', 'snopes.com', 'so.com', 'soccerway.com', 'sogou.com', 'sohu.com', 'soompi.com', 'soundcloud.com', 'southwest.com', 'spanishdict.com', 'spankwire.com', 'speedtest.net', 'spine-health.com', 'sporcle.com', 'sportingnews.com', 'spotify.com', 'springer.com', 'square-enix.com', 'squirt.org', 'ssa.gov', 'stackoverflow.com', 'standardbankbd.com', 'stanford.edu', 'staples.com', 'state.gov', 'steadyhealth.com', 'steampowered.com', 'stgeorge.com.au', 'strava.com', 'streamate.com', 'studentdoctor.net', 'stumbleupon.com', 'suicidegirls.com', 'sulekha.com', 'suncorp.com.au', 'swedbank.us', 'symbolab.com', 'tagged.com', 'taobao.com', 'target.com', 'td.com', 'tdameritrade.com', 'teamliquid.net', 'techcrunch.com', 'ted.com', 'telegraph.co.uk', 'tesco.com', 'theatlantic.com', 'thedailybeast.com', 'thefreedictionary.com', 'theguardian.com', 'thehill.com', 'thehindu.com', 'thekitchn.com', 'theknot.com', 'theonion.com', 'thesaurus.com', 'thesimsresource.com', 'thesun.co.uk', 'theverge.com', 'thrillist.com', 'tianya.cn', 'tibia.com', 'ticketmaster.com', 'time.com', 'timeanddate.com', 'timeout.com', 'tmall.com', 'tmz.com', 'tomsguide.com', 'tomshardware.com', 'travelocity.com', 'trello.com', 'tripadvisor.com', 'trustedreviews.com', 'trustpilot.com', 'tsb.co.uk', 'tsn.ca', 'tumblr.com', 'tums.ac.ir', 'turkishairlines.com', 'turnitin.com', 'twitch.tv', 'twitter.com', 'uber.com', 'ubisoft.com', 'ucla.edu', 'udacity.com', 'udemy.com', 'uefa.com', 'ultimate-guitar.com', 'umich.edu', 'un.org', 'unicredit.it', 'united.com', 'unity3d.com', 'ups.com', 'urbandictionary.com', 'urbanoutfitters.com', 'usaa.com', 'usatoday.com', 'usbank.com', 'usda.gov', 'usgs.gov', 'usnews.com', 'usps.com', 'utexas.edu', 'va.gov', 'variety.com', 'verizonwireless.com', 'very.co.uk', 'vice.com', 'vimeo.com', 'vintage-erotica-forum.com', 'visa.com', 'vocabulary.com', 'vodafone.com', 'vr.de', 'vrbo.com', 'walgreens.com', 'walmart.com', 'washington.edu', 'washingtonpost.com', 'wayfair.com', 'weather.com', 'webex.com', 'webmd.com', 'weebly.com', 'weibo.com', 'weightwatchers.com', 'wellsfargo.com', 'westernunion.com', 'westlaw.com', 'westpac.com.au', 'whatsapp.com', 'who.int', 'wikia.com', 'wikihow.com', 'wikipedia.org', 'wiktionary.org', 'wiley.com', 'wired.com', 'wisc.edu', 'wizards.com', 'wolfram.com', 'wonderhowto.com', 'wordpress.com', 'wordreference.com', 'worldbank.org', 'worldofwarcraft.com', 'wowhead.com', 'wsj.com', 'wunderground.com', 'wwe.com', 'xapo.com', 'xbox.com', 'xe.com', 'xfinity.com', 'xinhuanet.com', 'xnxx.com', 'xvideos.com', 'y8.com', 'yahoo.com', 'yelp.com', 'yoox.com', 'youneedabudget.com', 'youporn.com', 'youtube.com', 'zappos.com', 'zara.com', 'zhihu.com', 'zillow.com', 'zocdoc.com', 'zomato.com', 'zynga.com']
    domains = domains[1:10]

    for i in domains:
        original_domain_tld = i.decode('utf-8')
        squadict = recursively_analyze_gz_files(direcory=directory, original_domain_tld=original_domain_tld, output_dir=None)


    #original_domain_tld = "docs.google.com"
    #recursively_analyze_gz_files(direcory=directory, original_domain_tld=original_domain_tld, output_dir=None)
