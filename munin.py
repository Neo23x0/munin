#!/usr/bin/env python3

__AUTHOR__ = 'Florian Roth'
__VERSION__ = "0.13.0 April 2019"

"""
Install dependencies with:

pip install -r requirements.txt
pip3 install -r requirements.txt
"""

import configparser
import requests
from requests.auth import HTTPBasicAuth
import time
import re
import os
import ast
import signal
import sys
import json
import hashlib
import codecs
import traceback
import argparse
from datetime import datetime
from bs4 import BeautifulSoup
from future.utils import viewitems
from colorama import init, Fore, Back, Style
# Handle modules that may be difficult to install
# e.g. pymisp has no Debian package, selenium is obsolete
deactivated_features = []
try:
    from pymisp import PyMISP
except ImportError as e:
    print("ERROR: Module PyMISP not found (this feature will be deactivated: MISP queries)")
    deactivated_features.append("pymisp")
try:
    from selenium import webdriver
except ImportError as e:
    print("ERROR: Module selenium not found (this feature will be deactivated: --intense mode checking comments on VT)")
    deactivated_features.append("selenium")


# CONFIG ##############################################################

# API keys / secrets - please configure them in 'munin.ini'
VT_PUBLIC_API_KEY = '-'
MAL_SHARE_API_KEY = '-'
PAYLOAD_SEC_API_KEY = '-'
PAYLOAD_SEC_API_SECRET = '-'

VENDORS = ['Microsoft', 'Kaspersky', 'McAfee', 'CrowdStrike', 'TrendMicro',
           'ESET-NOD32', 'Symantec', 'F-Secure', 'Sophos', 'GData']

WAIT_TIME = 15  # Public API allows 4 request per minute, so we wait 15 secs by default

CSV_FIELD_ORDER = ['Lookup Hash', 'Rating', 'Comment', 'Positives', 'Virus', 'File Names', 'First Submitted',
                   'Last Submitted', 'File Type', 'MD5', 'SHA1', 'SHA256', 'Imphash', 'Harmless', 'Revoked',
                   'Expired', 'Trusted', 'Signed', 'Signer', 'Hybrid Analysis Sample', 'MalShare Sample',
                   'VirusBay Sample', 'MISP', 'MISP Events', 'URLhaus', 'AnyRun', 'CAPE', 'User Comments']

CSV_FIELDS = {'Lookup Hash': 'hash',
              'Rating': 'rating',
              'Comment': 'comment',
              'Positives': 'positives',
              'Virus': 'virus',
              'File Names': 'filenames',
              'First Submitted': 'first_submitted',
              'Last Submitted': 'last_submitted',
              'File Type': 'filetype',
              'MD5': 'md5',
              'SHA1': 'sha1',
              'SHA256': 'sha256',
              'Imphash': 'imphash',
              'Harmless': 'harmless',
              'Revoked': 'revoked',
              'Expired': 'expired',
              'Trusted': 'mssoft',
              'Signed': 'signed',
              'Signer': 'signer',
              'Hybrid Analysis Sample': 'hybrid_available',
              'MalShare Sample': 'malshare_available',
              'VirusBay Sample': 'virusbay_available',
              'MISP': 'misp_available',
              'MISP Events': 'misp_events',
              'URLhaus': 'urlhaus_available',
              'AnyRun': 'anyrun_available',
              'CAPE': 'cape_available',
              'Comments': 'comments',
              'User Comments': 'commenter',
              }

TAGS = ['HARMLESS', 'SIGNED', 'MSSOFT', 'REVOKED', 'EXPIRED']

# VirusTotal URL
VT_REPORT_URL = 'https://www.virustotal.com/vtapi/v2/file/report'
# MalwareShare URL
MAL_SHARE_URL = 'http://malshare.com/api.php'
# Hybrid Analysis URL
HYBRID_ANALYSIS_URL = 'https://www.hybrid-analysis.com/api/scan'
# Hybrid Analysis Download URL
HYBRID_ANALYSIS_DOWNLOAD_URL = 'https://www.hybrid-analysis.com/api'
# TotalHash URL
TOTAL_HASH_URL = 'https://totalhash.cymru.com/analysis/'
# VirusBay URL
VIRUSBAY_URL = 'https://beta.virusbay.io/sample/search?q='
# URLhaus
URL_HAUS_URL = "https://urlhaus-api.abuse.ch/v1/payload/"
URL_HAUS_MAX_URLS = 5
# AnyRun
URL_ANYRUN = "https://any.run/report/%s"
# CAPE
URL_CAPE = "https://cape.contextis.com/api/tasks/extendedsearch/"
CAPE_MAX_REPORTS = 5


def processLines(lines, resultFile, nocsv=False, debug=False):
    """
    Process the input file line by line
    """
    # Infos of the current batch
    infos = []

    printHighlighted("[+] Processing %d lines ..." % len(lines))

    # Sorted
    if args.sort:
        lines = sorted(lines)

    # Retrohunt Verification
    if args.retroverify:
        print("[+] Virustotal Retrohunt verification mode (using '%d' as sample size)" % int(args.r))
        verifiedSigs = {}

    for i, line in enumerate(lines):
        # Measure time
        start_time = time.time()
        # Remove line break
        line = line.rstrip("\n").rstrip("\r")
        # Skip comments
        if line.startswith("#"):
            continue

        # Info dictionary
        info = {"md5": "-", "sha1": "-", "sha256": "-",}

        # Get all hashes in line
        # ... and the rest of the line as comment
        hashVal, hashType, comment = fetchHash(line)
        info['hash'] = hashVal
        info[hashType] = hashVal
        info['comment'] = comment

        # If no hash found
        if hashVal == '':
            continue

        # Retrohunt Verification - Skip
        if args.retroverify:
            sigName = comment.rstrip(" /subfile")
            if sigName in verifiedSigs:
                if verifiedSigs[sigName]['count'] >= int(args.r):
                    if debug:
                        print("[D] Skipping entry because this sig has already been verified '%s'" % sigName)
                    continue

        # Cache
        cache_result = inCache(hashVal)
        if cache_result:
            info = cache_result
            # But keep the new comment
            info["comment"] = comment
        if debug:
            print("[D] Value found in cache: %s" % cache_result)
        # If found in cache or --nocache set
        vt_queried = False
        if args.nocache or not cache_result:

            # Get Information
            # Virustotal
            vt_info = getVTInfo(hashVal)
            info.update(vt_info)
            # MISP
            misp_info = getMISPInfo(hashVal)
            info.update(misp_info)
            # MalShare
            ms_info = getMalShareInfo(hashVal)
            info.update(ms_info)
            # Hybrid Analysis
            ha_info = getHybridAnalysisInfo(hashVal)
            info.update(ha_info)
            # URLhaus
            if 'md5' in info or 'sha256' in info:
                uh_info = getURLhaus(info['md5'], info['sha256'])
                info.update(uh_info)
            # AnyRun
            if 'sha256' in info:
                ar_info = getAnyRun(info['sha256'])
                info.update(ar_info)
            # CAPE
            if 'md5' in info:
                ca_info = getCAPE(info['md5'])
                info.update(ca_info)

            # TotalHash
            # th_info = {'totalhash_available': False}
            # if 'sha1' in info:
            #     th_info = getTotalHashInfo(info['sha1'])
            # info.update(th_info)
            # VirusBay
            if 'md5' in info:
                vb_info = getVirusBayInfo(info['md5'])
            info.update(vb_info)
            vt_queried = True

        # Print result
        printResult(info, i, len(lines))

        # Comment on Sample
        if args.comment:
            commentVTSample(hashVal, "%s %s" % (args.p, comment))

        # Comparison checks
        extraChecks(info, infos, cache)

        # Download Samples
        if args.download and 'sha256' in info:
            downloadHybridAnalysisSample(info['sha256'])
        elif args.debug and args.download:
            print("[D] Didn't start download: No sha256 hash found!")

        # Retrohunt Verification - Log
        if args.retroverify:
            sigName = comment.rstrip(" /subfile")
            rating = info['rating']
            if sigName not in verifiedSigs:
                verifiedSigs[sigName] = {'positives': [],
                                         'malicious': 0,
                                         'suspicious': 0,
                                         'clean': 0,
                                         'unknown': 0,
                                         'count': 0}
            verifiedSigs[sigName][rating] += 1
            verifiedSigs[sigName]['positives'].append(int(info['positives']))
            verifiedSigs[sigName]['count'] += 1
            if verifiedSigs[sigName]['count'] >= int(args.r):
                printVerificationResult(sigName, verifiedSigs[sigName])

        # Print to CSV
        if not nocsv:
            writeCSV(info, resultFile)
        # Add to hash cache and current batch info list
        if not cache_result:
            cache.append(info)
        infos.append(info)
        # Wait some time for the next request
        if vt_queried:
            time.sleep(max(0, WAIT_TIME - int(time.time() - start_time)))


def fetchHash(line):
    hashTypes = {32: 'md5', 40: 'sha1', 64: 'sha256'}
    pattern = r'((?<!FIRSTBYTES:\s)|[\b\s]|^)([0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})(\b|$)'
    hash_search = re.findall(pattern, line)
    # print hash_search
    if len(hash_search) > 0:
        hash = hash_search[0][1]
        rest = ' '.join(re.sub('({0}|;|,|:)'.format(hash), ' ', line).strip().split())
        return hash, hashTypes[len(hash)], rest
    return '', '', ''


def getVTInfo(hash):
    """
    Retrieves many different attributes of a sample from Virustotal via its hash
    :param hash:
    :return:
    """
    # Sample info
    sample_info = {
        'hash': hash,
        "result": "- / -",
        "virus": "-",
        "last_submitted": "-",
        "first_submitted": "-",
        "filenames": "-",
        "filetype": "-",
        "rating": "unknown",
        "positives": 0,
        "res_color": Back.CYAN,
        "imphash": "-",
        "harmless": False,
        "revoked": False,
        "signed": False,
        "expired": False,
        "mssoft": False,
        "vendor_results": {},
        "signer": "",
        "comments": 0,
        "commenter": '-',
    }

    # Prepare VT API request
    parameters = {"resource": hash, "apikey": VT_PUBLIC_API_KEY}
    success = False
    while not success:
        try:
            response_dict = requests.get(VT_REPORT_URL, params=parameters).json()
            success = True
        except Exception as e:
            if args.debug:
                traceback.print_exc()
                # print "Error requesting VT results"
            pass

    sample_info['vt_verbose_msg'] = response_dict.get("verbose_msg")

    if response_dict.get("response_code") > 0:
        # Hashes
        sample_info["md5"] = response_dict.get("md5")
        sample_info["sha1"] = response_dict.get("sha1")
        sample_info["sha256"] = response_dict.get("sha256")
        # AV matches
        sample_info["positives"] = response_dict.get("positives")
        sample_info["total"] = response_dict.get("total")
        sample_info["last_submitted"] = response_dict.get("scan_date")
        # Virus Name
        scans = response_dict.get("scans")
        virus_names = []
        sample_info["vendor_results"] = {}
        for vendor in VENDORS:
            if vendor in scans:
                if scans[vendor]["result"]:
                    virus_names.append("{0}: {1}".format(vendor, scans[vendor]["result"]))
                    sample_info["vendor_results"][vendor] = scans[vendor]["result"]
                else:
                    sample_info["vendor_results"][vendor] = "-"
            else:
                sample_info["vendor_results"][vendor] = "-"

        if len(virus_names) > 0:
            sample_info["virus"] = " / ".join(virus_names)

        # Positives / Total
        sample_info['vt_positives'] = response_dict.get("positives")
        sample_info['vt_total'] = response_dict.get("total")

        # Get more information with permalink -------------------------
        # This is necessary as the VT API does not provide all the needed field values
        if args.debug:
            print("[D] Processing permalink {0}".format(response_dict.get("permalink")))
        info = processPermalink(response_dict.get("permalink"), args.debug)
        # Now process the retrieved information
        # Other info
        sample_info.update(info)
        # File Names (special handling)
        sample_info["filenames"] = ", ".join(info['filenames']).replace(';', '_')
        sample_info["first_submitted"] = info['firstsubmission']

    return sample_info


def processPermalink(url, debug=False):
    """
    Requests the HTML page for the sample and extracts other useful data
    that is not included in the public API
    """
    headers = {'User-Agent': 'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)',
               'Referrer': 'https://www.virustotal.com/en/'}
    info = {'filenames': ['-'], 'firstsubmission': '-', 'harmless': False, 'signed': False, 'revoked': False,
            'expired': False, 'mssoft': False, 'imphash': '-', 'filetype': '-', 'signer': '-',
            'origname': '-', 'copyright': '-', 'description': '-', 'comments': 0, 'commenter': '-'}
    try:

        if intense_mode and not 'selenium' in deactivated_features:
            # 1. Method - using PhantomJS
            for key, value in enumerate(headers):
                capability_key = 'phantomjs.page.customHeaders.{}'.format(key)
                webdriver.DesiredCapabilities.PHANTOMJS[capability_key] = value

            browser = webdriver.PhantomJS()
            browser.get(url)
            source_code = browser.page_source

            # Extract info from source code
            soup = BeautifulSoup(source_code, 'html.parser')

        # 2. Fallback to requests
        else:
            source_code = requests.get(url, headers=headers)
            soup = BeautifulSoup(source_code.text, 'html.parser')
            source_code = source_code.content.decode("utf-8")

        # Get file names
        elements = soup.find_all('td')
        for i, row in enumerate(elements):
            text = row.text.strip()
            if text == "File names":
                file_names = elements[i + 1].text.strip().split("\n")
                info['filenames'] = filter(None, map(lambda file: file.strip(), file_names))
        # Get file type
        elements = soup.find_all('div')
        for i, row in enumerate(elements):
            text = row.text.strip()
            if text.startswith('File type'):
                info['filetype'] = elements[i].text[10:].strip()
        # Get original name
        elements = soup.find_all('div')
        for i, row in enumerate(elements):
            text = row.text.strip()
            if text.startswith('Original name'):
                info['origname'] = elements[i].text[15:].strip()
        # Get copyright
        elements = soup.find_all('div')
        for i, row in enumerate(elements):
            text = row.text.strip()
            if text.startswith('Copyright'):
                if u'floated-field-key' in elements[i].attrs['class']:
                    info['copyright'] = elements[i+1].text.strip()
        # Get description
        elements = soup.find_all('div')
        for i, row in enumerate(elements):
            text = row.text.strip()
            if text.startswith('Description'):
                info['description'] = elements[i].text[13:].strip()
        # Get signer
        elements = soup.find_all('div')
        for i, row in enumerate(elements):
            text = row.text.strip()
            if text.startswith('Signers'):
                info['signer'] = elements[i].text[10:].strip().split('\n')[0].lstrip('[+] ')
        # Get additional information
        elements = soup.findAll("div", {"class": "enum"})
        for i, row in enumerate(elements):
            text = row.text.strip()
            if 'First submission' in text:
                first_submission_raw = elements[i].text.strip().split("\n")
                info['firstsubmission'] = first_submission_raw[1].strip()
            if 'imphash' in text:
                info['imphash'] = elements[i].text.strip().split("\n")[-1].strip()
        # Comments
        comment_num = soup.findAll("span", {"class": "badge-info"})
        if comment_num:
            info['comments'] = comment_num[0].text
        commenter_raw = soup.findAll("div", {"class": "comment-signature"})
        comment_content = BeautifulSoup(str(commenter_raw), 'html.parser')
        commenter = comment_content.findAll("a")
        if commenter:
            commenters = []
            for c in commenter:
                if c.text not in commenters:
                    commenters.append(c.text)
            info['commenter'] = ", ".join(commenters[:10])
        # Harmless
        if "Probably harmless!" in source_code:
            info['harmless'] = True
        # Signed
        if "Signed file, verified signature" in source_code:
            info['signed'] = True
        # Revoked
        if "revoked by its issuer" in source_code:
            info['revoked'] = True
        # Expired
        if "Expired certificate" in source_code:
            info['expired'] = True
        # Microsoft Software
        if "This file belongs to the Microsoft Corporation software catalogue." in source_code:
            info['mssoft'] = True
    except Exception as e:
        if debug:
            traceback.print_exc()
    finally:
        # Return the info dictionary
        return info


def commentVTSample(resource, comment):
    """
    Posts a comment on a certain sample
    :return:
    """
    params = {
        'apikey': VT_PUBLIC_API_KEY,
        'resource': resource,
        'comment': comment
    }
    response = requests.post('https://www.virustotal.com/vtapi/v2/comments/put', params=params)
    response_json = response.json()
    if response_json['response_code'] != 1:
        print("[E] Error posting comment: %s" % response_json['verbose_msg'])
    else:
        printHighlighted("SUCCESSFULLY COMMENTED")


def getMalShareInfo(hash):
    """
    Retrieves information from MalwareShare https://malshare.com
    :param hash: hash value
    :return info: info object
    """
    info = {'malshare_available': False}
    # Prepare API request
    parameters_query = {"query": hash, "api_key": MAL_SHARE_API_KEY, "action": 'search'}
    parameters_details = {"hash": hash, "api_key": MAL_SHARE_API_KEY, "action": 'details'}
    try:
        response_query = requests.get(MAL_SHARE_URL, params=parameters_query)
        if args.debug:
            print("[D] Querying Malshare: %s" % response_query.request.url)
        #print response_query.content.rstrip('\n')
        # If response is MD5 hash
        if re.match(r'^[a-f0-9]{32}$', response_query.content.decode("utf-8").rstrip('\n')):
            info['malshare_available'] = True
            parameters_details['hash'] = response_query.content.decode("utf-8").rstrip('\n')
            #print parameters_details
            response_details = requests.get(MAL_SHARE_URL, params=parameters_details)
            #print response_details.content
        else:
            info['malshare_available'] = False
            if args.debug:
                print("[D] Malshare response: %s" % response_query.content)
    except Exception as e:
        if args.debug:
            traceback.print_exc()
    return info


def getMISPInfo(hash):
    """
    Retrieves information from a MISP instance
    :param hash: hash value
    :return info: info object
    """
    info = {'misp_available': False, 'misp_events': ''}
    requests.packages.urllib3.disable_warnings()  # I don't care
    # Check if any auth key is set
    key_set = False
    for m in MISP_AUTH_KEYS:
        if m != '' and m != '-':
            key_set = True
    if not key_set or 'pymisp' in deactivated_features:
        return info

    # Loop through MISP instances
    misp_info = []
    misp_events = []
    for c, m_url in enumerate(MISP_URLS, start=0):
        # Get the corresponding auth key
        m_auth_key = MISP_AUTH_KEYS[c]
        if args.debug:
            print("[D] Querying MISP: %s" % m_url)
        try:
            # Preparing API request
            misp = PyMISP(m_url, m_auth_key, args.verifycert, 'json')
            if args.debug:
                print("[D] Query: values=%s" % hash)
            result = misp.search('attributes', values=[hash])
            if result['response']:
                events_added = list()
                if args.debug:
                    print(json.dumps(result['response']))
                for r in result['response']["Attribute"]:
                    # Check for duplicates
                    if r['event_id'] in events_added:
                        continue
                    # Try to get info on the events
                    event_info = ""
                    misp_events.append('MISP%d:%s' % (c+1, r['event_id']))
                    e_result = misp.search('events', eventid=r['event_id'])
                    if e_result['response']:
                        event_info = e_result['response'][0]['Event']['info']
                        # too much
                        #if args.debug:
                        #    print(json.dumps(e_result['response']))
                    # Create MISP info object
                    misp_info.append({
                        'misp_nr': c+1,
                        'event_info': event_info,
                        'event_id': r['event_id'],
                        'comment': r['comment'],
                        'url': '%s/events/view/%s' % (m_url, r['event_id'])
                    })
                    events_added.append(r['event_id'])

            else:
                info['misp_available'] = False
        except Exception as e:
            if args.debug:
                traceback.print_exc()

    info['misp_info'] = misp_info
    info['misp_events'] = ", ".join(misp_events)
    if len(misp_events) > 0:
        info['misp_available'] = True

    return info


def getHybridAnalysisInfo(hash):
    """
    Retrieves information from Payload Security's public sandbox https://www.hybrid-analysis.com
    :param hash: hash value
    :return info: info object
    """
    info = {'hybrid_available': False, 'hybrid_score': '-', 'hybrid_date': '-', 'hybrid_compromised': '-'}
    try:
        # Prepare request
        preparedURL = "%s/%s" % (HYBRID_ANALYSIS_URL, hash)
        # Set user agent string
        headers = {'User-Agent': 'VxStream'}
        # Querying Hybrid Analysis
        if args.debug:
            print("[D] Querying Hybrid Analysis: %s" % preparedURL)
        response = requests.get(preparedURL, headers=headers,
                                auth=HTTPBasicAuth(PAYLOAD_SEC_API_KEY, PAYLOAD_SEC_API_SECRET))
        res_json = response.json()
        # If response has content
        info['hybrid_available'] = False
        if res_json['response_code'] == 0:
            if len(res_json['response']) > 0:
                info['hybrid_available'] = True
                if 'threatscore' in res_json['response'][0]:
                    info['hybrid_score'] = res_json['response'][0]['threatscore']
                if 'analysis_start_time' in res_json['response'][0]:
                    info['hybrid_date'] = res_json['response'][0]['analysis_start_time']
                if 'compromised_hosts' in res_json['response'][0]:
                    info['hybrid_compromised'] = res_json['response'][0]['compromised_hosts']
    except Exception as e:
        print("Error while accessing Hybrid Analysis: %s" % response.content)
        if args.debug:
            traceback.print_exc()
    finally:
        return info

def downloadHybridAnalysisSample(hash):
    """
    Downloads Sample from https://www.hybrid-analysis.com
    :param hash: sha256 hash value
    :return success: bool Download Success
    """
    info = {'hybrid_score': '-', 'hybrid_date': '-', 'hybrid_compromised': '-'}
    try:
        # Prepare request
        preparedURL = "%s/sample-dropped-files/%s" % (HYBRID_ANALYSIS_DOWNLOAD_URL, hash)
        # Set user agent string
        headers = {'User-Agent': 'VxStream'}
        # Prepare Output filename and write the zip
        outfile = "%s.zip" % os.path.join(args.d, hash)

        # Querying Hybrid Analysis
        if args.debug:
            print("[D] Requesting Downloadsample: %s" % preparedURL)
        response = requests.get(preparedURL, params={'environmentId':'100'}, headers=headers,
                                auth=HTTPBasicAuth(PAYLOAD_SEC_API_KEY, PAYLOAD_SEC_API_SECRET))

        # If the response is a json file
        if response.headers["Content-Type"] == "application/json":
            responsejson = json.loads(response.text)
            if args.debug:
                print("[D] Something went wrong: " +responsejson["response"]["error"])
            return False
        # If the content is an octet stream
        elif response.headers["Content-Type"] == "application/octet-stream":
            
            f_out = open(outfile, 'wb')
            f_out.write(response.content)
            f_out.close()
            print("[+] Successfully downloaded sample and dropped files to: %s" % outfile)

            # Return successful
            return True

    except Exception as e:
        print("Error while accessing Hybrid Analysis: %s" % response.content)
        if args.debug:
            traceback.print_exc()
    finally:
        return False


def getTotalHashInfo(sha1):
    """
    Retrieves information from Totalhash https://totalhash.cymru.com
    :param hash: hash value
    :return info: info object
    """
    info = {'totalhash_available': False}
    try:
        # Prepare request
        preparedURL = "%s?%s" % (TOTAL_HASH_URL, sha1)
        # Set user agent string
        # headers = {'User-Agent': ''}
        # Querying Hybrid Analysis
        if args.debug:
            print("[D] Querying Totalhash: %s" % preparedURL)
        response = requests.get(preparedURL)
        # print "Respone: '%s'" % response.content
        if response.content and \
                        '0 of 0 results' not in response.content and \
                        'Sorry something went wrong' not in response.content:
            info['totalhash_available'] = True
    except Exception as e:
        print("Error while accessing Totalhash: %s" % response.content)
        if args.debug:
            traceback.print_exc()
    return info


def getURLhaus(md5, sha256):
    """
    Retrieves information from URLhaus https://urlhaus-api.abuse.ch/#download-sample
    :param md5: hash value
    :param sha256: hash value
    :return info: info object
    """
    info = {'urlhaus_available': False}
    try:
        data = {}
        if sha256:
            data = {"sha256_hash": sha256}
        else:
            data = {"md5_hash": md5}
        response = requests.post(URL_HAUS_URL, data=data)
        # print("Respone: '%s'" % response.json())
        res = response.json()
        if res['query_status'] == "ok" and res['md5_hash']:
            info['urlhaus_available'] = True
            info['urlhaus_type'] = res['file_type']
            info['urlhaus_url_count'] = res['url_count']
            info['urlhaus_first'] = res['firstseen']
            info['urlhaus_last'] = res['lastseen']
            info['urlhaus_download'] = res['urlhaus_download']
            info['urlhaus_urls'] = res['urls']
    except Exception as e:
        print("Error while accessing URLhaus")
        if args.debug:
            traceback.print_exc()
    return info


def getCAPE(md5):
    """
    Retrieves information from CAPE
    :param md5: hash value
    :return info: info object
    """
    info = {'cape_available': False}
    try:
        data = {"option": "md5", "argument": md5}
        response = requests.post(URL_CAPE, data=data)
        # print("Response: '%s'" % response.json())
        res = response.json()
        if not res['error'] and len(res['data']) > 0:
            info['cape_available'] = True
            info['cape_reports'] = res['data']
    except Exception as e:
        print("Error while accessing CAPE")
        if args.debug:
            traceback.print_exc()
    return info


def getAnyRun(sha256):
    """
    Retrieves information from AnyRun Service
    :param sha256: hash value
    :return info: info object
    """
    info = {'anyrun_available': False}
    try:
        response = requests.get(URL_ANYRUN % sha256)
        # print(response.status_code)
        # print(response.content)
        if response.status_code == 200:
            info['anyrun_available'] = True
    except Exception as e:
        print("Error while accessing AnyRun: %s" % response.content)
        if args.debug:
            traceback.print_exc()
    return info


def getVirusBayInfo(hash):
    """
    Retrieves information from VirusBay https://beta.virusbay.io/
    :param hash: hash value
    :return info: info object
    """
    info = {'virusbay_available': False}
    try:
        # Prepare request
        preparedURL = "%s%s" % (VIRUSBAY_URL, hash)
        if args.debug:
            print("[D] Querying Virusbay: %s" % preparedURL)
        response = requests.get(preparedURL).json()
        # If response has the correct content
        info['virusbay_available'] = False
        #print(response)
        tags = []
        if response['search'] != []:
            info['virusbay_available'] = True
            for tag in response['search'][0]['tags']:
                tags.append(tag['name'])
            info['vb_tags'] = tags
            info['vb_link'] = "https://beta.virusbay.io/sample/browse/%s" % response['search'][0]['md5']
    except Exception as e:
        if args.debug:
            print("Error while accessing VirusBay")
            traceback.print_exc()
    return info


def extraChecks(info, infos, cache):
    """
    Performs certain comparison checks on the given info object compared to past
    evaluations from the current batch and cache
    :param info:
    :param infos:
    :param cache:
    :return:
    """
    # Some static values
    SIGNER_WHITELIST = ["Microsoft Windows", "Microsoft Corporation"]
    # Imphash check
    imphash_count = 0
    for i in infos:
        if 'imphash' in i:
            if i['imphash'] != "-" and i['imphash'] == info['imphash']:
                imphash_count += 1
    if imphash_count > 0:
        printHighlighted("[!] Imphash - appeared %d times in this batch %s" %
                         (imphash_count, info['imphash']))
    try:
        # MISP results
        if 'misp_available' in info:
            if info['misp_available']:
                for e in info['misp_info']:
                    printHighlighted("[!] MISP event found EVENT_ID: {0} EVENT_INFO: {1} URL: {2}".format(
                        e['event_id'], e['event_info'], e['url'])
                    )
    except KeyError as e:
        if args.debug:
            traceback.print_exc()
    try:
        # Malware Share availability
        if 'malshare_available' in info:
            if info['malshare_available']:
                printHighlighted("[!] Sample is available on malshare.com")
    except KeyError as e:
        if args.debug:
            traceback.print_exc()
    try:
        # Hybrid Analysis availability
        if 'hybrid_available' in info:
            if info['hybrid_available']:
                printHighlighted("[!] Sample is on hybrid-analysis.com SCORE: {0} DATE: {1} HOSTS: {2}".format(
                    info["hybrid_score"], info["hybrid_date"], ", ".join(info['hybrid_compromised'])
            ))
    except KeyError as e:
        if args.debug:
            traceback.print_exc()
    try:
        # URLhaus availability
        if 'urlhaus_available' in info:
            if info['urlhaus_available']:
                printHighlighted("[!] Sample on URLHaus Download: %s" % info['urlhaus_download'])
                printHighlighted("[!] URLHaus info TYPE: %s FIRST_SEEN: %s LAST_SEEN: %s URL_COUNT: %s" % (
                    info['urlhaus_type'],
                    info['urlhaus_first'],
                    info['urlhaus_last'],
                    info['urlhaus_url_count']
                ))
                c = 0
                for url in info['urlhaus_urls']:
                    printHighlighted("[!] URLHaus STATUS: %s URL: %s" % (url['url_status'], url['url']))
                    c += 1
                    if c > URL_HAUS_MAX_URLS:
                        break
    except KeyError as e:
        if args.debug:
            traceback.print_exc()
    try:
        # AnyRun availability
        if 'anyrun_available' in info:
            if info['anyrun_available']:
                printHighlighted("[!] Sample on ANY.RUN URL: %s" % (URL_ANYRUN % info['sha256']))
    except KeyError as e:
        if args.debug:
            traceback.print_exc()
    try:
        # CAPE availability
        if 'cape_available' in info:
            if info['cape_available']:
                c = 0
                for r in info['cape_reports']:
                    printHighlighted("[!] Sample on CAPE sandbox URL: https://cape.contextis.com/analysis/%s/" % r)
                    c += 1
                    if c > CAPE_MAX_REPORTS:
                        break
    except KeyError as e:
        if args.debug:
            traceback.print_exc()
    # # Totalhash availability
    # if info['totalhash_available']:
    #     printHighlighted("[!] Sample is available on https://totalhash.cymru.com")
    try:
        # VirusBay availability
        if info['virusbay_available']:
            printHighlighted("[!] Sample is on VirusBay "
                             "URL: %s TAGS: %s" % (info['vb_link'], ", ".join(info['vb_tags'])))
    except KeyError as e:
        if args.debug:
            traceback.print_exc()
    # Signed Appeared multiple times
    try:
        signer_count = 0
        for s in infos:
            if 'signer' in s:
                if s['signer'] != "-" and s['signer'] and s['signer'] == info['signer'] and \
                        not any(s in info['signer'] for s in SIGNER_WHITELIST):
                    signer_count += 1
        if signer_count > 0:
            printHighlighted("[!] Signer - appeared %d times in this batch %s" %
                             (signer_count, info['signer'].encode('raw-unicode-escape')))
    except KeyError as e:
        if args.debug:
            traceback.print_exc()


def printResult(info, count, total):
    """
    prints the result block
    :param info: all collected info
    :param count: counter (number of samples checked)
    :param total: total number of lines to check
    :return:
    """
    # Rating and Color
    info["rating"] = "unknown"
    info["res_color"] = Back.CYAN

    # If VT returned results
    if "vt_total" in info:
        info["rating"] = "clean"
        info["res_color"] = Back.GREEN
        if info["vt_positives"] > 0:
            info["rating"] = "suspicious"
            info["res_color"] = Back.YELLOW
        if info["vt_positives"] > 10:
            info["rating"] = "malicious"
            info["res_color"] = Back.RED

    # Head line
    printSeparator(count, total, info['res_color'], info["rating"])
    printHighlighted("HASH: {0} COMMENT: {1}".format(info["hash"], info['comment']))

    # More VT info
    if "vt_total" in info:
        # Result
        info["result"] = "%s / %s" % (info["vt_positives"], info["vt_total"])
        if info["virus"] != "-":
            printHighlighted("VIRUS: {0}".format(info["virus"]))
        printHighlighted("TYPE: {1} FILENAMES: {0}".format(removeNonAsciiDrop(info["filenames"]),
                                                           info['filetype']))
        # Extra Info
        printPeInfo(info)
        printHighlighted("FIRST: {0} LAST: {1} COMMENTS: {2} USERS: {3}".format(
            info["first_submitted"], info["last_submitted"], info["comments"], info["commenter"]))

    else:
        if args.debug:
            printHighlighted("VERBOSE_MESSAGE: %s" % info['vt_verbose_msg'])

    # Tags to show
    tags = ""
    for t in TAGS:
        tl = t.lower()
        if tl in info:
            if info[tl]:
                tags += " %s" % t

    # Print the highlighted result line
    printHighlighted("RESULT: %s%s" % (info["result"], tags), hl_color=info["res_color"])


def printVerificationResult(sigName, vResults):
    """
    prints the result of a retrohunt verification
    :param sigName: signature name
    :param vResults: dictionary with verification results
    :return:
    """
    # Color
    res_color = Back.CYAN
    # Average positives
    avgPositives = sum(vResults['positives']) / float(len(vResults['positives']))

    if avgPositives > 10:
        res_color = Back.RED
    if avgPositives > 10:
        res_color = Back.YELLOW
    if vResults['clean'] > 0:
        res_color = Back.YELLOW
    if vResults['suspicious'] == 0 and vResults['malicious'] == 0:
        res_color = Back.GREEN

    # Print the highlighted result line
    printHighlighted("VERIFIED_SIG: %s AVG_POS: %.2f" % (sigName, avgPositives), hl_color=res_color)


def printHighlighted(line, hl_color=Back.WHITE):
    """
    Print a highlighted line
    """
    # Tags
    colorer = re.compile('(HARMLESS|SIGNED|MS_SOFTWARE_CATALOGUE|MSSOFT|SUCCESSFULLY\sCOMMENTED)', re.VERBOSE)
    line = colorer.sub(Fore.BLACK + Back.GREEN + r'\1' + Style.RESET_ALL + ' ', line)
    colorer = re.compile('(REVOKED)', re.VERBOSE)
    line = colorer.sub(Fore.BLACK + Back.RED + r'\1' + Style.RESET_ALL + ' ', line)
    colorer = re.compile('(EXPIRED)', re.VERBOSE)
    line = colorer.sub(Fore.BLACK + Back.YELLOW + r'\1' + Style.RESET_ALL + ' ', line)
    # Extras
    colorer = re.compile('(\[!\])', re.VERBOSE)
    line = colorer.sub(Fore.BLACK + Back.LIGHTMAGENTA_EX + r'\1' + Style.RESET_ALL + '', line)
    # Add line breaks
    colorer = re.compile('(ORIGNAME:)', re.VERBOSE)
    line = colorer.sub(r'\n\1', line)
    # Standard
    colorer = re.compile('([A-Z_]{2,}:)\s', re.VERBOSE)
    line = colorer.sub(Fore.BLACK + hl_color + r'\1' + Style.RESET_ALL + ' ', line)
    print(line)


def printSeparator(count, total, color, rating):
    """
    Print a separator line status infos
    :param count:
    :param total:
    :return:
    """
    print(Fore.BLACK + color)
    print(" {0} / {1} > {2}".format(count+1, total, rating.title()).ljust(80) + Style.RESET_ALL)


def printPeInfo(sample_info):
    """
    Prints PE information in a clever form
    :param peInfo:
    :return:
    """
    peInfo = [u'origname', u'description', u'copyright', u'signer']
    outString = []
    for k, v in viewitems(sample_info):
        if k in peInfo:
            if v is not '-':
                outString.append("{0}: {1}".format(k.upper(), removeNonAsciiDrop(v)))
    if " ".join(outString):
        printHighlighted(" ".join(outString))

def saveCache(cache, fileName):
    """
    Saves the cache database as pickle dump to a file
    :param cache:
    :param fileName:
    :return:
    """
    with open(fileName, 'w') as fh:
        fh.write(json.dumps(cache))


def loadCache(fileName):
    """
    Load cache database as json dump from file
    :param fileName:
    :return:
    """
    try:
        with open(fileName, 'r') as fh:
            return json.load(fh), True
    except Exception as e:
        # traceback.print_exc()
        return [], False


def removeNonAsciiDrop(string):
    nonascii = "error"
    # print "CON: ", string
    try:
        # Generate a new string without disturbing characters and allow new lines
        # Python 2 method
        try:
            nonascii = "".join(i for i in string if (ord(i) < 127 and ord(i) > 31) or ord(i) == 10 or ord(i) == 13)
        except Exception as e:
            # Python 3 fallback
            return string
    except Exception as e:
        traceback.print_exc()
        pass
    return nonascii


def inCache(hashVal):
    """
    Check if a sample with a certain hash has already been checked and return the info if true
    :param hashVal: hash value used as reference
    :return: cache element or None
    """
    if not hashVal:
        return None
    for c in cache:
        if c['hash'] == hashVal or c['md5'] == hashVal or c['sha1'] == hashVal or c['sha256'] == hashVal:
            return c
    return None


def knownValue(infos, key, value):
    """
    Checks if a value of a given key appears in a previously checked info and
    returns the info if the value matches
    :param infos:
    :param key:
    :param value:
    :return: info
    """
    for i in infos:
        if i[key] == value:
            return i
    return None


def generateResultFilename(inputFileName):
    """
    Generate a result file name based on the input name
    :param inputName: name of the processed file
    :return alreadyExists: returns True if the file already exists
    :return resultFile: name of the output file
    """
    alreadyExists = False
    resultFile = "check-results_{0}.csv".format(os.path.splitext(os.path.basename(inputFileName))[0])
    if os.path.exists(resultFile):
        print("[+] Found results CSV from previous run: {0}".format(resultFile))
        print("[+] Appending results to file: {0}".format(resultFile))
        alreadyExists = True
    else:
        print("[+] Writing results to new file: {0}".format(resultFile))
    return alreadyExists, resultFile


def writeCSV(info, resultFile):
    """
    Write info line to CSV
    :param info:
    :return:
    """
    try:
        with codecs.open(resultFile, 'a', encoding='utf8') as fh_results:
            # Print every field from the field list to the output file
            for field_pretty in CSV_FIELD_ORDER:
                field = CSV_FIELDS[field_pretty]
                try:
                    field = info[field]
                except KeyError as e:
                    field = "False"
                try:
                    field = str(field).replace(r'"', r'\"').replace("\n", " ")
                except AttributeError as e:
                    if args.debug:
                        traceback.print_exc()
                    pass
                fh_results.write("%s;" % field)
            # Append vendor scan results
            for vendor in VENDORS:
                if vendor in info['vendor_results']:
                    fh_results.write("%s;" % info['vendor_results'][vendor])
                else:
                    fh_results.write("-;")
            fh_results.write('\n')
    except:
        if args.debug:
            traceback.print_exc()
        return False
    return True


def writeCSVHeader(resultFile):
    """
    Writes a CSV header line into the results file
    :param resultFile:
    :return:
    """
    try:
        with open(resultFile, 'w') as fh_results:
            fh_results.write("%s;" % ";".join(CSV_FIELD_ORDER))
            fh_results.write("%s;\n" % ";".join(VENDORS))
    except Exception as e:
        print("[E] Cannot write export file {0}".format(resultFile))


def getFileData(filePath):
    """
    Get the content of a given file
    :param filePath:
    :return fileData:
    """
    fileData = ""
    try:
        # Read file complete
        with open(filePath, 'rb') as f:
            fileData = f.read()
    except Exception as e:
        traceback.print_exc()
    finally:
        return fileData


def generateHashes(fileData):
    """
    Generates hashes for a given blob of data
    :param filedata:
    :return hashes:
    """
    hashes = {'md5': '', 'sha1': '', 'sha256': ''}
    try:
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        md5.update(fileData)
        sha1.update(fileData)
        sha256.update(fileData)
        hashes = {'md5': md5.hexdigest(), 'sha1': sha1.hexdigest(), 'sha256': sha256.hexdigest()}
    except Exception as e:
        traceback.print_exc()
    finally:
        return hashes


def checkPhantomJS():
    if 'selenium' in deactivated_features:
        return False
    try:
        browser = webdriver.PhantomJS()
        return True
    except Exception as e:
        print("Error: PhantomJS not found, Requests as fallback used. Some field may not be populated.")
        print("       To improve the analysis process, install http://phantomjs.org/download.html")
        return False

def signal_handler(signal, frame):
    if not args.nocache:
        print("\n[+] Saving {0} cache entries to file {1}".format(len(cache), args.c))
        saveCache(cache, args.c)
    sys.exit(0)


if __name__ == '__main__':

    init(autoreset=False)

    print(Style.RESET_ALL)
    print(Fore.BLACK + Back.WHITE)
    print("   _________   _    _   ______  _____  ______          ".ljust(80))
    print("  | | | | | \ | |  | | | |  \ \  | |  | |  \ \     /.) ".ljust(80))
    print("  | | | | | | | |  | | | |  | |  | |  | |  | |    /)\| ".ljust(80))
    print("  |_| |_| |_| \_|__|_| |_|  |_| _|_|_ |_|  |_|   // /  ".ljust(80))
    print("                                                /'\" \"  ".ljust(80))
    print(" ".ljust(80))
    print("  Online Hash Checker for Virustotal and Other Services".ljust(80))
    print(("  " + __AUTHOR__ + " - " + __VERSION__ + "").ljust(80))
    print(" ".ljust(80) + Style.RESET_ALL)
    print(Style.RESET_ALL + " ")

    parser = argparse.ArgumentParser(description='Online Hash Checker')
    parser.add_argument('-f', help='File to process (hash line by line OR csv with hash in each line - auto-detects '
                                   'position and comment)', metavar='path', default='')
    parser.add_argument('-c', help='Name of the cache database file (default: vt-hash-db.pkl)', metavar='cache-db',
                        default='vt-hash-db.json')
    parser.add_argument('-i', help='Name of the ini file that holds the API keys', metavar='ini-file',
                        default=os.path.dirname(os.path.abspath(__file__)) + '/munin.ini')
    parser.add_argument('-s', help='Folder with samples to process', metavar='sample-folder',
                        default='')
    parser.add_argument('--comment', action='store_true', help='Posts a comment for the analysed hash which contains '
                                                               'the comment from the log line', default=False)
    parser.add_argument('-p', help='Virustotal comment prefix', metavar='vt-comment-prefix',
                        default='Munin Analyzer Run:\n')

    parser.add_argument('--download', action='store_true', help='Enables Sample Download from Hybrid Analysis. SHA256 of sample needed.', default=False)
    parser.add_argument('-d', help='Output Path for Sample Download from Hybrid Analysis. Folder must exist', metavar='download_path',default='./')

    parser.add_argument('--nocache', action='store_true', help='Do not use cache database file', default=False)
    parser.add_argument('--intense', action='store_true', help='Do use PhantomJS to parse the permalink '
                                                               '(used to extract user comments on samples)',
                        default=False)
    parser.add_argument('--retroverify', action='store_true', help='Check only 40 entries with the same comment and the'
                                                                   'rest at the end of the run (retrohunt verification)',
                        default=False)
    parser.add_argument('-r', help='Number of results to take as verification', metavar='num-results',
                        default=40)
    parser.add_argument('--nocsv', action='store_true', help='Do not write a CSV with the results', default=False)
    parser.add_argument('--verifycert', action='store_true', help='Verify SSL/TLS certificates', default=False)
    parser.add_argument('--sort', action='store_true', help='Sort the input lines (useful for VT retrohunt results)', default=False)
    parser.add_argument('--debug', action='store_true', default=False, help='Debug output')

    args = parser.parse_args()

    # Intense Mode
    intense_mode = False
    if args.intense:
        # Check for PhantomJS
        intense_mode = checkPhantomJS()

    # Read the config file
    config = configparser.ConfigParser()
    try:
        config.read(args.i)
        VT_PUBLIC_API_KEY = config['DEFAULT']['VT_PUBLIC_API_KEY']
        MAL_SHARE_API_KEY = config['DEFAULT']['MAL_SHARE_API_KEY']
        PAYLOAD_SEC_API_KEY = config['DEFAULT']['PAYLOAD_SEC_API_KEY']
        PAYLOAD_SEC_API_SECRET = config['DEFAULT']['PAYLOAD_SEC_API_SECRET']

        # MISP config
        fall_back = False
        try:
            MISP_URLS = ast.literal_eval(config.get('MISP', 'MISP_URLS'))
            MISP_AUTH_KEYS = ast.literal_eval(config.get('MISP','MISP_AUTH_KEYS'))
        except Exception as e:
            if args.debug:
                traceback.print_exc()
            print("[E] Since munin v0.13.0 you're able to define multiple MISP instances in config. The new .ini "
                  "expects the MISP config lines to contain lists (see munin.ini). Falling back to old config format.")
            fall_back = True

        # Fallback to old config
        if fall_back:
            MISP_URLS = list([config.get('MISP', 'MISP_URL')])
            MISP_AUTH_KEYS = list([config.get('MISP', 'MISP_API_KEY')])

    except Exception as e:
        traceback.print_exc()
        print("[E] Config file '%s' not found" % args.i)

    # Check API Key
    if VT_PUBLIC_API_KEY == '' or not re.match(r'[a-fA-F0-9]{64}', VT_PUBLIC_API_KEY):
        print("[E] No API Key set or wrong format")
        print("    Include your API key in the header section of the script (API_KEY)\n")
        print("    More info:")
        print("    https://www.virustotal.com/en/faq/#virustotal-api\n")
        sys.exit(1)

    # Check input file
    if args.f == '' and args.s == '':
        print("[E] Please provide an input file with '-f inputfile' or a sample directory to process '-s sample-dir'\n")
        parser.print_help()
        sys.exit(1)
    if not os.path.exists(args.f) and not os.path.exists(args.s):
        print("[E] Cannot find input file {0}".format(args.f))
        sys.exit(1)

    # Trying to load cache from pickle dump
    cache, success = loadCache(args.c)
    if not args.nocache:
        if success:
            print("[+] {0} cache entries read from cache database: {1}".format(len(cache), args.c))
        else:
            print("[-] No cache database found")
            print("[+] Analyzed hashes will be written to cache database: {0}".format(args.c))
        print("[+] You can always interrupt the scan by pressing CTRL+C without losing the scan state")

    # Open input file
    if args.f:
        # Generate a result file name
        alreadyExists, resultFile = generateResultFilename(args.f)
        try:
            with open(args.f, 'r') as fh:
                lines = fh.readlines()
        except Exception as e:
            print("[E] Cannot read input file")
            sys.exit(1)
    if args.s:
        # Generate a result file name
        pathComps = args.s.split(os.sep)
        if pathComps[-1] == "":
            del pathComps[-1]
        alreadyExists, resultFile = generateResultFilename(pathComps[-1])
        # Empty lines container
        lines = []
        for root, directories, files in os.walk(args.s, followlinks=False):
            for filename in files:
                try:
                    filePath = os.path.join(root, filename)
                    print("[ ] Processing %s ..." % filePath)
                    fileData = getFileData(filePath)
                    hashes = generateHashes(fileData)
                    # Add the results as a line for processing
                    lines.append("{0} {1}".format(hashes["sha256"], filePath))
                except Exception as e:
                    traceback.print_exc()

    # Write a CSV header
    if not args.nocsv and not alreadyExists:
        writeCSVHeader(resultFile)

    # Now add a signal handler so that no results get lost
    signal.signal(signal.SIGINT, signal_handler)

    # Process the input lines
    try:
        processLines(lines, resultFile, args.nocsv, args.debug)
    except UnicodeEncodeError as e:
        print("[E] Error while processing some of the values due to unicode decode errors. "
              "Try using python3 instead of version 2.")

    # Write Cache
    if not args.nocsv:
        print("\n[+] Results written to file {0}".format(resultFile))
    print("\n[+] Saving {0} cache entries to file {1}".format(len(cache), args.c))

    # Don't save cache if cache shouldn't be used
    if not args.nocache:
        saveCache(cache, args.c)

    print(Style.RESET_ALL)

