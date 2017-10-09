#!/usr/bin/env python2.7

__AUTHOR__ = 'Florian Roth'
__VERSION__ = "0.1 October 2017"

"""
Install dependencies with:
pip install requests bs4 colorama pickle
"""

import configparser
import requests
import time
import re
import os
import signal
import sys
import pickle
from bs4 import BeautifulSoup
import traceback
import argparse
from colorama import init, Fore, Back, Style

# CONFIG ##############################################################

VENDORS = ['Microsoft', 'Kaspersky', 'McAfee', 'CrowdStrike', 'TrendMicro',
           'ESET-NOD32', 'Symantec', 'F-Secure', 'Sophos', 'GData']
VT_PUBLIC_API_KEY = '-'
MAL_SAHRE_API_KEY = '-'
WAIT_TIME = 15  # Public API allows 4 request per minute, so we wait 15 secs by default

CSV_FIELD_ORDER = ['Lookup Hash', 'Rating', 'Comment', 'Positives', 'Virus', 'File Names', 'First Submitted',
                   'Last Submitted', 'File Type', 'MD5', 'SHA1', 'SHA256', 'Imphash', 'Harmless', 'Signed', 'Revoked',
                   'Expired', 'Trusted']

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
              'Signed': 'signed',
              'Revoked': 'revoked',
              'Expired': 'expired',
              'Trusted': 'mssoft',
              }

TAGS = ['HARMLESS', 'SIGNED', 'MSSOFT', 'REVOKED', 'EXPIRED']

# VirusTotal URL
VT_REPORT_URL = 'https://www.virustotal.com/vtapi/v2/file/report'
# MalwareShare URL
MAL_SHARE_URL = 'http://malshare.com/api.php'


def fetchHash(line):
    pattern = r'(?<!FIRSTBYTES:\s)\b([0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})\b'
    hash_search = re.findall(pattern, line)
    if len(hash_search) > 0:
        hash = hash_search[-1]
        rest = ' '.join(re.sub('({0}|;|,|:)'.format(hash), ' ', line).strip().split())

        return hash, rest
    return '', ''


def printHighlighted(line, hl_color=Back.WHITE):
    """
    Print a highlighted line
    """
    # Tags
    colorer = re.compile('(HARMLESS|SIGNED|MS_SOFTWARE_CATALOGUE)', re.VERBOSE)
    line = colorer.sub(Fore.BLACK + Back.GREEN + r'\1' + Style.RESET_ALL + ' ', line)
    colorer = re.compile('(SIG_REVOKED)', re.VERBOSE)
    line = colorer.sub(Fore.BLACK + Back.RED + r'\1' + Style.RESET_ALL + ' ', line)
    colorer = re.compile('(SIG_EXPIRED)', re.VERBOSE)
    line = colorer.sub(Fore.BLACK + Back.YELLOW + r'\1' + Style.RESET_ALL + ' ', line)
    # Extras
    colorer = re.compile('(\[!\])', re.VERBOSE)
    line = colorer.sub(Fore.BLACK + Back.CYAN + r'\1' + Style.RESET_ALL + ' ', line)
    # Standard
    colorer = re.compile('([A-Z_]{2,}:)\s', re.VERBOSE)
    line = colorer.sub(Fore.BLACK + hl_color + r'\1' + Style.RESET_ALL + ' ', line)
    print line


def saveCache(cache, fileName):
    """
    Saves the cache database as pickle dump to a file
    :param cache:
    :param fileName:
    :return:
    """
    with open(fileName, 'wb') as fh:
        pickle.dump(cache, fh, pickle.HIGHEST_PROTOCOL)


def loadCache(fileName):
    """
    Load cache database as pickle dump from file
    :param fileName:
    :return:
    """
    try:
        with open(fileName, 'rb') as fh:
            return pickle.load(fh), True
    except Exception, e:
        # traceback.print_exc()
        return [], False


def removeNonAsciiDrop(string):
    nonascii = "error"
    # print "CON: ", string
    try:
        # Generate a new string without disturbing characters and allow new lines
        nonascii = "".join(i for i in string if (ord(i) < 127 and ord(i) > 31) or ord(i) == 10 or ord(i) == 13)
    except Exception, e:
        traceback.print_exc()
        pass
    return nonascii


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
        "md5": "-",
        "sha1": "-",
        "sha256": "-",
        "imphash": "-",
        "harmless": "-",
        "revoked": "-",
        "signed": "-",
        "expired": "-",
        "mssoft": "-",
        "vendor_results": {},
        "signer": "",
    }

    # Prepare VT API request
    parameters = {"resource": hash, "apikey": VT_PUBLIC_API_KEY}
    success = False
    while not success:
        try:
            response_dict = requests.get(VT_REPORT_URL, params=parameters).json()
            success = True
        except Exception, e:
            if args.debug:
                traceback.print_exc()
                # print "Error requesting VT results"
            pass

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

        # Type
        sample_info["rating"] = "clean"
        sample_info["res_color"] = Back.GREEN
        if sample_info["positives"] > 0:
            sample_info["rating"] = "suspicious"
            sample_info["res_color"] = Back.YELLOW
        if sample_info["positives"] > 10:
            sample_info["rating"] = "malicious"
            sample_info["res_color"] = Back.RED

        # Get more information with permalink
        if args.debug:
            print "Processing permalink {0}".format(response_dict.get("permalink"))
        info = processPermalink(response_dict.get("permalink"), args.debug)

        # File Names
        sample_info["filenames"] = removeNonAsciiDrop(", ".join(info['filenames'][:5]).replace(';', '_'))
        sample_info["first_submitted"] = info['firstsubmission']
        # Other info
        sample_info.update(info)
        # Result
        sample_info["result"] = "%s / %s" % (response_dict.get("positives"), response_dict.get("total"))
        printHighlighted("VIRUS: {0}".format(sample_info["virus"]))
        filenames = ", ".join(sample_info["filenames"])
        printHighlighted("FILENAMES: {0}".format(filenames.encode('raw-unicode-escape')))
        if sample_info['signer']:
            printHighlighted("SIGNER: {0}".format(sample_info['signer'].encode('raw-unicode-escape')))
        printHighlighted("FIRST_SUBMITTED: {0} LAST_SUBMITTED: {1}".format(
            sample_info["first_submitted"], sample_info["last_submitted"]))

    else:
        if args.debug:
            printHighlighted("VERBOSE_MESSAGE: %s" % response_dict['verbose_msg'])

    # Tags to show
    tags = ""
    for t in TAGS:
        tl = t.lower()
        if tl in sample_info:
            if sample_info[tl]:
                tags += " %s" % t
    # Print the highlighted result line
    printHighlighted("RESULT: %s%s" % (sample_info["result"], tags), hl_color=sample_info["res_color"])

    return sample_info


def getMalShareInfo(hash):
    """
    Retrieves information from MalwareShare https://malshare.com
    :param hash: hash value
    :return info: info object
    """
    info = {}
    # Prepare VT API request
    parameters_query = {"query": hash, "api_key": MAL_SAHRE_API_KEY, "action": 'search'}
    parameters_details = {"hash": hash, "api_key": MAL_SAHRE_API_KEY, "action": 'details'}
    try:
        response_query = requests.get(MAL_SHARE_URL, params=parameters_query)
        #print response_query.content.rstrip('\n')
        # If response is MD5 hash
        if re.match(r'^[a-f0-9]{32}$', response_query.content.rstrip('\n')):
            info['malshare_available'] = True
            parameters_details['hash'] = response_query.content.rstrip('\n')
            #print parameters_details
            response_details = requests.get(MAL_SHARE_URL, params=parameters_details)
            #print response_details.content
        else:
            info['malshare_available'] = False
            if args.debug:
                print "MalQuery response: %s" % response_query.content
    except Exception, e:
        if args.debug:
            traceback.print_exc()
    return info


def processLines(lines, resultFile, nocsv=False, dups=False, debug=False):
    """
    Process the input file line by line
    """
    # Infos of the current batch
    infos = []
    for line in lines:
        # Skip comments
        if line.startswith("#"):
            continue
        # Remove line break
        line.rstrip("\n\r")
        # Get all hashes in line
        # ... and the rest of the line as comment
        hashVal, comment = fetchHash(line)
        # If no hash found
        if hashVal == '':
            continue
        # Info dictionary
        info = None
        info = {'hash': hashVal, 'comment': comment}
        # Cache
        result = inCache(hashVal)
        if not args.nocache and result:
            if dups:
                # Colorized head of each hash check
                printHighlighted("\nHASH: {0} COMMENT: {1}".format(hashVal, comment))
                printHighlighted("RESULT: %s (from cache)" % result['hash']['result'])
            continue
        else:
            # Colorized head of each hash check
            printHighlighted("\nHASH: {0} COMMENT: {1}".format(hashVal, comment))

        # Get VirusTotal Info
        vt_info = getVTInfo(hashVal)
        ms_info = getMalShareInfo(hashVal)
        # hybrid_info

        # Add the infos to the main info dictionary
        info.update(vt_info)
        info.update(ms_info)

        # Comparison checks
        extraChecks(info, infos, cache)

        # Print to CSV
        if not nocsv:
            writeCSV(info, resultFile)
        # Add to hash cache and current batch info list
        cache.append(info)
        infos.append(info)
        # Wait some time for the next request
        time.sleep(WAIT_TIME)


def extraChecks(info, infos, cache):
    """
    Performs certain comparison checks on the given info object compared to past
    evaluations from the current batch and cache
    :param info:
    :param infos:
    :param cache:
    :return:
    """
    # Imphash check
    imphash_count = 0
    for i in infos:
        if 'imphash' in i:
            if i['imphash'] != "-" and i['imphash'] == info['imphash']:
                imphash_count += 1
    if imphash_count > 0:
        printHighlighted("[!] Imphash value appeared in %d other values of this batch" % imphash_count)
    # Malware Share availability
    if info['malshare_available']:
        printHighlighted("[!] Sample is available on Malshare.com")


def inCache(hashVal):
    """
    Check if a sample with a certain hash has already been checked and return the info if true
    :param hashVal: hash value used as reference
    :return: cache element or None
    """
    for c in cache:
        if c['hash'] == hashVal:
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
    :param inputName:
    :return: result file name
    """
    resultFile = "check-results_{0}.csv".format(os.path.splitext(os.path.basename(inputFileName))[0])
    if os.path.exists(resultFile):
        print "[+] Found results CSV from previous run: {0}".format(resultFile)
        print "[+] Appending results to file: {0}".format(resultFile)
    else:
        print "[+] Writing results to new file: {0}".format(resultFile)
    return resultFile


def writeCSV(info, resultFile):
    """
    Write info line to CSV
    :param info:
    :return:
    """
    try:
        with open(resultFile, "a") as fh_results:
            # Print every field from the field list to the output file
            for field_pretty in CSV_FIELD_ORDER:
                field = CSV_FIELDS[field_pretty]
                fh_results.write("%s;" % info[field])
            # Append vendor scan results
            for vendor in VENDORS:
                if vendor in info['vendor_results']:
                    fh_results.write("%s;" % info['vendor_results'][vendor])
                else:
                    fh_results.write("-;")
            fh_results.write('\n')
    except:
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
            fh_results.write("%s\n" % ";".join(VENDORS))
    except Exception, e:
        print "[E] Cannot write export file {0}".format(resultFile)

def processPermalink(url, debug=False):
    """
    Requests the HTML page for the sample and extracts other useful data
    that is not included in the public API
    """
    headers = {'User-Agent': 'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)',
               'Referrer': 'https://www.virustotal.com/en/'}
    info = {'filenames': ['-'], 'firstsubmission': '-', 'harmless': False, 'signed': False, 'revoked': False,
            'expired': False, 'mssoft': False, 'imphash': '-', 'filetype': '-'}
    try:
        source_code = requests.get(url, headers=headers)

        # Extract info from source code
        soup = BeautifulSoup(source_code.text, 'html.parser')
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
        # Harmless
        if "Probably harmless!" in source_code.content:
            info['harmless'] = True
        # Signed
        if "Signed file, verified signature" in source_code.content:
            info['signed'] = True
        # Revoked
        if "revoked by its issuer" in source_code.content:
            info['revoked'] = True
        # Expired
        if "Expired certificate" in source_code.content:
            info['expired'] = True
        # Microsoft Software
        if "This file belongs to the Microsoft Corporation software catalogue." in source_code.content:
            info['mssoft'] = True
    except Exception, e:
        if debug:
            traceback.print_exc()
    finally:
        # Return the info dictionary
        return info


def signal_handler(signal, frame):
    print "\n[+] Saving {0} cache entries to file {1}".format(len(cache), args.c)
    saveCache(cache, args.c)
    sys.exit(0)


if __name__ == '__main__':

    signal.signal(signal.SIGINT, signal_handler)
    init(autoreset=False)

    print Style.RESET_ALL
    print Fore.BLACK + Back.WHITE
    print " ".ljust(80)
    print "   _________   _    _   ______  _____  ______  ".ljust(80)
    print "  | | | | | \ | |  | | | |  \ \  | |  | |  \ \ ".ljust(80)
    print "  | | | | | | | |  | | | |  | |  | |  | |  | | ".ljust(80)
    print "  |_| |_| |_| \_|__|_| |_|  |_| _|_|_ |_|  |_| ".ljust(80)
    print " ".ljust(80)
    print "  Online hash checker for Virustotal and other services".ljust(80)
    print ("  " + __AUTHOR__ + " - " + __VERSION__ + "").ljust(80)
    print " ".ljust(80) + Style.RESET_ALL
    print Style.RESET_ALL + " "

    parser = argparse.ArgumentParser(description='Virustotal Online Checker')
    parser.add_argument('-f', help='File to process (hash line by line OR csv with hash in each line - auto-detects '
                                   'position and comment)', metavar='path', default='')
    parser.add_argument('-c', help='Name of the cache database file (default: vt-hash-db.pkl)', metavar='cache-db',
                        default='vt-hash-db.pkl')
    parser.add_argument('-i', help='Name of the ini file that holds the API keys', metavar='ini-file',
                        default='munin.ini')
    parser.add_argument('--nocache', action='store_true', help='Do not use cache database file', default=False)
    parser.add_argument('--nocsv', action='store_true', help='Do not write a CSV with the results', default=False)
    parser.add_argument('--dups', action='store_true', help='Do not skip duplicate hashes', default=False)
    parser.add_argument('--debug', action='store_true', default=False, help='Debug output')

    args = parser.parse_args()

    # Read the config file
    config = configparser.ConfigParser()
    try:
        config.read(args.i)
        VT_PUBLIC_API_KEY = config['DEFAULT']['VT_PUBLIC_API_KEY']
        MAL_SHARE_API_KEY = config['DEFAULT']['MAL_SHARE_API_KEY']
    except Exception, e:
        traceback.print_exc()
        print "[E] Config file '%s' not found" % args.i

    # Check API Key
    if VT_PUBLIC_API_KEY == '' or not re.match(r'[a-fA-F0-9]{64}', VT_PUBLIC_API_KEY):
        print "[E] No API Key set or wrong format"
        print "    Include your API key in the header section of the script (API_KEY)\n"
        print "    More info:"
        print "    https://www.virustotal.com/en/faq/#virustotal-api\n"
        sys.exit(1)

    # Check input file
    if args.f == '':
        print "[E] Please provide an input file with '-f inputfile'\n"
        parser.print_help()
        sys.exit(1)
    if not os.path.exists(args.f):
        print "[E] Cannot find input file {0}".format(args.f)
        sys.exit(1)

    # Trying to load cache from pickle dump
    cache, success = loadCache(args.c)
    if not args.nocache:
        if success:
            print "[+] {0} cache entries read from cache database: {1}".format(len(cache), args.c)
        else:
            print "[-] No cache database found"
            print "[+] Analyzed hashes will be written to cache database: {0}".format(args.c)
        print "[+] You can always interrupt the scan by pressing CTRL+C without losing the scan state"

    # Open input file
    try:
        with open(args.f, 'rU') as fh:
            lines = fh.readlines()
    except Exception, e:
        print "[E] Cannot read input file "
        sys.exit(1)

    # Generate a result file name
    resultFile = generateResultFilename(args.f)

    # Write a CSV header
    if not args.nocsv:
        writeCSVHeader(resultFile)

    # Process the input lines
    processLines(lines, resultFile, args.nocsv, args.dups, args.debug)

    # Write Cache
    print "\n[+] Saving {0} cache entries to file {1}".format(len(cache), args.c)
    saveCache(cache, args.c)

    print Style.RESET_ALL

