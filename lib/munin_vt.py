from datetime import datetime
import json
import math
import requests
import os
import traceback
from lib.connections import PROXY

RETROHUNT_URL = 'https://www.virustotal.com/api/v3/intelligence/retrohunt_jobs'
VT_COMMENT_API = 'https://www.virustotal.com/api/v3/files/%s/comments?relationships=author'
VT_REPORT_URL = 'https://www.virustotal.com/api/v3/files/%s'
VENDORS = ['Microsoft', 'Kaspersky', 'McAfee', 'CrowdStrike', 'TrendMicro',
           'ESET-NOD32', 'Symantec', 'F-Secure', 'Sophos', 'GData']

VT_PUBLIC_API_KEY = "-"

def getVTInfo(hash, debug=False):
    """
    Retrieves many different attributes of a sample from Virustotal via its hash
    :param hash:
    :return:
    """
    # Prepare VT API request
    headers = {"x-apikey": VT_PUBLIC_API_KEY}
    success = False
    while not success:
        try:
            response_dict_code = requests.get(VT_REPORT_URL % hash, headers=headers, proxies=PROXY)
            response_dict = json.loads(response_dict_code.content.decode("utf-8"))
            success = True
        except Exception as e:
            if debug:
                traceback.print_exc()
    if not response_dict_code.ok:
        if debug:
            print("[D] Received error message from VirusTotal: Status code %d, message %s" % (response_dict_code.status_code,  response_dict_code.content))
        info = getEmptyInfo()
        info['hash'] = hash
        return info

    info = processVirustotalSampleInfo(response_dict["data"], debug)
    if "sha256" in info:
        info.update(searchVirustotalComments(info["sha256"], debug))

    info['hash'] = hash

    # Harmless - TODO: Legacy features
    if "Probably harmless!" in response_dict_code:
        info['harmless'] = True
    # Microsoft Software
    if "This file belongs to the Microsoft Corporation software catalogue." in response_dict_code:
        info['mssoft'] = True
    return info


def getRetrohuntResults(retrohunt_id, no_comments=False, debug=False):
    headers = { 'x-apikey': VT_PUBLIC_API_KEY}
    url = "%s/%s/matching_files?limit=100" % (RETROHUNT_URL, retrohunt_id)
    files = []
    while True:
        response = requests.get(url, headers=headers, proxies=PROXY)

        if not response.ok:
            print("[E] Error response from VT: Status code %d, message %s" % (response.status_code, response.content))
            break

        try:
            response_json = json.loads(response.content)
        except ValueError:
            print("[E] Non-JSON response from VT: Message %s" % response.content)
            break

        for file in response_json["data"]:
            file_info = processVirustotalSampleInfo(file, debug)
            file_info['hash'] = file["id"]  # Add hash info manually, since no original hash exists
            file_info['matching_rule'] = file["context_attributes"]["rule_name"]
            if not no_comments:
                file_info.update(searchVirustotalComments(file["id"]))
            else:
                file_info.update({
                    "comments": 0,
                    "commenter": []
                })
            files.append(file_info)

        if "next" in response_json["links"]:
            url = response_json["links"]["next"]
        else:
            break
    return sorted(files, key = lambda i: i['matching_rule'])


def convertSize(size_bytes):
    """
    Converts number of bytes to a readable form
    Source: https://stackoverflow.com/questions/5194057/better-way-to-convert-file-sizes-in-python
    :param size_bytes:
    :return:
    """
    if size_bytes == 0:
       return "0B"
    size_name = ("B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB")
    i = int(math.floor(math.log(size_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(size_bytes / p, 2)
    return "%s %s" % (s, size_name[i])

def getEmptyInfo():
    return {
        'hash': '-',
        "result": "- / -",
        "virus": "-",
        "last_submitted": "-",
        "first_submitted": "-",
        "filenames": "-",
        "filetype": "-",
        "rating": "unknown",
        "positives": 0,
        "imphash": "-",
        "harmless": False,
        "revoked": False,
        "signed": False,
        "expired": False,
        "mssoft": False,
        "vendor_results": {},
        "signer": "-",
        "vt_queried": True,
        "tags": [],
        "copyright": "-", 
        "description": "-",
        "times_submitted": 0, 
        "reputation": 0, 
        "filesize": 0}

def get_crossplatfrom_basename(path):
    return os.path.basename(path.replace("\\", "/"))

def processVirustotalSampleInfo(sample_info, debug=False):
    """
    Processes a v3 API information dictionary of a sample and extracts useful data
    """
    info = getEmptyInfo()

    try:
        # Get file names
        info['filenames'] = list(set(map(get_crossplatfrom_basename, sample_info['attributes']['names'])))
        if 'meaningful_name' in sample_info['attributes']:
            meaningful_name = get_crossplatfrom_basename(sample_info['attributes']['meaningful_name'])
            if meaningful_name in info['filenames']:
                info['filenames'].remove(meaningful_name) # Prevent duplicate name by removing the other occurrence
            info['filenames'].insert(0, meaningful_name) # Insert meaningful name to be first, if available

        info["filenames"] = ", ".join(info['filenames']).replace(';', '_')
        # Get file type
        info['filetype'] = sample_info['attributes']['type_description']
        # Get file size
        info['filesize'] = convertSize(sample_info['attributes']['size'])
        # Get tags
        info['tags'] = sample_info['attributes']['tags']
        # First submission
        info['first_submitted'] = datetime.utcfromtimestamp(
            sample_info['attributes']['first_submission_date']
        ).strftime('%Y-%m-%d %H:%M:%S')
        # Times submitted
        info['times_submitted'] = sample_info['attributes']['times_submitted']
        # Reputation
        info['reputation'] = sample_info['attributes']['reputation']

        # Exiftool
        if 'exiftool' in sample_info['attributes']:
            if 'LegalCopyright' in sample_info['attributes']['exiftool']:
                # Get copyright
                if 'LegalCopyright' in sample_info['attributes']['exiftool']:
                    info['copyright'] = sample_info['attributes']['exiftool']['LegalCopyright']
                # Get description
                if 'FileDescription' in sample_info['attributes']['exiftool']:
                    info['description'] = sample_info['attributes']['exiftool']['FileDescription']
        # PE Info
        if 'pe_info' in sample_info['attributes']:
            if 'imphash' in sample_info['attributes']['pe_info']:
                # Get additional information
                info['imphash'] = sample_info['attributes']['pe_info']['imphash']
        # PE Signature
        if 'signature_info' in sample_info['attributes']:
            # Signer
            if 'signers' in sample_info['attributes']['signature_info']:
                info['signer'] = sample_info['attributes']['signature_info']['signers']
            # Valid
            if 'verified' in sample_info['attributes']['signature_info']:
                if sample_info['attributes']['signature_info']['verified'] == "Signed":
                    info['signed'] = True
                if "Revoked" in sample_info['attributes']['signature_info']['verified']:
                    info['revoked'] = True
                if "Expired" in sample_info['attributes']['signature_info']['verified']:
                    info['expired'] = True

        # Hashes
        info["md5"] = sample_info['attributes']['md5']
        info["sha1"] = sample_info['attributes']['sha1']
        info["sha256"] = sample_info['attributes']['sha256']
        # AV matches
        info["positives"] = sample_info["attributes"]["last_analysis_stats"]["malicious"] + sample_info["attributes"]["last_analysis_stats"]["suspicious"]
        info["total"] = sample_info["attributes"]["last_analysis_stats"]["undetected"] + sample_info["attributes"]["last_analysis_stats"]["malicious"] + sample_info["attributes"]["last_analysis_stats"]["suspicious"] + sample_info["attributes"]["last_analysis_stats"]["harmless"]
        if info["positives"] == 0:
            info["rating"] = "clean"
        elif info["positives"] <= 10:
            info["rating"] = "suspicious"
        else:
            info["rating"] = "malicious"

        info["last_submitted"] = datetime.utcfromtimestamp(
            sample_info['attributes']['last_submission_date']
        ).strftime('%Y-%m-%d %H:%M:%S')
        # Virus Name
        scans = sample_info['attributes']['last_analysis_results']
        virus_names = []
        info["vendor_results"] = {}
        for vendor in VENDORS:
            if vendor in scans:
                if scans[vendor]["result"]:
                    virus_names.append("{0}: {1}".format(vendor, scans[vendor]["result"]))
                    info["vendor_results"][vendor] = scans[vendor]["result"]
                else:
                    info["vendor_results"][vendor] = "-"
            else:
                info["vendor_results"][vendor] = "-"

        if len(virus_names) > 0:
            info["virus"] = " / ".join(virus_names)

    except Exception:
        if debug:
            traceback.print_exc()
    finally:
        # Return the info dictionary
        return info

def searchVirustotalComments(sha256, debug=False):
    info = {
        "comments": 0,
        "commenter": ['-']
    }

    try:
        headers = { 'x-apikey': VT_PUBLIC_API_KEY}
        # Comments
        r_code_comments = requests.get(VT_COMMENT_API % sha256, headers=headers, proxies=PROXY)
        if not r_code_comments.ok:
            if debug:
                print("[D] Could not query comments for sample %s" % sha256)
            return info

        r_comments = json.loads(r_code_comments.content.decode("utf-8"))
        #print(json.dumps(r_comments, indent=4, sort_keys=True))
        info['comments'] = len(r_comments['data'])
        if len(r_comments['data']) > 0:
            info['commenter'] = []
            for com in r_comments['data']:
                info['commenter'].append(com['relationships']['author']['data']['id'])
    except Exception:
        if debug:
            traceback.print_exc()
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
    response = requests.post('https://www.virustotal.com/vtapi/v2/comments/put', params=params, proxies=PROXY)
    response_json = response.json()
    if response_json['response_code'] != 1:
        print("[E] Error posting comment: %s" % response_json['verbose_msg'])
    else:
        printHighlighted("SUCCESSFULLY COMMENTED")
