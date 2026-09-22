import codecs
import traceback

# only write top10 vendors to CSV because file format can't handle changing number of them
VENDORS = ['Microsoft', 'Kaspersky', 'McAfee', 'CrowdStrike', 'TrendMicro', 'ESET-NOD32', 'Symantec', 'F-Secure', 'Sophos', 'GData']

# Removed services:
#   'VirusBay Sample' - beta.virusbay.io is offline
#   'AnyRun' - URL format changed, all hashes now return 200 via redirect; new API requires auth
#   'CAPE' - capesandbox.com is behind Cloudflare on v1 endpoints; no public token registration
CSV_FIELD_ORDER = ['Lookup Hash', 'Rating', 'Comment', 'Positives', 'File Size', 'Virus', 'File Names', 'First Submitted',
                   'Last Submitted', 'File Type', 'MD5', 'SHA1', 'SHA256', 'Imphash', 'Matching Rule', 'Harmless', 'Revoked',
                   'Expired', 'Trusted', 'Signed', 'Signer', 'Hybrid Analysis Sample', 'MalShare Sample',
                   'MISP', 'MISP Events', 'URLhaus', 'VALHALLA', 'User Comments']

CSV_FIELDS = {'Lookup Hash': 'hash',
              'Rating': 'rating',
              'Comment': 'comment',
              'Matching Rule': 'matching_rule',
              'Positives': 'positives',
              'Virus': 'virus',
              'File Names': 'filenames',
              'First Submitted': 'first_submitted',
              'Last Submitted': 'last_submitted',
              'File Type': 'filetype',
              'File Size': 'filesize',
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
              'MISP': 'misp_available',
              'MISP Events': 'misp_events',
              'URLhaus': 'urlhaus_available',
              'VALHALLA': 'valhalla_matches',
              'Comments': 'comments',
              'User Comments': 'commenter',
              'Reputation': 'reputation',
              'Times Submitted': 'times_submitted',
              'Tags': 'tags',
              }

def writeCSV(info, resultFile, field_order=CSV_FIELD_ORDER, include_vendors=True):
    """
    Write info line to CSV
    :param info:
    :param resultFile:
    :param field_order: list of CSV_FIELD_ORDER entries to write (allows excluding unconfigured providers)
    :param include_vendors: whether to append per-vendor AV columns. Set False for hugin, which uses
        the retrohunt matching_files endpoint that does not return last_analysis_results (per-vendor
        detections) — only last_analysis_stats — so vendor columns would always be empty.
    :return:
    """
    try:
        with codecs.open(resultFile, 'a', encoding='utf8') as fh_results:
            # Print every field from the field list to the output file
            for field_pretty in field_order:
                field = CSV_FIELDS[field_pretty]
                try:
                    field = info[field]
                except KeyError as e:
                    field = "False"
                try:
                    field = str(field).replace(r'"', r'\"').replace("\n", " ").replace(";", ",")
                except AttributeError as e:
                    traceback.print_exc()
                fh_results.write("%s;" % field)
            # Append vendor scan results (skipped for hugin — see include_vendors docstring)
            if include_vendors:
                for vendor in VENDORS:
                    if vendor in info['vendor_results']:
                        fh_results.write("%s;" % info['vendor_results'][vendor])
                    else:
                        fh_results.write("-;")
            fh_results.write('\n')
    except:
        traceback.print_exc()
        return False
    return True


def writeCSVHeader(resultFile, field_order=CSV_FIELD_ORDER, include_vendors=True):
    """
    Writes a CSV header line into the results file
    :param resultFile:
    :param field_order: list of CSV_FIELD_ORDER entries to write (allows excluding unconfigured providers)
    :param include_vendors: whether to append per-vendor AV columns. Set False for hugin, which uses
        the retrohunt matching_files endpoint that does not return last_analysis_results (per-vendor
        detections) — only last_analysis_stats — so vendor columns would always be empty.
    :return:
    """
    try:
        with open(resultFile, 'w') as fh_results:
            fh_results.write("%s;" % ";".join(field_order))
            if include_vendors:
                fh_results.write("%s;" % ";".join(VENDORS))
            fh_results.write('\n')
    except Exception as e:
        print("[E] Cannot write export file {0}".format(resultFile))
