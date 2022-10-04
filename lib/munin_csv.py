import codecs
import traceback
import csv
from lib.munin_vt import VENDORS

CSV_FIELD_ORDER = ['Lookup Hash', 'Rating', 'Comment', 'Positives', 'File Size', 'Virus', 'File Names', 'First Submitted',
                   'Last Submitted', 'File Type', 'MD5', 'SHA1', 'SHA256', 'Imphash', 'Matching Rule', 'Harmless', 'Revoked',
                   'Expired', 'Trusted', 'Signed', 'Signer', 'Hybrid Analysis Sample', 'MalShare Sample',
                   'VirusBay Sample', 'MISP', 'MISP Events', 'URLhaus', 'AnyRun', 'CAPE', 'VALHALLA', 'User Comments']

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
              'VirusBay Sample': 'virusbay_available',
              'MISP': 'misp_available',
              'MISP Events': 'misp_events',
              'URLhaus': 'urlhaus_available',
              'AnyRun': 'anyrun_available',
              'CAPE': 'cape_available',
              'VALHALLA': 'valhalla_matches',
              'Comments': 'comments',
              'User Comments': 'commenter',
              'Reputation': 'reputation',
              'Times Submitted': 'times_submitted',
              'Tags': 'tags',
              }

def writeCSV(info, resultFile):
    """
    Write info line to CSV
    :param info:
    :return:
    """
    try:
        with codecs.open(resultFile, 'a', encoding='utf8') as fh_results:
            writer = csv.writer(fh_results, delimiter=';', quotechar='"')
            row = []
            # Every field from the field list will print to the output file
            for field_pretty in CSV_FIELD_ORDER:
                field = CSV_FIELDS[field_pretty]
                try:
                    field = info[field]
                except KeyError as e:
                    field = "False"
                try:
                    field = str(field).replace("\n", " ")
                except AttributeError as e:
                    traceback.print_exc()
                row.append(field)
            # Append vendor scan results
            for vendor in VENDORS:
                if vendor in info['vendor_results']:
                    field = info['vendor_results'][vendor]
                    field = field.replace("\n", " ")
                    row.append(field)
                else:
                    row.append("-")
            row.append("")  # empty final field for backwards compatibility
            writer.writerow(row)
    except:
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
