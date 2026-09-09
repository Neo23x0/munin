#!/usr/bin/env python3

__AUTHOR__ = 'Max Altgelt'
__VERSION__ = "0.2.1 March 2025"

import argparse
import collections
import configparser
from datetime import datetime
import json
import logging
import os
import requests
import subprocess
import tempfile
import time
import traceback
import io
import zipfile

from colorama import init, Fore, Back, Style

from lib.munin_csv import writeCSV, writeCSVHeader
import lib.munin_vt as munin_vt
import lib.connections as connections
from lib.helper import generateResultFilename
from lib.munin_stdout import printResult


def send_to_analyzer(csv_path: str, url: str) -> None:
    """POST *csv_path* to the retrohunt-analyzer-service and write the
    returned files (HTML report + optional enriched CSV) next to the CSV.

    The service endpoint is ``POST {url}/api/v1/reports`` which returns an
    ``application/zip`` archive.  Any file inside the ZIP is extracted to the
    same directory as *csv_path*.

    All errors are caught and printed as warnings so the caller's flow is
    never interrupted.

    Args:
        csv_path: Path to the retrohunt results CSV produced by hugin.
        url: Base URL of the retrohunt-analyzer-service
    """
    endpoint = url.rstrip("/") + "/api/v1/reports"
    out_dir = os.path.dirname(os.path.abspath(csv_path))

    print("[*] Sending retrohunt CSV to analyzer service: %s" % endpoint)
    try:
        with open(csv_path, "rb") as fh:
            response = requests.post(
                endpoint,
                files={"file": (os.path.basename(csv_path), fh, "text/csv")},
                timeout=120,
            )
    except Exception as exc:
        print("[W] Could not reach retrohunt-analyzer-service: %s" % exc)
        return

    if response.status_code != 200:
        print("[W] Retrohunt-analyzer-service returned HTTP %d: %s"
              % (response.status_code, response.text[:200]))
        return

    try:
        with zipfile.ZipFile(io.BytesIO(response.content)) as zf:
            names = zf.namelist()
            for name in names:
                out_path = os.path.join(out_dir, os.path.basename(name))
                with zf.open(name) as src, open(out_path, "wb") as dst:
                    dst.write(src.read())
                print("[+] Analyzer output saved: %s" % out_path)
    except Exception as exc:
        print("[W] Failed to extract analyzer response: %s" % exc)
        return

    enriched = any(n.endswith("_enriched.csv") for n in names)
    if enriched:
        print("[+] Enriched CSV included (Valhalla configured on service)")
    else:
        print("[*] No enriched CSV in response (Valhalla not configured on service)")


def main():
    init(autoreset=False)

    print(Style.RESET_ALL)
    print(Fore.BLACK + Back.WHITE)
    print("   _    _   _    _   ______  _____  ______   ".ljust(80))
    print("  | |  | | | |  | | | | ____  | |  | |  \\ \\   (.\\ ".ljust(80))
    print("  | |--| | | |  | | | |  | |  | |  | |  | |   |/(\\ ".ljust(80))
    print("  |_|  |_| \\_|__|_| |_|__|_| _|_|_ |_|  |_|    \\ \\\\".ljust(80))
    print("                                               \" \"'\\  ".ljust(80))
    print(" ".ljust(80))
    print("  Result Checker for Virustotal Retrohunts".ljust(80))
    print(("  " + __AUTHOR__ + " - " + __VERSION__ + "").ljust(80))
    print(" ".ljust(80) + Style.RESET_ALL)
    print(Style.RESET_ALL + " ")

    parser = argparse.ArgumentParser(description='Retrohunt Checker')
    parser.add_argument('-r', help='Name for the queried retrohunt', metavar='retrohunt-name', default='')
    parser.add_argument('-i', help='Name of the ini file that holds the VT API key', metavar='ini-file',
                        default=os.path.dirname(os.path.abspath(__file__)) + '/munin.ini')
    parser.add_argument('--csv-path', help='Write a CSV with the results', default='retrohunt_results.csv')
    parser.add_argument('--debug', action='store_true', default=False, help='Debug output')
    parser.add_argument('--comments', help='Download VirusTotal comments', action='store_true', default=False)
    parser.add_argument('--no-comments', help='Deprecated - set by default, doesn\'t do anything', default=False)
    
    args = parser.parse_args()

    # PyMISP error handling > into Nirvana
    logger = logging.getLogger("pymisp")
    logger.setLevel(logging.CRITICAL)
    if args.debug:
        logger.setLevel(logging.DEBUG)

    # Read the config file
    config = configparser.ConfigParser()
    try:
        config.read(args.i)
        munin_vt.VT_PUBLIC_API_KEY = config['DEFAULT']['VT_PUBLIC_API_KEY']
        try:
            connections.setProxy(config['DEFAULT']['PROXY'])
        except KeyError as e:
            print("[E] Your config misses the PROXY field - check the new munin.ini template and add it to your "
                  "config to avoid this error.")
        analyzer_url = config['DEFAULT'].get('RETROHUNT_ANALYZER_URL', '-').strip()
    except Exception as e:
        traceback.print_exc()
        print("[E] Config file '%s' not found or missing field - check the template munin.ini if fields have "
              "changed" % args.i)
        analyzer_url = '-'

    print("[+] Retrieving Retrohunt results ...")
    found_files = munin_vt.getRetrohuntResults(args.r, not args.comments, args.debug)
    print("[+] Retrohunt results retrieved")

    csv_filename = args.csv_path

    writeCSVHeader(csv_filename)

    for i, file_info in enumerate(found_files):
        printResult(file_info, i, len(found_files))
        writeCSV(file_info, csv_filename)

    if analyzer_url and analyzer_url != '-':
        send_to_analyzer(csv_filename, analyzer_url)


if __name__ == '__main__':
    main()
