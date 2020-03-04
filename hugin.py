#!/usr/bin/env python3

__AUTHOR__ = 'Max Altgelt'
__VERSION__ = "0.2.0 March 2020"

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

from colorama import init, Fore, Back, Style

from lib.munin_csv import writeCSV, writeCSVHeader
import lib.munin_vt as munin_vt
import lib.connections as connections
from lib.helper import generateResultFilename
from lib.munin_stdout import printResult

def main():
    init(autoreset=False)

    print(Style.RESET_ALL)
    print(Fore.BLACK + Back.WHITE)
    print("   _    _   _    _   ______  _____  ______   ".ljust(80))
    print("  | |  | | | |  | | | | ____  | |  | |  \ \   (.\\ ".ljust(80))
    print("  | |--| | | |  | | | |  | |  | |  | |  | |   |/(\\ ".ljust(80))
    print("  |_|  |_| \_|__|_| |_|__|_| _|_|_ |_|  |_|    \\ \\\\".ljust(80))
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
    parser.add_argument('--no-comments', help='Skip VirusTotal comments', action='store_true', default=False)
    
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
    except Exception as e:
        traceback.print_exc()
        print("[E] Config file '%s' not found or missing field - check the template munin.ini if fields have "
              "changed" % args.i)

    print("[+] Retrieving Retrohunt results ...")
    found_files = munin_vt.getRetrohuntResults(args.r, args.no_comments, args.debug)
    print("[+] Retrohunt results retrieved")

    csv_filename = args.csv_path

    writeCSVHeader(csv_filename)

    for i, file_info in enumerate(found_files):
        printResult(file_info, i, len(found_files))
        writeCSV(file_info, csv_filename)

if __name__ == '__main__':
    main()
    