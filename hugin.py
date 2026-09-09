#!/usr/bin/env python3

__AUTHOR__ = 'Max Altgelt'
__VERSION__ = "0.3.0 September 2026"

import argparse
import collections
import configparser
from datetime import datetime
import io
import json
import logging
import os
import requests
import ssl
import subprocess
import sys
import tempfile
import time
import traceback
import zipfile

from colorama import init, Fore, Back, Style

from lib.munin_csv import writeCSV, writeCSVHeader
import lib.munin_vt as munin_vt
import lib.connections as connections
from lib.helper import generateResultFilename
from lib.munin_stdout import printResult


def _effective_requests_ca_bundle(ca_bundle: str) -> str:
    """Return the CA bundle Requests will use for the analyzer request."""
    return (ca_bundle
            or os.environ.get("REQUESTS_CA_BUNDLE")
            or os.environ.get("CURL_CA_BUNDLE")
            or requests.certs.where())


def _print_analyzer_tls_help(exc: Exception, ca_bundle: str, debug: bool) -> None:
    """Print actionable guidance for analyzer TLS verification failures."""
    print("[W] TLS certificate verification failed for the retrohunt-analyzer-service: %s" % exc)
    print("[*] Your browser and Python requests may use different CA stores, or the server may provide an "
          "incomplete certificate chain.")
    print("[*] Set RETROHUNT_ANALYZER_CA_BUNDLE in your INI file to an approved PEM CA bundle.")
    print("[*] See README.md: 'TLS certificates for the Retrohunt Analyzer' (macOS/Linux).")
    print("[*] Do not disable TLS certificate verification.")

    if debug:
        print("[D] Python executable: %s" % sys.executable)
        print("[D] Python/OpenSSL: %s / %s" % (sys.version.split()[0], ssl.OPENSSL_VERSION))
        print("[D] requests version: %s" % requests.__version__)
        print("[D] requests default CA bundle: %s" % requests.certs.where())
        print("[D] Effective analyzer CA bundle: %s" % _effective_requests_ca_bundle(ca_bundle))
        print("[D] REQUESTS_CA_BUNDLE: %s" % (os.environ.get("REQUESTS_CA_BUNDLE") or "<not set>"))
        print("[D] CURL_CA_BUNDLE: %s" % (os.environ.get("CURL_CA_BUNDLE") or "<not set>"))
        print("[D] SSL_CERT_FILE: %s" % (os.environ.get("SSL_CERT_FILE") or "<not set>"))
        print("[D] OpenSSL default verify paths: %s" % (ssl.get_default_verify_paths(),))
        traceback.print_exc()


def send_to_analyzer(csv_path: str, url: str, ca_bundle: str = "", debug: bool = False) -> None:
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
        ca_bundle: Optional path to a PEM CA bundle used only for this request.
        debug: Print detailed TLS and exception diagnostics.
    """
    endpoint = url.rstrip("/") + "/api/v1/reports"
    out_dir = os.path.dirname(os.path.abspath(csv_path))
    ca_bundle = ca_bundle.strip() if ca_bundle else ""
    if ca_bundle == "-":
        ca_bundle = ""

    if ca_bundle and not os.path.isfile(ca_bundle):
        print("[W] Configured analyzer CA bundle does not exist or is not a file: %s" % ca_bundle)
        return

    verify = ca_bundle or True

    print("[*] Sending retrohunt CSV to analyzer service: %s" % endpoint)
    if debug:
        print("[D] Effective analyzer TLS CA bundle: %s" % _effective_requests_ca_bundle(ca_bundle))
    try:
        with open(csv_path, "rb") as fh:
            response = requests.post(
                endpoint,
                files={"file": (os.path.basename(csv_path), fh, "text/csv")},
                timeout=120,
                verify=verify,
            )
    except requests.exceptions.SSLError as exc:
        _print_analyzer_tls_help(exc, ca_bundle, debug)
        return
    except Exception as exc:
        print("[W] Could not reach retrohunt-analyzer-service: %s" % exc)
        if debug:
            traceback.print_exc()
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
        analyzer_ca_bundle = config['DEFAULT'].get('RETROHUNT_ANALYZER_CA_BUNDLE', '-').strip()
    except Exception as e:
        traceback.print_exc()
        print("[E] Config file '%s' not found or missing field - check the template munin.ini if fields have "
              "changed" % args.i)
        analyzer_url = '-'
        analyzer_ca_bundle = '-'

    print("[+] Retrieving Retrohunt results ...")
    found_files = munin_vt.getRetrohuntResults(args.r, not args.comments, args.debug)
    print("[+] Retrohunt results retrieved")

    csv_filename = args.csv_path

    writeCSVHeader(csv_filename)

    for i, file_info in enumerate(found_files):
        printResult(file_info, i, len(found_files))
        writeCSV(file_info, csv_filename)

    if analyzer_url and analyzer_url != '-':
        send_to_analyzer(csv_filename, analyzer_url, analyzer_ca_bundle, args.debug)


if __name__ == '__main__':
    main()
