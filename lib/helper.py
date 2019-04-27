import re
import subprocess
import platform
import socket
import os
from datetime import datetime


def isIp(value):
    """
    Checks if a value is an IP
    :param value:
    :return:
    """
    ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b$'
    if re.match(ip_pattern, value):
        return True
    return False


def is_private(ip):
    """
    Checks if an IP is private
    :param ip:
    :return:
    """
    ip = IP(ip)
    if ip.iptype() == "PRIVATE":
        return True
    return False


def is_resolvable(domain):
    """
    Checks if a domain is resolvable
    :param domain:
    :return:
    """
    try:
        socket.gethostbyname(domain)
        return True
    except Exception as e:
        # traceback.print_exc()
        return False


def is_pingable(ip):
    """
    Ping the target IP
    :param ip:
    :return:
    """
    try:
        # Ping parameters as function of OS
        ping_str = "-n 1 -w 500" if platform.system().lower() == "windows" else "-c 1 -W 500"
        # Ping
        subprocess.check_output("ping {0} {1}".format(ping_str, ip),
                                stderr=subprocess.STDOUT,
                                shell=True)
        return True
    except Exception as e:
        # traceback.print_exc()
        return False


def header_function(header_raw):
    """
    Process header info
    Example from pycurl quick start guide http://pycurl.io/docs/latest/quickstart.html
    :param header_line:
    :return:
    """
    headers = {}
    header_lines = header_raw.splitlines()

    for header_line in header_lines:

        # HTTP standard specifies that headers are encoded in iso-8859-1.
        # On Python 2, decoding step can be skipped.
        # On Python 3, decoding step is required.
        header_line = header_line.decode('iso-8859-1')

        # Header lines include the first status line (HTTP/1.x ...).
        # We are going to ignore all lines that don't have a colon in them.
        # This will botch headers that are split on multiple lines...
        if ':' not in header_line:
            continue

        # Break the header line into header name and value.
        name, value = header_line.split(':', 1)

        # Remove whitespace that may be present.
        # Header lines include the trailing newline, and there may be whitespace
        # around the colon.
        name = name.strip()
        value = value.strip()

        # Header names are case insensitive.
        # Lowercase name here.
        name = name.lower()

        # Now we can actually record the header name and value.
        headers[name] = value

    return headers


def generateResultFilename(inputFileName):
    """
    Generate a result file name based on the input name
    :param inputName: name of the processed file
    :return alreadyExists: returns True if the file already exists
    :return resultFile: name of the output file
    """
    alreadyExists = False
    # CLI
    if not inputFileName:
        resultFile = "check-results_{0}.csv".format(datetime.now().strftime("%Y-%m-%d"))
        if os.path.exists(resultFile):
            alreadyExists = True
        return alreadyExists, resultFile
    # Default
    else:
        resultFile = "check-results_{0}.csv".format(os.path.splitext(os.path.basename(inputFileName))[0])
        if os.path.exists(resultFile):
            print("[+] Found results CSV from previous run: {0}".format(resultFile))
            print("[+] Appending results to file: {0}".format(resultFile))
            alreadyExists = True
        else:
            print("[+] Writing results to new file: {0}".format(resultFile))
        return alreadyExists, resultFile
