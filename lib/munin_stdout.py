from colorama import init, Fore, Back, Style
import re

def printResult(info, count, total):
    """
    prints the result block
    :param info: all collected info
    :param count: counter (number of samples checked)
    :param total: total number of lines to check
    :return:
    """
    # Rating and Color
    info["res_color"] = Back.CYAN

    # If VT returned results
    if "total" in info:
        info["res_color"] = Back.GREEN
        if info["positives"] > 0:
            info["res_color"] = Back.YELLOW
        if info["positives"] > 10:
            info["res_color"] = Back.RED

    # Head line
    printSeparator(count, total, info['res_color'], info["rating"])
    headline = "HASH: {0}".format(info["hash"])
    if 'comment' in info and info['comment'] != '':
        headline += " COMMENT: {0}".format(info['comment'])
    if 'matching_rule' in info and info['matching_rule'] != '':
        headline += " RULE: {0}".format(info['matching_rule'])
    printHighlighted(headline)

    # More VT info
    if "total" in info:
        # Result
        info["result"] = "%s / %s" % (info["positives"], info["total"])
        if info["virus"] != "-":
            printHighlighted("VIRUS: {0}".format(info["virus"]))
        printHighlighted("TYPE: {1} SIZE: {2} FILENAMES: {0}".format(removeNonAsciiDrop(info["filenames"]),
                                                                     info['filetype'],
                                                                     info['filesize']))

        # Tags to show
        tags = ""
        if isinstance(info['tags'], list):
            tags = " ".join(map(lambda x: x.upper(), info['tags']))
        # Extra Info
        printPeInfo(info)
        printHighlighted("FIRST: {0} LAST: {1} SUBMISSIONS: {5} REPUTATION: {6}\nCOMMENTS: {2} USERS: {3} TAGS: {4}".format(
            info["first_submitted"],
            info["last_submitted"],
            info["comments"],
            ', '.join(info["commenter"]),
            tags,
            info["times_submitted"],
            info["reputation"]
        ), tag_color=True)

    # Print the highlighted result line
    printHighlighted("RESULT: %s" % (info["result"]), hl_color=info["res_color"])


def printHighlighted(line, hl_color=Back.WHITE, tag_color=False):
    """
    Print a highlighted line
    """
    if tag_color:
        # Tags
        colorer = re.compile('(HARMLESS|SIGNED|MS_SOFTWARE_CATALOGUE|MSSOFT|SUCCESSFULLY\sCOMMENTED)', re.VERBOSE)
        line = colorer.sub(Fore.BLACK + Back.GREEN + r'\1' + Style.RESET_ALL + '', line)
        colorer = re.compile('(REVOKED|EXPLOIT|CVE-[0-9\-]+|OBFUSCATED|RUN\-FILE)', re.VERBOSE)
        line = colorer.sub(Fore.BLACK + Back.RED + r'\1' + Style.RESET_ALL + '', line)
        colorer = re.compile('(EXPIRED|VIA\-TOR|OLE\-EMBEDDED|RTF|ATTACHMENT|ASPACK|UPX|AUTO\-OPEN|MACROS)', re.VERBOSE)
        line = colorer.sub(Fore.BLACK + Back.YELLOW + r'\1' + Style.RESET_ALL + '', line)
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


def printKeyLine(line):
    """
    Print a given string as a separator line
    :param line:
    :return:
    """
    print(Fore.BLACK + Back.WHITE)
    print("{0}".format(line).ljust(80) + Style.RESET_ALL)
    print("")


def printPeInfo(sample_info):
    """
    Prints PE information in a clever form
    :param peInfo:
    :return:
    """
    peInfo = [u'origname', u'description', u'copyright', u'signer']
    outString = []
    for k, v in sample_info.items():
        if k in peInfo:
            if v != '-':
                outString.append("{0}: {1}".format(k.upper(), removeNonAsciiDrop(v)))
    if " ".join(outString):
        printHighlighted(" ".join(outString))

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