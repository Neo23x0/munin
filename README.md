    _________   _    _   ______  _____  ______
    | | | | | \ | |  | | | |  \ \  | |  | |  \ \
    | | | | | | | |  | | | |  | |  | |  | |  | |
    |_| |_| |_| \_|__|_| |_|  |_| _|_|_ |_|  |_|

    Online Hash Checker for Virustotal and Other Services
    Florian Roth

# What is Munin?

Munin is a online hash checker utility that retrieves valuable information from various online sources

The current version of Munin queries the following services:

- Virustotal
- Malshare
- HybridAnalysis

Note: Munin is based on the script "VT-Checker", which has been maintained in the LOKI repository 

# Screenshot

![Munin Screenshot](https://github.com/Neo23x0/munin/blob/master/screens/munin.png "Munin in action")

# Usage

    usage: munin.py [-h] [-f path] [-c cache-db] [-i ini-file] [--nocache]
                    [--nocsv] [--dups] [--debug]

    Online Hash Checker

    optional arguments:
      -h, --help   show this help message and exit
      -f path      File to process (hash line by line OR csv with hash in each
                   line - auto-detects position and comment)
      -c cache-db  Name of the cache database file (default: vt-hash-db.pkl)
      -i ini-file  Name of the ini file that holds the API keys
      --nocache    Do not use cache database file
      --nocsv      Do not write a CSV with the results
      --dups       Do not skip duplicate hashes
      --debug      Debug output

# Features

- Extracts hashes from any text file based on regular expressions
- Retrieves valuable information from Virustotal via API (JSON response) and other information via permalink (HTML parsing)
- Keeps a history (cache) to query the services only once for a hash that may appear multiple times in the text file
- Creates CSV file with the findings for easy post-processing and reporting
- Appends results to a previous CSV if available

# Displays

- Hash and comment (comment is the rest of the line of which the hash has been extracted)
- AV vendor matches based on a user defined list
- Filenames used in the wild
- Signer of a signed portable executable
- Result based on Virustotal ratio
- First and last submission
- Tags for certain indicators: Harmless, Signed, Expired, Revoked, MSSoftware

# Extra Checks

- Queries Malshare.com for sample uploads
- Queries Hybrid-Analysis.com for present analysis
- Imphash duplicates in current batch > allows you to spot overlaps in import table hashes

# Getting started

1. Download / clone the repo
2. Install missing packages : `pip install requests bs4 colorama pickle configparser`
3. Set the API keys in the `munin.ini` file
4. Use the demo file for a first run: `python munin.py -f munin-demo.txt --nocache`

# Get the API Keys used by Munin

## Virustotal

1. Create an account here [https://www.virustotal.com/#/join-us](https://www.virustotal.com/#/join-us)
2. Check `Profile > My API key` for your public API key

## Malshare

Register here [https://malshare.com/register.php](https://malshare.com/register.php)

## Hybrid Analysis

1. Create an account here [https://www.hybrid-analysis.com/signup](https://www.hybrid-analysis.com/signup)
2. After login, check `Profile > API key`
