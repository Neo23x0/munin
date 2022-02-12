[![Actively Maintained](https://img.shields.io/badge/Maintenance%20Level-Actively%20Maintained-green.svg)](https://gist.github.com/cheerfulstoic/d107229326a01ff0f333a1d3476e068d)

     _________   _    _   ______  _____  ______
    | | | | | \ | |  | | | |  \ \  | |  | |  \ \     /.)
    | | | | | | | |  | | | |  | |  | |  | |  | |    /)\|
    |_| |_| |_| \_|__|_| |_|  |_| _|_|_ |_|  |_|   // /
                                                  /'" "
    
    Online Hash Checker for Virustotal and Other Services
    Florian Roth


## What is Munin?

Munin is a online hash checker utility that retrieves valuable information from various online sources

The current version of Munin queries the following services:

- [Virustotal](https://www.virustotal.com)
- [HybridAnalysis](https://www.hybrid-analysis.com/)
- [Any.Run](https://app.any.run/)
- [URLhaus](https://urlhaus.abuse.ch/)
- [MISP](https://www.circl.lu/services/misp-malware-information-sharing-platform/)
- [CAPE](https://cape.contextis.com/)
- [Malshare](https://malshare.com/)
- [Valhalla](https://valhalla.nextron-systems.com/)
- [Hashlookup](https://circl.lu/services/hashlookup/)

## Screenshot

Default Mode - Read Hashes from File

![Munin Screenshot](https://github.com/Neo23x0/munin/blob/master/screens/munin.png "Munin in action")

## Usage

    usage: munin.py [-h] [-f path] [-o output] [-c cache-db] [-i ini-file]
                    [-s sample-folder] [--comment] [-p vt-comment-prefix]
                    [--download] [-d download_path] [--nocache] [--nocsv]
                    [--verifycert] [--sort] [--web] [-w port] [--cli] [--debug]

    Online Hash Checker

    optional arguments:
      -h, --help            show this help message and exit
      -f path               File to process (hash line by line OR csv with hash in
                            each line - auto-detects position and comment)
      -o output             Output file for results (CSV)
      -c cache-db           Name of the cache database file (default: vt-hash-
                            db.pkl)
      -i ini-file           Name of the ini file that holds the API keys
      -s sample-folder      Folder with samples to process
      --comment             Posts a comment for the analysed hash which contains
                            the comment from the log line
      -p vt-comment-prefix  Virustotal comment prefix
      --download            Enables Sample Download from Hybrid Analysis. SHA256
                            of sample needed.
      -d download_path      Output Path for Sample Download from Hybrid Analysis.
                            Folder must exist
      --nocache             Do not use cache database file
      --nocsv               Do not write a CSV with the results
      --verifycert          Verify SSL/TLS certificates
      --sort                Sort the input lines
      --web                 Run Munin as web service
      -w port               Web service port
      --cli                 Run Munin in command line interface mode
      --debug               Debug output


## Features

- MODE A: Extracts hashes from any text file based on regular expressions
- MODE B: Walks sample directory and checks hashes online
- MODE C: Command line interface mode (fallback if no file or directory input is provided)
- Retrieves valuable information from Virustotal via API (JSON response) and other information via permalink (HTML parsing)
- Retrieves extra information from a list of platforms
- Keeps a history (cache) to query the services only once for a hash that may appear multiple times in the text file
- Cached objects are stored in JSON
- Creates CSV file with the findings for easy post-processing and reporting
- Appends results to a previous CSV if available

## Displays

- Hash and comment (comment is the rest of the line of which the hash has been extracted)
- AV vendor matches based on a user defined list
- Filenames used in the wild
- PE information like the description, the original file name and the copyright statement
- Signer of a signed portable executable
- Result based on Virustotal ratio
- First and last submission
- Tags for certain indicators: Harmless, Signed, Expired, Revoked, MSSoftware

## Extra Checks

- Queries Malshare.com for sample uploads
- Queries Hybrid-Analysis.com for reports
- Queries multiple MISP instances for available events
- Queries Any.run sandbox for reports
- Queries CAPE sandbox for reports
- Queries URLhaus for reports
- Queries Malshare for available samples
- Queries Valhalla for YARA rule matches
- Imphash duplicates in current batch > allows you to spot overlaps in import table hashes
- PE signature duplicate checks

## Operation Modes

1. Default - by providing an input file (-f) with hashes or sample directory (-s)
2. Command Line Interface - using the --cli paramerter
3. Web Service Mode - using the --web paramerter

## Getting started

1. Download / clone the repo
2. Install required packages: `pip3 install -r requirements.txt` (on macOS add `--user`)
3. Set the API keys for the different services in your custom ini file `cp munin.ini my.ini` (see section `Get the API Keys` for help)
4. Use the demo file for a first run: `python munin.py -i my.ini -f munin-demo.txt`

## Requirements

- Python 3.7 and higher 
- Internet Connection (Proxy Support; SSL/TLS interception can be a problem)

## Typical Command Lines

Process a Virustotal Retrohunt result and sort the lines before checking so that matched signatures are checked in blocks

```bash
python3 munin.py -i my.ini -f ~/Downloads/retro_hunt
```

Process a directory with samples and check their hashes online

```bash
python3 munin.py -i my.ini -s ~/malware/case34
```

Use the command line interface mode (new in v0.14)
```bash
python3 munin.py -i my.ini
```

## Get the API Keys

### Virustotal

1. Create an account here [https://www.virustotal.com/#/join-us](https://www.virustotal.com/#/join-us)
2. Check `Profile > My API key` for your public API key

### MalShare

Register here [https://malshare.com/register.php](https://malshare.com/register.php)

### Malware Bazar

Register here [https://bazaar.abuse.ch/](https://bazaar.abuse.ch/). You can then find your API key in your [Account Overview](https://bazaar.abuse.ch/account/). 

### Hybrid Analysis

1. Create an account here [https://www.hybrid-analysis.com/signup](https://www.hybrid-analysis.com/signup)
2. After login, check `Profile > API key`

### MISP 

1. Log into your MISP 
2. Go to your profile "My Profile"
3. The value of `Authkey` is used as API key
4. Note that the .ini file uses both a list for the MISP instances and for the respective API keys

### Valhalla

Currently for customers or invited researchers only \
[https://valhalla.nextron-systems.com/](https://valhalla.nextron-systems.com/)

### Hashlookup

[Hashlookup](https://circl.lu/services/hashlookup/) CIRCL's instance is provided free of charge and served as a best-effort basis.

## Command Line Interface Mode

Start munin with `--cli` and follow the instruction. 

E.g. 
```bash
python3 munin.py -i my.ini --cli
```

Paste content with hash values in it and then press `CTRL+D` to finalize the input. The last line needs a line break at its end. 

In the default, it will create a CSV file with the current date in the file name.

![Munin CLI](https://github.com/Neo23x0/munin/blob/master/screens/munin-cli.png "Munin Command Line Interface")

## Web Service Mode

Start munin with `--web` and optionall select a port `-w port`. 

E.g. 
```bash
python3 munin.py -i my.ini --web -w 8080
```

The web service waits for strings in the following URL scheme.

```bash
http://server:port/<string>
```

The string can be any string without line breaks, e.g.
```bash
Emotet:1585ad28f7d1e0ca696e6c6c2f1d008a
ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa;IOC1
dc9b5e8aa6ec86db8af0a7aa897ca61db3e5f3d2e0942e319074db1aaccfdc83
```

The result will look like this:
```json
{
    "comment": "Emotet",
    "commenter": "-",
    "comments": "0",
    "copyright": "Copyright (C) America Online, Inc. 1999 - 2004",
    "description": "Utilities",
    "expired": false,
    "filenames": "sourcedev.exe, MISCUTIL, x8ykNnr_9WofXq7Nh_xuEzSPW.exe, jwuKBLWN681ztj6Zks.exe",
    "filetype": "Win32 EXE",
    "first_submitted": "2019-01-19 13:46:21 UTC ( 2 months, 2 weeks ago )",
    "firstsubmission": "2019-01-19 13:46:21 UTC ( 2 months, 2 weeks ago )",
    "harmless": false,
    "hash": "1585ad28f7d1e0ca696e6c6c2f1d008a",
    "hybrid_available": false,
    "hybrid_compromised": "-",
    "hybrid_date": "-",
    "hybrid_score": "-",
    "imphash": "2820d9bdc397f88a8a1e957e1a824482",
    "last_submitted": "2019-02-27 09:44:03",
    "malshare_available": false,
    "md5": "1585ad28f7d1e0ca696e6c6c2f1d008a",
    "misp_available": true,
    "misp_events": "",
    "misp_info": [],
    "mssoft": false,
    "origname": "-",
    "positives": 48,
    "rating": "malicious",
    "res_color": "\u001b[41m",
    "result": "48 / 64",
    "revoked": false,
    "sha1": "4561d0ad575d5f02fb06e062a37de15861c3bd89",
    "sha256": "35e304d10d53834e3e41035d12122773c9a4d183a24e03f980ad3e6b2ecde7fa",
    "signed": false,
    "signer": "-",
    "total": 64,
    "urlhaus_available": true,
    "vendor_results": {
        "CrowdStrike": "win/malicious_confidence_100% (W)",
        "ESET-NOD32": "a variant of Win32/Kryptik.GOUY",
        "F-Secure": "Trojan.TR/AD.Emotet.pdiuu",
        "GData": "Trojan.GenericKD.40960256",
        "Kaspersky": "HEUR:Trojan.Win32.Generic",
        "McAfee": "Emotet-FLL!1585AD28F7D1",
        "Microsoft": "Trojan:Win32/Emotet.DN",
        "Sophos": "Mal/Emotet-Q",
        "Symantec": "Trojan.Gen.2",
        "TrendMicro": "-"
    },
    "virus": "Microsoft: Trojan:Win32/Emotet.DN / Kaspersky: HEUR:Trojan.Win32.Generic / McAfee: Emotet-FLL!1585AD28F7D1 / CrowdStrike: win/malicious_confidence_100% (W) / ESET-NOD32: a variant of Win32/Kryptik.GOUY / Symantec: Trojan.Gen.2 / F-Secure: Trojan.TR/AD.Emotet.pdiuu / Sophos: Mal/Emotet-Q / GData: Trojan.GenericKD.40960256",
    "virusbay_available": false,
    "vt_positives": 48,
    "vt_queried": false,
    "vt_total": 64,
    "vt_verbose_msg": "Scan finished, information embedded"
}
```

The queries to Virustotal need to be throttled. Therefore the web service applies a cool down time, that is minimized by substracting the time it took to process all other platforms from the wait time of 15 seconds. 
```
cooldown_time = vt_wait_time - process_time
```

During the cooldown, requests will return this response:
```json
{"status": "VT cooldown active"}
```

The cool down is not relevant when requesting hashes that are already in the lookup cache. 

# Munin Hosts

The Munin host and IP checker script (`munin-host.py`) retrieves more information on IP addresses and host/domain names in IOC lists. 

## Usage

```bash
usage: munin.py [-h] [-f path] [-c cache-db] [-i ini-file] [-s sample-folder]
                [--comment] [-p vt-comment-prefix] [--download]
                [-d download_path] [--nocache] [--intense] [--nocsv]
                [--verifycert] [--sort] [--web] [-w port] [--debug]

Online Hash Checker

optional arguments:
  -h, --help            show this help message and exit
  -f path               File to process (hash line by line OR csv with hash in
                        each line - auto-detects position and comment)
  -c cache-db           Name of the cache database file (default: vt-hash-
                        db.pkl)
  -i ini-file           Name of the ini file that holds the API keys
  -s sample-folder      Folder with samples to process
  --comment             Posts a comment for the analysed hash which contains
                        the comment from the log line
  -p vt-comment-prefix  Virustotal comment prefix
  --download            Enables Sample Download from Hybrid Analysis. SHA256
                        of sample needed.
  -d download_path      Output Path for Sample Download from Hybrid Analysis.
                        Folder must exist
  --nocache             Do not use cache database file
  --intense             Do use PhantomJS to parse the permalink (used to
                        extract user comments on samples)
  --nocsv               Do not write a CSV with the results
  --verifycert          Verify SSL/TLS certificates
  --sort                Sort the input lines
  --web                 Run Munin as web service
  -w port               Web service port
  --cli                 Run Munin in command line interface mode
  --debug               Debug output
``` 

## Screenshot

![Munin Hosts_Screenshot](https://github.com/Neo23x0/munin/blob/master/screens/munin-hosts.png "Munin Hosts in action")

## Examples

Parse the demo file, extract IPs and hosts, don't just check the domains that are still resolvable and download samples directly from the remote systems.
```
python3 munin-host.py -i your-key.ini -f ./munin-hosts-demo.txt --noresolve --download
```

## Warning

Using `munin-host.py` in an IDS monitored network will cause numerous alerts as munin-host.py performs DNS lookups for malicous domains and has the option to download malicious samples. 

## Issues

### pycurl on macOS

The script `munin-host.py` requires the module `pycurl`. It's sometimes tricky to make it work on macOS as it requires an openssl to be installed, which is then used in the build process. 

If error's occur try the following (some environments will require pip3)
```
pip uninstall pycurl
brew update
brew reinstall openssl
export PKG_CONFIG_PATH="/usr/local/opt/openssl/lib/pkgconfig"
export LDFLAGS="-L/usr/local/opt/openssl/lib"
export CPPFLAGS="-I/usr/local/opt/openssl/include"
export PYCURL_SSL_LIBRARY=openssl
pip install pycurl --global-option="--with-openssl"
```

# Hugin for Virustotal Retrohunts

The Hugin script (`hugin.py`) retrieves and displays information to all samples returned in a retrohunt. The big advantage is that you don't have to wait 15 seconds between each sample request but pull the full JSON result file via v3 of the Virustotal API. This way you get your results immediately. The disadvantage is that other services like Any.run, Hybrid-Analysis, MISP or Valhalla don't get queried with Hugin.

## Usage

```bash
usage: hugin.py [-h] [-r retrohunt-name] [-i ini-file]
                [--csv-path CSV_PATH] [--debug] [--no-comments]

Retrohunt Checker

optional arguments:
  -h, --help           show this help message and exit
  -r retrohunt-name    Name for the queried retrohunt
  -i ini-file           Name of the ini file that holds the VT API key
  --csv-path CSV_PATH  Write a CSV with the results
  --debug              Debug output
  --no-comments        Skip VirusTotal comments
```
## Examples

Parse a retrohunt and export a CSV file with the results.

```
python3 hugin.py -i config-with-your-key.ini -r retrohunt-123456789
```
