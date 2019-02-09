    _________   _    _   ______  _____  ______
    | | | | | \ | |  | | | |  \ \  | |  | |  \ \
    | | | | | | | |  | | | |  | |  | |  | |  | |
    |_| |_| |_| \_|__|_| |_|  |_| _|_|_ |_|  |_|

    Online Hash Checker for Virustotal and Other Services
    Florian Roth

## What is Munin?

Munin is a online hash checker utility that retrieves valuable information from various online sources

The current version of Munin queries the following services:

- Virustotal
- Malshare
- HybridAnalysis

Note: Munin is based on the script "VT-Checker", which has been maintained in the LOKI repository 

## Screenshot

![Munin Screenshot](https://github.com/Neo23x0/munin/blob/master/screens/munin.png "Munin in action")

## Usage

    usage: munin.py [-h] [-f path] [-c cache-db] [-i ini-file] [-s sample-folder]
                    [--comment] [-p vt-comment-prefix] [--download]
                    [-d download_path] [--nocache] [--intense] [--retroverify]
                    [-r num-results] [--nocsv] [--verifycert] [--sort] [--debug]

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
      --retroverify         Check only 40 entries with the same comment and
                            therest at the end of the run (retrohunt verification)
      -r num-results        Number of results to take as verification
      --nocsv               Do not write a CSV with the results
      --verifycert          Verify SSL/TLS certificates
      --sort                Sort the input lines (useful for VT retrohunt results)
      --debug               Debug output

## Features

- MODE A: Extracts hashes from any text file based on regular expressions
- MODE B: Walks sample directory and checks hashes online
- Retrieves valuable information from Virustotal via API (JSON response) and other information via permalink (HTML parsing)
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
- Queries Hybrid-Analysis.com for present analysis
- Imphash duplicates in current batch > allows you to spot overlaps in import table hashes

## Getting started

1. Download / clone the repo
2. Install required packages: `pip3 install -r requirements.txt` (on macOS add `--user`)
3. (optional: required for --intense mode) Download PhantomJS and place it in your $PATH, e.g. /usr/local/bin [http://phantomjs.org/download.html](http://phantomjs.org/download.html)
4. Set the API key for the different services in the `munin.ini` file
5. Use the demo file for a first run: `python munin.py -f munin-demo.txt --nocache`

## Typical Command Lines

Process a Virustotal Retrohunt result and sort the lines before checking so that matched signatures are checked in blocks

```bash
python munin.py -f my.ini -f ~/Downloads/retro_hunt
```

Process an IOC file and show who commented on these samples on Virustotal (uses PhantomJS, higher CPU usage)

```bash
python munin.py -f my.ini -f ~/Downloads/misp-event-1234.csv --sort --intense
```

Process a directory with samples and check their hashes online

```bash
python munin.py -f my.ini -s ~/malware/case34
```

## Get the API Keys used by Munin

### Virustotal

1. Create an account here [https://www.virustotal.com/#/join-us](https://www.virustotal.com/#/join-us)
2. Check `Profile > My API key` for your public API key

### Malshare

Register here [https://malshare.com/register.php](https://malshare.com/register.php)

### Hybrid Analysis

1. Create an account here [https://www.hybrid-analysis.com/signup](https://www.hybrid-analysis.com/signup)
2. After login, check `Profile > API key`

# Munin Hosts

The Munin host and IP checker script (`munin-host.py`) retrieves more information on IP addresses and host/domain names in IOC lists. 

## Usage

```bash
usage: munin-host.py [-h] [-f path] [-m max-items] [-c cache-db] [-i ini-file]
                     [--nocache] [--nocsv] [--recursive] [--download]
                     [-o output-folder] [--dups] [--noresolve] [--ping]
                     [--debug]

Virustotal Online Checker (IP/Domain)

optional arguments:
  -h, --help        show this help message and exit
  -f path           File to process (hash line by line OR csv with hash in
                    each line - auto-detects position and comment)
  -m max-items      Maximum number of items (urls, hosts, samples) to show
  -c cache-db       Name of the cache database file (default: vt-hosts-
                    db.json)
  -i ini-file       Name of the ini file that holds the API keys
  --nocache         Do not use the load the cache db (vt-check-cache.pkl)
  --nocsv           Do not write a CSV with the results
  --recursive       Process the resolved IPs as well
  --download        Try to download the URLs (directories with host/ip names)
  -o output-folder  Store the downloads to the given directory
  --dups            Do not skip duplicate hashes
  --noresolve       Do not perform DNS resolve test on found domain names
  --ping            Perform ping check on IPs (speeds up process if many
                    public but internally routed IPs appear in text file)
  --debug           Debug output
``` 

## Screenshot

![Munin Hosts_Screenshot](https://github.com/Neo23x0/munin/blob/master/screens/munin-hosts.png "Munin Hosts in action")

## Examples

Parse the demo file, extract IPs and hosts, don't just check the domains that are still resolvable and download samples directly from the remote systems.
```
python3 munin-hosts.py -i your-key.ini -f ./munin-hosts-demo.txt --noresolve --download
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
