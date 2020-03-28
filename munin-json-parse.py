#!/usr/bin/python

import json
import sys
import colorama
from colorama import Fore,Style

with open(sys.argv[1], "r") as f:
	data = json.load(f)
print ("----------------------------------------------------")

print ( "Total Hash Count : %s" % len(data))
print ( "Showing Suspicious and Malicious Entries Only")
print ("----------------------------------------------------")

for x in data:
	if not any(s in x['rating'] for s in ('unknown', 'clean')):
		if 'malicious' in x['rating']:	
			print (Fore.RED + "%s has been detected by %s AVs and rated as %s, Possible Filenames include %s." % (x['hash'], x['result'], x['rating'], x['filenames']))
			print(Style.RESET_ALL, end='')
		else:
			print ("%s has been detected by %s AVs and rated as %s." % (x['hash'], x['result'], x['rating']))



