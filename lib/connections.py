#!/usr/bin/env python3

PROXY = {}

def setProxy(proxy_string):
    # Create valid ProxyDict 
    if proxy_string != "-":
        PROXY = {'http': proxy_string, 'https': proxy_string}
    # No proxy if nothing is set in .ini
    else:
        PROXY = {}