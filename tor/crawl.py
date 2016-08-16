#!/usr/bin/env python3
import socks
import socket
import requests
import sys
import re
import argparse
from urllib.parse import urljoin

# command line options
parser = argparse.ArgumentParser()
parser.add_argument("url", help="url to be crawled (eg. http://example.com)")
parser.add_argument("-d", metavar="depth", default=2, type=int, help="depth to crawl (default 2)")
parser.add_argument("-t", metavar="threads", default=5, type=int, help="number of threads (default 5)")
parser.add_argument("--tor", action="store_true", help="use Tor for anonymous crawling")
args = parser.parse_args()

def startTor():
    socks.setdefaultproxy(proxy_type=socks.PROXY_TYPE_SOCKS5, addr="127.0.0.1", port=9050)
    socket.socket = socks.socksocket

def crawl(url, depth, emails):
    # limit recursion
    if (depth == 0):
        return

    print("Crawling link: " + url)

    # email regex
    email_regex = re.compile(r'([\w\.,]+@[\w\.,]+\.\w+)')
    # <a> regex
    link_regex = re.compile(r'href="(.*?)"')

    # get the webpage
    try:
        req = requests.get(url)
    except KeyboardInterrupt:
        printFinal(emails)
        print("[*] User exit\n")
        sys.exit()
    except:
        return

    result = []

    # check if request successful
    if (req.status_code != 200):
        return

    # find all links and remove duplicates
    links = list(set(link_regex.findall(req.text)))

    # crawl all links
    for link in links:
        # get absolute url for a link
        link = urljoin(url, link)
        crawl(link, depth - 1, emails)

    # find all emails on current page
    result += email_regex.findall(req.text)
    #return list without duplicates
    emails += list(set(result))

def printFinal(emails):
    print("\n[*] Retrieved emails:")
    for email in emails:
        print("    " + email)
    print()


if __name__ == "__main__":

    print("Regular IP: " + requests.get("http://icanhazip.com").text)

    if args.tor:
        startTor()
        print("Tor IP: " + requests.get("http://icanhazip.com").text)

    emails = []

    crawl(args.url, args.d, emails)
    emails = list(set(emails))
    printFinal(emails)


'''
Installation:
    apt-get install python3-pip
    pip3 install pysocks
'''
