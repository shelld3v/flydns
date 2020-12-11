#!/usr/bin/env python3
# released at BSides Canberra by @infosec_au and @nnwakelam
# updated with <3 by @shelld3v

import argparse
import threading
import time
import datetime
import socket
from threading import Lock
from queue import Queue as Queue

import tldextract
from tldextract.tldextract import LOG
import logging
from termcolor import colored
from ipwhois import IPWhois
import dns.resolver
import os
from warnings import filterwarnings

logging.basicConfig(level=logging.CRITICAL)
filterwarnings(action="ignore")

banner =  colored("="*70 + "\n", "blue")
banner += colored("Flydns v0.1                         https://github.com/shelld3v/flydns\n", "cyan")
banner += colored("="*70, "blue")

def get_alteration_words(wordlist_fname):
    with open(wordlist_fname, "r") as f:
        words = f.readlines()
    for line in fp:
        words.extend(line.strip().split("."))
        
    return list(dict.fromkeys(words))

# will write to the file if the check returns true
def write_domain(args, wp, full_url):
    wp.write(full_url)

# function inserts words at every index of the subdomain
def insert_all_indexes(args, alteration_words):
    with open(args.output_tmp, "a") as wp:
        for line in fp:
            ext = tldextract.extract(line.strip())
            current_sub = ext.subdomain.split(".")

            for word in alteration_words:
                for index in range(0, len(current_sub)):
                    current_sub.insert(index, word.strip())

                    # join the list to make into actual subdomain (aa.bb.cc)
                    actual_sub = ".".join(current_sub)

                    # save full URL as line in file
                    full_url = "{0}.{1}.{2}\n".format(
                        actual_sub, ext.domain, ext.suffix)
                    if actual_sub[-1:] != ".":
                        write_domain(args, wp, full_url)
                    current_sub.pop(index)
                current_sub.append(word.strip())
                actual_sub = ".".join(current_sub)
                full_url = "{0}.{1}.{2}\n".format(
                    actual_sub, ext.domain, ext.suffix)

                if len(current_sub[0]) > 0:
                    write_domain(args, wp, full_url)
                current_sub.pop()

# adds word-NUM and wordNUM to each subdomain at each unique position
def insert_number_suffix_subdomains(args, alternation_words):
    with open(args.output_tmp, "a") as wp:
        for line in fp:
            ext = tldextract.extract(line.strip())
            current_sub = ext.subdomain.split(".")

            for word in range(0, 10):
                for index, value in enumerate(current_sub):
                    #add word-NUM
                    original_sub = current_sub[index]
                    current_sub[index] = current_sub[index] + "-" + str(word)

                    # join the list to make into actual subdomain (aa.bb.cc)
                    actual_sub = ".".join(current_sub)

                    # save full URL as line in file
                    full_url = "{0}.{1}.{2}\n".format(actual_sub, ext.domain, ext.suffix)
                    write_domain(args, wp, full_url)
                    current_sub[index] = original_sub

                    # add wordNUM
                    original_sub = current_sub[index]
                    current_sub[index] = current_sub[index] + str(word)

                    # join the list to make into actual subdomain (aa.bb.cc)
                    actual_sub = ".".join(current_sub)

                    # save full URL as line in file
                    full_url = "{0}.{1}.{2}\n".format(actual_sub, ext.domain, ext.suffix)
                    write_domain(args, wp, full_url)
                    current_sub[index] = original_sub

# adds word- and -word to each subdomain at each unique position
def insert_dash_subdomains(args, alteration_words):
    with open(args.output_tmp, "a") as wp:
        for line in fp:
            ext = tldextract.extract(line.strip())
            current_sub = ext.subdomain.split(".")

            for word in alteration_words:
                for index, value in enumerate(current_sub):
                    original_sub = current_sub[index]
                    current_sub[index] = current_sub[
                        index] + "-" + word.strip()

                    # join the list to make into actual subdomain (aa.bb.cc)
                    actual_sub = ".".join(current_sub)

                    # save full URL as line in file
                    full_url = "{0}.{1}.{2}\n".format(
                        actual_sub, ext.domain, ext.suffix)
                    if len(current_sub[0]) > 0 and actual_sub[:1] != "-":
                        write_domain(args, wp, full_url)
                    current_sub[index] = original_sub

                    # second dash alteration
                    current_sub[index] = word.strip() + "-" + \
                        current_sub[index]
                    actual_sub = ".".join(current_sub)

                    # save second full URL as line in file
                    full_url = "{0}.{1}.{2}\n".format(
                        actual_sub, ext.domain, ext.suffix)
                    if actual_sub[-1:] != "-":
                        write_domain(args, wp, full_url)
                    current_sub[index] = original_sub

# adds prefix and suffix word to each subdomain
def join_words_subdomains(args, alteration_words):
    with open(args.output_tmp, "a") as wp:
        for line in fp:
            ext = tldextract.extract(line.strip())
            current_sub = ext.subdomain.split(".")
            for word in alteration_words:
                for index, value in enumerate(current_sub):
                    original_sub = current_sub[index]
                    current_sub[index] = current_sub[index] + word.strip()

                    # join the list to make into actual subdomain (aa.bb.cc)
                    actual_sub = ".".join(current_sub)

                    # save full URL as line in file
                    full_url = "{0}.{1}.{2}\n".format(
                        actual_sub, ext.domain, ext.suffix)
                    write_domain(args, wp, full_url)
                    current_sub[index] = original_sub

                    # second dash alteration
                    current_sub[index] = word.strip() + current_sub[index]
                    actual_sub = ".".join(current_sub)

                    # save second full URL as line in file
                    full_url = "{0}.{1}.{2}\n".format(
                        actual_sub, ext.domain, ext.suffix)
                    write_domain(args, wp, full_url)
                    current_sub[index] = original_sub

# scanning for open ports
def scan_ports(args, target):
    open_ports = []
    ports = args.ports.split(",")
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(2.5)

        try:
            sock.connect((target, int(port)))
            sock.close()
            open_ports.append(port)
        except:
            pass

    return open_ports

# Check if the domain is resolvable or not then do further actions
def dns_resolve(args, q, target, resolved_out):
    global progress
    global lock
    global starttime
    global found
    global resolverName
    lock.acquire()
    progress += 1
    lock.release()

    if not args.quiet and progress % 500 == 0:
        lock.acquire()
        left = linecount-progress
        secondspassed = (int(time.time())-starttime)+1
        amountpersecond = progress / secondspassed
        lock.release()
        seconds = 0 if amountpersecond == 0 else int(left/amountpersecond)
        timeleft = str(datetime.timedelta(seconds=seconds))
        print(
            colored("[*] Progress: {0:.2f}, approximate {1} left".format((progress/linecount) * 100, timeleft),
                    "blue")
        )

    final_hostname = target
    result = list()
    result.append(target)

    # if a DNS server has been manually specified
    if resolverName:
        resolver.nameservers = [resolverName]
    try:
        for rdata in resolver.query(final_hostname, 'CNAME'):
            result.append(rdata.target)
            record = "CNAME"
    except dns.resolver.NXDOMAIN:
        return
    except:
        pass

    if len(result) == 1:
        try:
            if resolverName:
                A = resolver.query(final_hostname, "A")
                if len(A) > 0:
                    result = list()
                    result.append(final_hostname)
                    result.append(str(A[0]))
            else:
                A = socket.gethostbyname(final_hostname)
                result = list()
                result.append(final_hostname)
                result.append(A)
            record = "A"

        except:
            pass

    # will always have 1 item (target)
    if len(result) > 1:
        if str(result[1]) in found:
            if found[str(result[1])] > 3:
                return
            else:
                found[str(result[1])] = found[str(result[1])] + 1
        else:
            found[str(result[1])] = 1

        # port scan the domain
        if args.ports:
            ports = scan_ports(args, result[0])
        else:
            ports = []

        if args.whois:
            obj = IPWhois(socket.gethostbyname(final_hostname))
            info = obj.lookup_whois()
        else:
            info = None

        resolved_out.write(str(result[0]) + ":" + str(result[1]) + "\n")
        resolved_out.flush()
        ext = tldextract.extract(str(result[1]))

        if ext.domain == "amazonaws":
            try:
                for rdata in resolver.query(result[1], 'CNAME'):
                    result.append(rdata.target)
            except:
                pass
        print(
            colored(
                result[0],
                "red") +
            " : " +
            colored(
                "{0} {1}".format(record, result[1]),
                "green"),
            end="")

        if len(result) > 2 and result[2]:
            print(
                colored(
                    result[0],
                    "red") +
                " : " +
                colored(
                    "{0} {1}".format(record, result[1]),
                    "green") +
                ": " +
                colored(
                    result[2],
                    "blue"),
                end="")

        if ports:
            print(
                colored(
                    " (" + ", ".join(ports) + ")",
                    "yellow")
            )
        else:
            print()

        if info:
            try:
                print(colored("  | {0}".format(info["asn_description"]), "yellow"))
                print(colored("  | ASN:     {0}".format(info["asn"]), "yellow"))
                print(colored("  | CIDR:    {0}".format(info["asn_cidr"]), "yellow"))
                print(colored("  | Date:    {0}".format(info["asn_date"]), "yellow"))
                print(colored("  | Country: {0}".format(info["asn_country_code"]), "yellow"))
                print(colored("  | Emails:  {0}".format(", ".join(info["nets"][0]["emails"])), "yellow"))
            except:
                pass

    q.put(result)

def remove_duplicates(args):
    with open(args.output) as b:
        blines = set(b)
        with open(args.output, 'w') as result:
            for line in blines:
                result.write(line)

def remove_existing(args):
    with open(args.input) as b:
        blines = set(b)
    with open(args.output_tmp) as a:
        with open(args.output, 'w') as result:
            for line in a:
                if line not in blines:
                    result.write(line)
    os.remove(args.output_tmp)


def main():
    global fp
    global progress
    global linecount
    global lock
    global starttime
    global found
    global resolverName
    global resolver

    q = Queue()

    parser = argparse.ArgumentParser(description="Flydns v0.1")
    parser.add_argument("-s", "--subdomains",
                        help="Subdomains (separated by ',')", required=False)
    parser.add_argument("-i", "--input",
                        help="List of subdomains", required=False)
    parser.add_argument("-o", "--output",
                        help="Output location for altered subdomains",
                        required=True)
    parser.add_argument("-w", "--wordlist",
                        help="List of words to alter the subdomains with",
                        required=False, default="words.txt")
    parser.add_argument("-p", "--ports",
                        help="Scan for ports", required=False)
    parser.add_argument("-n", "--add-number-suffix",
                        help="Add number suffix to every domain (0-9)",
                        action="store_true")
    parser.add_argument("-e", "--ignore-existing",
                        help="Ignore existing domains in file", action="store_true")
    parser.add_argument("-d", "--dnsserver",
                        help="IP address of resolver to use (overrides system default)",
                        required=False)
    parser.add_argument("-S", "--save",
                        help="File to save resolved altered subdomains to",
                        required=False)
    parser.add_argument("-W", "--whois",
                        help="Whois lookup to get more information", action="store_true")
    parser.add_argument("-t", "--threads",
                        help="Amount of threads to run simultaneously (Default: 50)",
                        required=False, default="50")
    parser.add_argument("-q", "--quiet",
                        help="Quiet mode", action="store_true")

    args = parser.parse_args()

    if not args.subdomains and not args.input:
        print("No target selected, -h for more information")
        exit(0)
    elif args.subdomains:
        tmp = open(".flydns.tmp", "w+")
        for subdomain in args.subdomains.split(","):
            tmp.write(subdomain + "\n")
        tmp.close()
        args.input = ".flydns.tmp"

    try:
        fp = open(args.input, "r").readlines()
    except:
        print("Unable to open {0}".format(args.input))

    try:
        resolved_out = open(args.save, "a")
    except:
        print("Please provide a file name to save results to via the -S argument")
        raise SystemExit

    alteration_words = get_alteration_words(args.wordlist)

    # if we should remove existing, save the output to a temporary file
    if args.ignore_existing:
        args.output_tmp = args.output + '.tmp'
    else:
        args.output_tmp = args.output

    # wipe the output before, so we fresh alternated data
    open(args.output_tmp, 'w').close()

    insert_all_indexes(args, alteration_words)
    insert_dash_subdomains(args, alteration_words)

    if args.add_number_suffix:
        insert_number_suffix_subdomains(args, alteration_words)

    join_words_subdomains(args, alteration_words)

    threadhandler = []

    # Removes already existing + dupes from output
    if args.ignore_existing is True:
        remove_existing(args)
    else:
        remove_duplicates(args)

    if not args.quiet:
        print(banner)

    lock = Lock()
    found = {}
    progress = 0
    starttime = int(time.time())
    linecount = len(open(args.output, "r").readlines())
    resolverName = args.dnsserver
    resolver = dns.resolver.Resolver()
    resolver.timeout = 1
    resolver.lifetime = 1

    with open(args.output, "r") as fp:
        for i in fp:
            if args.threads:
                if len(threadhandler) > int(args.threads):

                    # wait until there is only half of the threads are alive
                    try:
                        while len(threadhandler) > int(args.threads)/2:
                            threadhandler.pop().join()
                    except KeyboardInterrupt:
                        print(
                            colored("[!] Keyboard Interrupted", "red")
                        )
                        threading.Event().set()
                        exit(0)

            try:
                t = threading.Thread(
                    target=dns_resolve, args=(
                        args, q, i.strip(), resolved_out))
                t.daemon = True
                threadhandler.append(t)
                t.start()
            except Exception as error:
                print(
                    colored("[!] Error: {0}".format(error),
                           "red")
                )

        # wait for threads
        try:
            while len(threadhandler) > 0:
                threadhandler.pop().join()
        except KeyboardInterrupt:
                print(
                    colored("[!] Keyboard Interrupted", "red")
                )
                threading.Event().set()
                exit(0)

    if not args.quiet:
        timetaken = str(datetime.timedelta(seconds=(int(time.time())-starttime)))
        print(
            colored("[*] Completed in {0}".format(timetaken),
                "blue")
        )

if __name__ == "__main__":
    main()
