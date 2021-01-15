# FlyDNS - Related subdomains discovery tool

## What is FlyDNS

FlyDNS was first a fork of Altdns, but then has been updated to become a separated recon tool.

FlyDNS will try to find related subdomains from user given subdomains, by generating permutations, mutations, alterations. The alterations came from combinations between wordlist entries and subdomains patterns.

## Installation

```
git clone https://github.com/shelld3v/flydns.git
cd flydns
pip3 install .
```

## Usage

| Flag | Description
|------|------------------------------------------------------
|  -s  | Target subdomains
|  -i  | Subdomains list from a file
|  -o  | Output of altered and permuted subdomains.
|  -w  | Your wordlist.
|  -f  | Output of resolved subdomains.
|  -t  | How many threads the resolver will use simultaneously
|  -r  | Perform discovery recursively
|  -d  | System DNS resolvers
|  -e  | Exclude subdomains by DNS answers
|  -R  | Reverse DNS lookup for IP addresses
|  -p  | Ports to scan
|  -a  | Look for only active subdomains
|  -n  | Add number suffix to every domain (0-9)
|  -W  | Perform Whois lookup for every resolved subdomains

Example: `flydns -i subdomains.txt -o output_subdomains.txt -f resolved_result.txt`

## More

This tool is currently in development by @shelld3v, feel free to request a feature!
