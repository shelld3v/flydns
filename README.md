# Flydns - Related subdomains discovery tool

## What is flydns

Flydns was first a fork of altdns, but then has been updated to become a separated recon tool.

Flydns will try to find related subdomains from user given subdomains, by generating permutations, mutations, alterations. The alterations came from combinations between wordlist entries and subdomains patterns.

## Installation

```
git clone https://github.com/shelld3v/flydns.git
cd flydns
pip install .
```

## Usage

`# flydns -i subdomains.txt -o output_subdomains.txt -S resolved.txt`

- `-i`: Subdomains list, you can try `-s` with your subdomains if you don't want to save them into a file.
- `-o`: Output of altered and permuted subdomains.
- `-w`: Your wordlist.
- `-S`: Output of resolved subdomains.
- `-t`: How many threads the resolver will use simultaneously
- `-d`: System DNS resolver
- `-p`: Ports to scan
- `-n`: Add number suffix to every domain (0-9)
- `-W`: Perform Whois lookup for every resolved subdomains

## More

This tool is currently in development by @shelld3v, feel free to request a feature!
