# Flydns - Attack surface discovery tool

## What is altdns

Altdns is a DNS recon tool created by [shubs](https://twitter.com/infosec_au), that allows for the discovery of subdomains that conform to patterns. Altdns takes in words that could be present in subdomains under a domain (such as test, dev, staging) as well as takes in a list of subdomains that you know of.

From these two lists that are provided as input to altdns, the tool then generates a _massive_ output of "altered" or "mutated" potential subdomains that could be present. It saves this output so that it can then be used by your favourite DNS bruteforcing tool.

Further information on attack methodology and this tool release can be found here: https://docs.google.com/presentation/d/1PCnjzCeklOeGMoWiE2IUzlRGOBxNp8K5hLQuvBNzrFY/

## What is flydns

Flydns if a fork from altdns. Basically, Altdns just a tool to generate new subdomains from patterns in the given subdomains. But, I decided to update it into a real advanced recon tool, with more techniques. And evenwhat, the main purpose of this tool is: finding subdomains related to given subdomains

## Installation

```
git clone https://github.com/shelld3v/flydns.git
cd flydns
pip install .
```

## Usage

`# flydns -i subdomains.txt -o data_output -w words.txt -S results_output.txt`

- `subdomains.txt` contains the known subdomains for an organization
- `data_output` is a file that will contain the _massive_ list of altered and permuted subdomains
- `words.txt` is your list of words that you'd like to permute your current subdomains with (i.e. `admin`, `staging`, `dev`, `qa`) - one word per line
- the `-S` command tells flydns where to save the results of the resolved permuted subdomains. `results_output.txt` will contain the final list of permuted subdomains found that are valid and have a DNS record.
- the `-t` command limits how many threads the resolver will use simultaneously
- `-d 1.2.3.4` overrides the system default DNS resolver and will use the specified IP address as the resolving server. Setting this to the authoritative DNS server of the target domain *may* increase resolution performance 

## More

This fork is currently in development by @shelld3v, feel free to request a feature!
