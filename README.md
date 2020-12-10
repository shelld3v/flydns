# Altdns - Subdomain discovery through alterations and permutations | Re-developed by @shelld3v

Altdns is a DNS recon tool that allows for the discovery of subdomains that conform to patterns. Altdns takes in words that could be present in subdomains under a domain (such as test, dev, staging) as well as takes in a list of subdomains that you know of.

From these two lists that are provided as input to altdns, the tool then generates a _massive_ output of "altered" or "mutated" potential subdomains that could be present. It saves this output so that it can then be used by your favourite DNS bruteforcing tool.

Alternatively, the `-r` flag can be passed to altdns so that once this output is generated, the tool can then resolve these subdomains (multi-threaded) and save the results to a file.

Altdns works best with large datasets. Having an initial dataset of 200 or more subdomains should churn out some valid subdomains via the alterations generated.

Further information on attack methodology and this tool release can be found here: https://docs.google.com/presentation/d/1PCnjzCeklOeGMoWiE2IUzlRGOBxNp8K5hLQuvBNzrFY/

# Installation

```
git clone https://github.com/shelld3v/altdns.git
cd altdns
pip install .
```

# Usage

`# altdns -i subdomains.txt -o data_output -w words.txt -S results_output.txt`

- `subdomains.txt` contains the known subdomains for an organization
- `data_output` is a file that will contain the _massive_ list of altered and permuted subdomains
- `words.txt` is your list of words that you'd like to permute your current subdomains with (i.e. `admin`, `staging`, `dev`, `qa`) - one word per line
- the `-S` command tells altdns where to save the results of the resolved permuted subdomains. `results_output.txt` will contain the final list of permuted subdomains found that are valid and have a DNS record.
- the `-t` command limits how many threads the resolver will use simultaneously
- `-d 1.2.3.4` overrides the system default DNS resolver and will use the specified IP address as the resolving server. Setting this to the authoritative DNS server of the target domain *may* increase resolution performance 

# Screenshots

<img src="https://i.imgur.com/fkfZqkl.png" width="600px"/>

<img src="https://i.imgur.com/Jyfue26.png" width="600px"/>

# More

This fork is currently in development by @shelld3v, feel free to request a feature!
