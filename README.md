netrecon_suite
A big bash script I wrote because I got tired of typing the same 30 networkcommands every time I sat down to look at a box.

You give it a target — an IP, a domain, a subnet, or just the word "local" —and it asks you literally one question, then runs the whole toolbox for you:DNS records, whois, traceroutes, ARP scans, ping tests, nmap, banner grabs,TLS checks, packet captures... all of it. Everything lands in a timestampedfolder so you can actually find your results later instead of scrollingthrough your terminal history at 2am.

The deal
Only run this against stuff you own or have permission to test.Seriously. Read DISCLAIMER.md before you touch anything. Scanning otherpeople's machines without asking is illegal almost everywhere and it's notmy problem when it goes wrong.

Quick start
git clone https://github.com/YOURNAME/netrecon-suite.gitcd netrecon-suitechmod +x netrecon_suite.sh./netrecon_suite.sh
It'll ask for a target. Type one in. Walk away. Come back to a folder fullof organized results and a FINAL_REPORT.txt that sums it all up.

What it actually does
Four modules, auto-picked based on what kind of target you gave it:

Module 1 - DNS & routing: dig, whois, traceroute (three flavors),mtr, ASN lookup, geoip, subdomain enum if you have the tools installed
Module 2 - local network: arp-scan, nmap sweeps, fping, netdiscover,figures out what devices are on your LAN and who made their network cards
Module 3 - performance: ping profiles, jitter, mtr, live TCP statswith ss, iperf3, curl timing breakdown, packet capture + tshark stats
Module 4 - black box audit: the full nmap zoo, masscan, zmap, hping3,grabs service banners by hand, openssl/sslscan/testssl, nikto, the works
Useful flags
./netrecon_suite.sh 8.8.8.8              # no questions at all./netrecon_suite.sh example.com -m 1,3   # only modules 1 and 3./netrecon_suite.sh local --fast         # quick local look, shorter timeouts./netrecon_suite.sh target --ask         # put the safety prompts back on
Everything else (--timeout, -o, --iface, --zombie, --evasive) is in--help along with all the default values.

Changing the defaults
Crack open the script and find the big block near the top that saysUSER-CONFIGURABLE DEFAULTS. Every timeout, ping count, scan rate andfallback chain lives there with comments. Change it once, it's changedforever. A copy of your live settings gets dropped into every resultsfolder as README.md too, so you always know exactly how a run behaved.

Missing tools? It doesn't care (much)
You don't need all ~45 tools installed. The script checks what exists andwalks fallback chains (dig -> host -> nslookup, ncat -> nc -> pure bash,and so on). Whatever's missing just gets logged as SKIPPED with a reason.requirements.txt has the full shopping list if you want everything.

Self-tests (safe, no network traffic)
NETRECON_STEP2_SELFTEST=1 bash netrecon_suite.shNETRECON_STEP8_SELFTEST=1 bash netrecon_suite.sh
Both should print a bunch of "pass" lines and exit clean. If they don't,something's broken - open an issue.

Tested on
Kali, Ubuntu, Arch (and WSL2). bash 4+. Runs fine without root, but halfthe fun tools want sudo, so most people should just run it with sudo.
