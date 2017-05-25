# Forensic Tools

A collection of penetration testing, analytics, and forensic tools that I wrote in summer 2016.

### IP Checker:

* Uses VirusTotal, location, spam blacklist, and registrar data to determine if a given IP is associated with malicious material.

![IP Checker](http://i.imgur.com/znjFCK8.png)

### Disk Analyzer:

* Queries multiple tools such as VirusTotal, WildFire, ClamAV, and NSRL to perform deep analysis on a forensic disk image.

![Disk Tool](http://i.imgur.com/uEAAkhy.png)

### Tor Web Crawler

* Connects to the Tor network and does web scraping for email addresses.
* Follows links on webpages so it can quickly find data for a specific domain.

### dnmap

* Builds a master-slave dnmap implementation to provide distributed port scanning for load-balancing and covert reconnaissance.
* Uses SaltStack to build, start, or destroy an arbitrary number of AWS scanner slaves with a single command. 
