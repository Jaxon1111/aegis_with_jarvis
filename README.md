# Purpose of this project
I found a repository called ShonyDanza on github and tried it out. ShonyDanza is a project that uses Shodan's search data and additional features to create pentesting/cyberdefense capabilities, and it looked pretty interesting to me. After using ShonyDanza for myself, I thought that if this premise applied to other OSINT tools, the data pool could geta lot bigger than Shodan alone, so I found a free search engine called Criminal IP and made a program that essentially does what shonydanza does.



# Prerequisites

* Python3
* Criminal IP - API key (You can get it from 'criminalip.io')



# Usage

1. git clone https://github.com/Jaxon1111/aegis_with_jarvis.git
2. activate virtualenv & install requirements
   1. source .venv/bin/activate
   2. pip3 install -r requirements.txt



# How to get started

$ python3 aegis_with_jarvis.py



# Select Options

1.  Get API plan info
2.  Get IPs from asset banner search
    a.  Get IPs by port
    b.  Get IPs by software product/version
    c.  Get IPs by service
    d.  Get IPs by tag
    e.  Get IPs by tech_stack
3.  Get IPs with CVE from search query
4.  Check whether IPs have(s) CVE
5.  Get whois info
6.  Get domain info
7.  Find exploits
    a.  Get exploits by cve_id
    b.  Get exploits by author
    c.  Get exploits by edb_id
    d.  Get exploits by platform
    e.  Get exploits by type
    f.  Get exploits by keyword
    g.  Return to main menu
8.  Example queries
9.  Change API Key
10.  Exit



# Issue / Feedback etc.

Thanks for using aegis_with_jarvis! If you have any issues/feedback you want to tell me, just leave a comment or pop me an email.

You're always welcome to add a sample pull request added to example_queries.py.
