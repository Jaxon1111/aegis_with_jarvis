import argparse
import json
import os
import random
import requests
import time
from pprint import pprint
from config import user_agents
from example_queries import queries


HEADERS = {
    "x-api-key": "",
    "User-Agent": random.choice(user_agents.agents),
}


def menu():
    print("""
1. Get API plan info
2. Get IPs from asset banner search
3. Get IPs with CVE from search query
4. Check whether IPs have(s) CVE
5. Get whois info
6. Get domain info
7. Find exploits
8. Example queries
9. Change API Key
10. Exit
    """)


def get_user_api_info(x_api_key):
    url = 'https://api.criminalip.io/v1/user/me'
    data = {
        'x-api-key': x_api_key 
    }
    
    res = requests.post(url=url, headers=HEADERS)
    res = res.json()

    if res['status'] == 401:
        print("Please check your api key from .api_key file")

    if res['status'] == 200:
        data = res['data']
        print("--------------------------------------------------")
        print("account_type : {}".format(data['account_type']))
        print("api_key : {}".format(data['account_type']))
        print("company_name : {}".format(data['company_name']))
        print("email : {}".format(data['email']))
        print("last_access_date : {}".format(data['last_access_date']))
        print("max_search : {}".format(data['max_search']))
        print("membership_date: {}".format(data['membership_date']))
        print("name : {}".format(data['name']))
        print("plan_date: {}".format(data['plan_date']))
        print("--------------------------------------------------")


def get_ips(search_type=None, keyword=None, port=None, product=None, version=None, service=None, tag=None, tech_stack=None, offset=None):
    url = 'https://api.criminalip.io/v1/banner/search'
    params = {
        "query": '',
        "offset": 0,
    }

    if offset:
        params['offset'] = offset

    search_query = ''
    if search_type == 'by_port':
        params['query'] = '{} port: {}'.format(keyword, port)

        options = {'keyword': keyword, 'port': port}
        for k, v in options.items():
            if v:
                if k == 'keyword':
                    search_query += '{} '.format(v)
                else:
                    search_query += '{}:{} '.format(k, v)

    elif search_type == 'by_software':
        params['query'] = '{} product: {} product_version: {}'.format(keyword, product, version)
        search_query = params['query']
        
    elif search_type == 'by_service':
        params['query'] = '{} service: {}'.format(keyword, service)
        search_query = params['query']

    elif search_type == 'by_tag':
        params['query'] = '{} tag: {}'.format(keyword, tag)
        search_query = params['query']

    elif search_type == 'by_tech_stack':
        params['query'] = '{} tech_stack: {}'.format(keyword, tech_stack)
        search_query = params['query']

    ip_list = []
    res = requests.get(url=url, params=params, headers=HEADERS)
    res = res.json()

    if res['status'] == 200:
        for r in res['data']['result']:
            ip_list.append(r['ip_address'])
            print(r['ip_address'])

    print('Criminal_IP Search Query ===> {}'.format(search_query))

    option = input("Do you want to get result count? Y/N : ")
    if option == 'Y' or option == 'y':
        stats_url = 'https://api.criminalip.io/v1/banner/stats'
        res = requests.get(url=stats_url, params=params, headers=HEADERS)
        res = res.json()

        if res['status'] == 200:
            print("Result count : {}".format(res['data']['count']))


def get_cve_ips(query, offset=None):
    url = 'https://api.criminalip.io/v1/banner/search'
    params = {
        "query": query,
        "offset": 0,
    }

    if offset:
        params['offset'] = offset

    ip_list = []
    res = requests.get(url=url, params=params, headers=HEADERS)
    res = res.json()

    if res['status'] == 200:
        for r in res['data']['result']:
            if r['has_cve']:
                ip_list.append(r['ip_address'])
                print(':'.join([r['ip_address'], str(r['open_port_no'])]))

        if len(ip_list) == 0:
            print("IPs with CVE is not found")


def get_whois_data(ip):
    url = 'https://api.criminalip.io/v1/ip/data'
    params = {
        'ip': ip
    }

    res = requests.get(url=url, params=params, headers=HEADERS)
    res = res.json()
    
    if res['status'] == 200:
        data = res['whois']['data'][0]
        print("--------------------------------------------------")
        print('as name: {}'.format(data['as_name']))
        print('as number: {}'.format(data['as_no']))
        print('city: {}'.format(data['city']))
        print('confirmed time: {}'.format(data['confirmed_time']))
        print('latitude: {}'.format(data['latitude']))
        print('longitude: {}'.format(data['longitude']))
        print('org country code: {}'.format(data['org_country_code'].upper()))
        print('org name: {}'.format(data['org_name']))
        print('postal code: {}'.format(data['postal_code']))
        print("--------------------------------------------------")


def get_domain_data(domain):
    url = 'https://api.criminalip.io/v1/domain/scan'
    data = {
        'query': domain
    }

    res = requests.post(url=url, data=data, headers=HEADERS)
    res = res.json()
    
    scan_id = ''
    if res['status'] == 200:
        scan_id = res['data']['scan_id']

    print("Please wait for a moment... (30-40 seconds)")
    while True:
        domain_scan_result_url = 'https://api.criminalip.io/v1/domain/report/{}'.format(scan_id)
        domain_scan_res = requests.get(url=domain_scan_result_url, headers=HEADERS)
        domain_scan_res = domain_scan_res.json()

        time.sleep(3)
        if domain_scan_res['status'] == 200:
            dns_record = domain_scan_res['data']['dns_record']

            print("--------------------------------------------------")
            ipv4 = [ipv4['ip'] for ipv4 in dns_record['dns_record_type_a']['ipv4']]
            ipv6 = [ipv6['ip'] for ipv6 in dns_record['dns_record_type_a']['ipv6']]
            print('dns_record_type_a - ipv4 : {}'.format(', '.join(ipv4)))
            print('dns_record_type_a - ipv6 : {}'.format(', '.join(ipv6)))

            if dns_record['dns_record_type_cname']:
                print('dns_record_type_cname : {}'.format(', '.join(map(str, dns_record['dns_record_type_cname']))))
            if dns_record['dns_record_type_mx']:
                print('dns_record_type_mx : {}'.format(', '.join(map(str, dns_record['dns_record_type_mx']))))
            if dns_record['dns_record_type_ns']:
                print('dns_record_type_ns: {}'.format(', '.join(dns_record['dns_record_type_ns'])))
            if dns_record['dns_record_type_ptr']:
                print('dns_record_type_ptr : {}'.format(', '.join(dns_record['dns_record_type_ptr'])))
            if dns_record['dns_record_type_soa']:
                print('dns_record_type_soa : {}'.format(', '.join(dns_record['dns_record_type_soa'])))
            print("--------------------------------------------------")

            break


def find_exploits(search_type=None, cve_id=None, author=None, edb_id=None, platform=None, exploit_type=None, keyword=None, offset=None):
    url = 'https://api.criminalip.io/v1/exploit/search'
    params = {
        'query': '',
        'offset': 0
    }

    if offset:
        params['offset'] = offset

    if search_type == 'by_cve_id':
        params['query'] = 'cve_id: {}'.format(cve_id)
    elif search_type == 'by_author':
        params['query'] = 'author: {}'.format(author)
    elif search_type == 'by_edb_id':
        params['query'] = 'edb_id: {}'.format(edb_id)
    elif search_type == 'by_platform':
        params['query'] = 'platform: {}'.format(platform)
    elif search_type == 'by_ exploit_type':
        params['query'] = 'type: {}'.format(exploit_type)
    elif search_type == 'by_keyword':
        params['query'] = '{}'.format(keyword)

    res = requests.get(url=url, params=params, headers=HEADERS)
    res = res.json()

    if res['status'] == 200:
        for i, r in enumerate(res['data']['result']):
            print("--------------------------------------------------")
            print("{} / {}".format(i+1, len(res['data']['result'])))
            print("author : {}".format(r['author']))
            print("edb id : {}".format(r['edb_id']))
            print("edb registration date : {}".format(r['edb_reg_date']))
            print("platform : {}".format(r['platform']))
            print("title : {}".format(r['title']))
            print("type : {}".format(r['type']))

    option = input("Do you want to get result count? Y/N : ")
    if option == 'Y' or option == 'y':
        stats_url = 'https://api.criminalip.io/v1/exploit/search'
        res = requests.get(url=stats_url, params=params, headers=HEADERS)
        res = res.json()

        if res['status'] == 200:
            print("Result count : {}".format(res['data']['count']))


def change_api_key(api_key):
    with open('.api_key', 'w') as file:
        file.write(api_key)
        file.close()

    print("Successfully updated your criminal_ip api key")


def main():
    if os.path.exists('.api_key'):
        with open('.api_key', 'r') as file:
            api_key = file.readline().strip()
    else:
        api_key = input("Enter Criminal_IP API KEY : ")
        with open('.api_key', 'w') as file:
            file.write(api_key)
            file.close()

    global HEADERS
    HEADERS['x-api-key'] = api_key
    
    while True:
        menu()

        selected_num = int(input("Enter Selection: "))

        if selected_num == 1:
            get_user_api_info(HEADERS['x-api-key'])

        elif selected_num == 2:
            while True:
                print("""
1. Get IPs by port
2. Get IPs by software product/version
3. Get IPs by service
4. Get IPs by tag
5. Get IPs by tech_stack
6. Return to main menu
""")

                option = int(input("Enter Selection: "))
                if option == 1:
                    keyword = input("Enter keyword(optional): ")
                    port = input("Enter port: ")
                    offset = input("Enter start position(from 0 to 9,900 by 100): ")
                    get_ips(search_type="by_port", keyword=keyword, port=port, offset=offset)

                elif option == 2:
                    keyword = input("Enter keyword(optional): ")
                    product = input("Enter product name: ")
                    version = input("Enter product version(optional): ")
                    offset = input("Enter start position(from 0 to 9,900 by 100): ")
                    get_ips(search_type="by_software", keyword=keyword, product=product, version=version, offset=offset)

                elif option == 3:
                    keyword = input("Enter keyword(optional): ")
                    service = input("Enter service name: ")
                    offset = input("Enter start position(from 0 to 9,900 by 100): ")
                    get_ips(search_type="by_service", keyword=keyword, service=service, offset=offset)

                elif option == 4:
                    keyword = input("Enter keyword(optional): ")
                    tag = input("Enter tag (ex: https): ")
                    offset = input("Enter start position(from 0 to 9,900 by 100): ")
                    get_ips(search_type="by_tag", keyword=keyword, tag=tag, offset=offset)

                elif option == 5:
                    keyword = input("Enter keyword(optional): ")
                    tech_stack = input("Enter tech stack (ex: jQuery): ")
                    offset = input("Enter start position(from 0 to 9,900 by 100): ")
                    get_ips(search_type="by_tech_stack", keyword=keyword, tech_stack=tech_stack, offset=offset)

                elif option == 6:
                    break

        elif selected_num == 3:
            query = input("Enter search query: ")
            offset = input("Enter start position(from 0 to 9,900 by 100): ")
            if not query:
                print("Search query is necessary")
                break

            get_cve_ips(query=query, offset=offset)

        elif selected_num == 4:
            ip = input("Enter IP or IP/CIDR: ")
            offset = input("Enter start position(from 0 to 9,900 by 100): ")
            if not ip:
                print("IP is necessary")
                break

            query = 'ip: {}'.format(ip)
            get_cve_ips(query=query, offset=offset)

        elif selected_num == 5:
            ip = input("Enter IP : ")

            get_whois_data(ip=ip)
            
        elif selected_num == 6:
            domain = input("Enter domain: ")

            get_domain_data(domain=domain)

        elif selected_num == 7:
            while True:
                print("""
1. Get exploits by cve_id 
2. Get exploits by author 
3. Get exploits by edb_id
4. Get exploits by platform 
5. Get exploits by type 
6. Get exploits by keyword
7. Return to main menu
""")

                option = int(input("Enter Selection: "))
                if option == 1:
                    cve_id = input("Enter CVE_ID : ")
                    offset = input("Enter start position(from 0 to 9,900 by 100): ")
                    find_exploits(search_type="by_cve_id", cve_id=cve_id, offset=offset)

                elif option == 2:
                    author = input("Enter author : ")
                    offset = input("Enter start position(from 0 to 9,900 by 100): ")
                    find_exploits(search_type="by_author", author=author, offset=offset)

                elif option == 3:
                    edb_id = input("Enter edb id : ")
                    offset = input("Enter start position(from 0 to 9,900 by 100): ")
                    find_exploits(search_type="by_edb_id", edb_id=edb_id, offset=offset)

                elif option == 4:
                    platform = input("Enter platform : ")
                    offset = input("Enter start position(from 0 to 9,900 by 100): ")
                    find_exploits(search_type="by_platform", platform=platform, offset=offset)

                elif option == 5:
                    exploit_type = input("Enter exploit type : ")
                    offset = input("Enter start position(from 0 to 9,900 by 100): ")
                    find_exploits(search_type="by_exploit_type", exploit_type=exploit_type, offset=offset)

                elif option == 6:
                    keyword = input("Enter keyword : ")
                    offset = input("Enter start position(from 0 to 9,900 by 100): ")
                    find_exploits(search_type="by_keyword", keyword=keyword, offset=offset)

                elif option == 7:
                    break

        elif selected_num == 8:
            print("Example queries are below :")

            i = 0
            for k, v in queries.items():
                i += 1
                print('{} : {}'.format(i, v))
                    
        elif selected_num == 9:
            api_key = input("Enter Criminal_IP API KEY : ")
            change_api_key(api_key)

        elif selected_num == 10:
            exit("Exit")

        else:
            print("Selected invalid number, please select again")


if __name__ == '__main__':
    main()

