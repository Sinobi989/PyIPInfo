import subprocess
import shodan
import re
import asyncio
import requests
import json
import datetime
import pycountry
import ipaddress
from aiohttp import ClientSession
from bs4 import BeautifulSoup

Shodan_API_Key = ""  # Replace with your Shodan API key
VT_API_KEY = ""  # Replace with your VirusTotal API key
AbuseIPDB_API_KEY = ""  # Replace with your AbuseIPDB API key



def ping(IP):
    try:
        subprocess.check_output(['ping', '-n', '1', IP], shell=True)
        return True
    except subprocess.CalledProcessError:
        return False


def country_code_to_name(country_code):
    try:
        country = pycountry.countries.get(alpha_2=country_code)
        return country.name
    except KeyError:
        return "Unknown"


def AbuseIPDB_check(IP):
    url = 'https://api.abuseipdb.com/api/v2/check'

    querystring = {
        'ipAddress': IP,
        'maxAgeInDays': '90'
    }

    headers = {
        'Accept': 'application/json',
        'Key': AbuseIPDB_API_KEY
    }

    response = requests.request(method='GET', url=url, headers=headers, params=querystring)
    json_response = response.json()
    parsed_data = json.loads(json.dumps(json_response))

    # Extract desired parameters
    total_reports = parsed_data["data"]["totalReports"]
    abuse_confidence_score = parsed_data["data"]["abuseConfidenceScore"]
    domain = parsed_data["data"]["domain"]
    is_tor = parsed_data["data"]["isTor"]
    last_reported_at = parsed_data["data"]["lastReportedAt"]
    Country_code = parsed_data["data"]["countryCode"]
    Country_Name = country_code_to_name(Country_code)

    # Convert lastReportedAt to human-readable format
    last_reported_at_datetime = datetime.datetime.strptime(last_reported_at, "%Y-%m-%dT%H:%M:%S+00:00")
    human_readable_time = last_reported_at_datetime.strftime("%Y-%m-%d %H:%M:%S")

    return total_reports, abuse_confidence_score, domain, is_tor, human_readable_time, Country_Name


def Shodan_Check(IP):
    try:
        api = shodan.Shodan(Shodan_API_Key)
        host = api.host(IP)
        return host
    except shodan.exception.APIError as e:
        print("Error:", e)
        return None


def is_valid_ip(IP):
    try:
        ipaddress.IPv4Address(IP)
        return True
    except ValueError:
        return False


async def VT_Check_Malicious_Score(IP, session):
    try:
        headers = {"x-apikey": VT_API_KEY}
        async with session.get(f"https://www.virustotal.com/api/v3/ip_addresses/{IP}", headers=headers) as response:
            if response.status == 200:
                response_json = await response.json()
                positives = response_json["data"]["attributes"]["last_analysis_stats"]["malicious"]
                link = response_json["data"]["links"]["self"]
                ASN = response_json["data"]["attributes"]["asn"]

                return positives, link, ASN
            else:
                print(f"Error fetching VirusTotal data. HTTP Status Code: {response.status}")
                return 0, []
    except Exception as e:
        print(f"Error: {e}")
        return 0, []


async def main():
    async with ClientSession() as session:
        # ---------------Api key check----------------------------#
        while True:
                Missing_API_Counter = 0
                IP_address = input("Enter IPv4 address: \n")
                if is_valid_ip(IP_address):
                    if ping(IP_address):
                        print("\n--- Ping check ---")
                        print(f"{IP_address} is reachable")
                        # ---------------Spur Check----------------------------#
                        # Perform spur.us VPN/proxy check
                        print("\n--- VPN\Proxy check ---")
                        URL = f"https://spur.us/context/{IP_address}"
                        html_response = requests.get(URL)
                        if html_response.status_code == 200:
                            html_content = html_response.text
                            soup = BeautifulSoup(html_content, 'html.parser')
                            Soup_tag = soup.h2
                            icon_tag = Soup_tag.find('i', class_='fas fa-ethernet')
                            if icon_tag:
                                icon_tag.extract()

                            # Remove extra whitespace
                            cleaned_text = Soup_tag.get_text().strip()

                            # Remove extra spaces and hyphens
                            cleaned_text = re.sub(r'\s+', ' ', cleaned_text)
                            cleaned_text = re.sub(r'-+', '-', cleaned_text)
                            print(cleaned_text)
                        else:
                            print("Connectivity issue to Spur.us")
                        # Perform VirusTotal check asynchronously
                        if not VT_API_KEY == "":
                            positives, link, ASN = await VT_Check_Malicious_Score(IP_address, session)
                        # ---------------VT check-----------------------------------#
                        # Print VirusTotal results
                            print("\n--- VirusTotal Results ---")
                            print(f"Positive hits: {positives}")
                            print(f"Link to report: {link}")
                            print(f"ASN: {ASN}")
                        else:
                            print("\nMissing VT API key, Skipping task\n")
                            Missing_API_Counter += 1
                        # --------------AbuseIPDB check----------------------------#
                        if not AbuseIPDB_API_KEY == "":
                            total_reports, abuse_confidence_score, domain, is_tor, human_readable_time, Country_Name = AbuseIPDB_check(
                                IP_address)
                            print("\n--- AbuseIPDB Results ---")
                            print(f"In the last 90 days there were: {total_reports} reports")
                            print(f"abuseIPDB Confidence Score: {abuse_confidence_score}")
                            print(f"domain: {domain}")
                            print(f"Origin country is {Country_Name}")
                            print(f"Is Tor exit node?: {is_tor}")
                            print(f"Last report was on: {human_readable_time}")
                        else:
                            print("Missing AbuseIPDB API key, Skipping task")
                            Missing_API_Counter += 1
                        # ---------------Shodan Check------------------------------#
                        # Perform Shodan check
                        if not Shodan_API_Key == "":
                            host = Shodan_Check(IP_address)
                            if host:
                                # Print host information
                                print("\n--- Host Information ---")
                                print("IP Address:", host['ip_str'])
                                print("Organization:", host.get('org', 'Unknown'))
                                print("Operating System:", host.get('os', 'Unknown'))
                                hostnames = host.get('hostnames', [])
                                if hostnames:
                                    print("Hostname:", hostnames[0])
                                else:
                                    print("Hostname: Not found")
                                print("Open ports:")
                                for item in host['ports']:
                                    print(item)
                        else:
                            print("Missing Shodan API key, Skipping task")
                            Missing_API_Counter += 1

                        if Missing_API_Counter > 0:
                            print("Please note that you are missing some API keys\n We recommend using all of the "
                                  "available keys for a better experience.")
                            Missing_API_Counter = 0
                        Continue = input("\n Check another IP?(Y/N) \n")
                        if Continue == "N":
                            break
                        else:
                            continue
                    else:
                        print(f"{IP_address} is not reachable")
                        Check_Validation = input("\n Continue the search?(Y/N) \n")
                        if Check_Validation == "N":
                            break
                        else:
                            continue
                else:
                    print("The input is an invalid IPv4 address.")
                    continue


if __name__ == "__main__":
    asyncio.run(main())
