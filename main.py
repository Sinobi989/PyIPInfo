import subprocess
import shodan
import requests
import re
import vt
import asyncio
import requests
from aiohttp import ClientSession
from bs4 import BeautifulSoup

Shodan_API_Key = ""  # Replace with your Shodan API key
VT_API_KEY = ""  # Replace with your VirusTotal API key


def ping(IP):
    try:
        subprocess.check_output(['ping', '-n', '1', IP], shell=True)
        return True
    except subprocess.CalledProcessError:
        return False


def Shodan_Check(IP):
    try:
        api = shodan.Shodan(Shodan_API_Key)
        host = api.host(IP)
        return host
    except shodan.exception.APIError as e:
        print("Error:", e)
        return None


async def VT_Check(IP, session):
    try:
        headers = {"x-apikey": VT_API_KEY}
        async with session.get(f"https://www.virustotal.com/api/v3/ip_addresses/{IP}", headers=headers) as response:
            if response.status == 200:
                response_json = await response.json()
                positives = response_json["data"]["attributes"]["last_analysis_stats"]["malicious"]

                return positives
            else:
                print(f"Error fetching VirusTotal data. HTTP Status Code: {response.status}")
                return 0, []
    except Exception as e:
        print(f"Error: {e}")
        return 0, []

async def main():
    async with ClientSession() as session:
        while True:
            IP_address = input("Enter IP address: \n")

            if ping(IP_address):
                print("\n--- Connectivity ---")
                print(f"{IP_address} is reachable")
                #Perform spur.us VPN/proxy check
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
                    String = Soup_tag.text
                    print(cleaned_text)
                else:
                    print("Connectivity issue to Spur.us")
                # Perform VirusTotal check asynchronously
                positives = await VT_Check(IP_address, session)

                # Print VirusTotal results
                print("\n--- VirusTotal Results ---")
                print(f"Positive hits: {positives}")

                # Perform Shodan check
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
                    for item in host['ports']:
                        print(item)

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

if __name__ == "__main__":
    asyncio.run(main())