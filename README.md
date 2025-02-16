# PyIP


This is my first ever public Python project. It is intended for blue teamers to check the reputation and details of a given IPv4(IPv6 support will be added in the future) address using freely available API keys and public information sources. It then displays a comprehensive report in the console.


## Description


This project aims to provide a quick and easy way to investigate IP addresses. It leverages various public APIs and data sources to gather information about an IP address, including its geolocation, associated ASN, potential threat level, and other relevant details.  The results are presented in a user-friendly format within the console.  This tool is intended for informational purposes and should not be used for any illegal activities.


API keys can be obtained freely upon registering to the relevant websites.


## Features


* **IP Address Lookup:** Retrieves reachability(ping) information and VPN\Proxy\Tor exit node information about a given IP address without API keys.

* **Associated country:** Determines the origin state of the IP address.

* **ASN Information:** Identifies the Autonomous System Number associated with the IP address.

* **Threat Assessment (where available):**  Provides insights into potential security risks associated with the IP address (using free API keys).

* **Clear Console Output:** Presents the results in a readable and organized format.

* **Uses Free APIs:** Relies on publicly available APIs for data retrieval (note: rate limits may apply) from VirusTotal, AbuseIPDB and Shodan.

* **Easy to Use:** Simple command-line interface.


## How to use

1. **Clone the repository:**

   ```bash

   git clone https://github.com/Sinobi989/PyIP.git

2. **Edit main.py to insert your API keys:**


   ![image](https://github.com/user-attachments/assets/8d2a9f53-29c1-4f75-9f3b-28b160284626)

3. **Run main.py using python:**

   ![image](https://github.com/user-attachments/assets/d78602b8-087c-43f6-aca3-29be4ac75f7f)

## Output example

  ![image](https://github.com/user-attachments/assets/3f7357e7-ff63-44a4-b06f-d54139ea68c3)
