# Clone of https://github.com/mthcht/dyn-dns-list (corrected version for automation) 

> **Notice:** In response to the recent surge in interest and traffic to this repository, significant efforts have been made to rejuvenate and automate its maintenance. The automation process now ensures that the `links.csv` and `links.txt` files are updated on a daily basis. This is achieved through a GitHub Actions workflow that systematically scrapes dynamic DNS provider websites for the latest domain information, ensuring the repository remains a reliable and up-to-date resource for the community.

**Domains Last Update: 16/07/2025, 21:11**

# Dynamic DNS domain list (2025) - 32756 domains

While working on another project, I needed a list of domains being used for dynamic DNS, and since I've lost a few hours of my life, I decided to just release the list. Due to the repository getting some views lately and having some extra time, I decided to automate the scraping part, so that the list remains updated.

<div align="center">
  <kbd>
    <img src="https://i.imgur.com/GPecoyu.png" />
  </kbd>
</div>

## Use Cases

- Blocking access to known malicious domains: the list can be used to block access to domains that are known to be used by malware, phishing, or other types of malicious activities.
- Monitoring network traffic: the list can be used to monitor network traffic and identify potential security threats or policy violations.
- Implementing parental controls: the list can be used to restrict access to certain domains that may be inappropriate or harmful for children.
- Implementing content filtering: the list can be used to filter out domains that contain specific types of content, such as adult content or gambling sites.
- Implementing ad-blocking: the list can be used to block domains that are known to serve ads, thereby improving the browsing experience and reducing the risk of malware infections.
- Enhancing privacy and security: the list can be used to block domains that are known to track user activity or collect personal information, thereby enhancing privacy and security.

## Automated Scraping

This project is a NodeJS application which is designed to automate the scraping of various dynamic DNS providers to maintain an updated list of domains. The `scripts` folder contains individual scripts for scraping each DNS provider's site. The results of each scraping operation are stored in the `data` folder in JSON format, with each file named after the corresponding DNS provider.

Upon execution of the main script (`main.js`), all the scrapers run concurrently and fetch the latest data from the respective DNS provider websites. Post completion, a consolidated list of all the domains, along with their retrieved date and provider, is generated in both CSV and TXT formats and stored in the root directory of the project.

The project uses Puppeteer for scraping websites that either require login or are behind cloudflare, or node fetch for simpler websites, and Cheerio for parsing and extracting information.

If there are any more websites you know that provide Dynamic DNS, please open an issue, and I will automate that too.


## Setup and Running the Project

1. Clone the repository.
2. Navigate to the `scripts` folder.
3. Install dependencies by running `npm install`.
4. Rename the `.env example` file to `.env` and set up your environment variables.
5. Run `node main.js` to start the scraping process. A chromium window will pop up and will navigate to cloudns.net, which will automatically enter the login details, and wait 15 seconds for you to complete the captcha. After you finish the captcha, please don't press the login button, as that will disrupt the script.
6. The output will be JSON files for each provider in the `data` folder, and a `links.csv` file will also be created in the root directory with all the domains, the date they were retrieved, and their provider.

## Usage Example

When running the project for the first time, it initializes by scraping each provider's site for their available domains. An example of the initial run can be seen below:

<div align="center">
  <kbd>
    <img src="https://i.imgur.com/lUoaWfC.png" />
  </kbd>
</div>

In the image above, the script is shown scraping the domains from each provider. Once the scraping process is completed, the results are stored in individual JSON files within the `data` folder. A consolidated list of all the domains is also generated and stored as a CSV and TXT file in the root directory of the project.

For subsequent runs, the script only adds new domains to the list. This ensures that the list remains up-to-date while avoiding duplicate entries.


### DNS Providers included:
- [afraid.org](https://afraid.org/) (32721 domains)
- [dyn.com](https://dyn.com/) (293 domains)
- [changeip.com](https://changeip.com/) (157 domains)
- [noip.com](https://noip.com/) (83 domains) 
- [now-dns.com](https://now-dns.com/) (32 domains)
- [dynu.com](https://dynu.com/) (21 domains)
- [pubyun.com](https://pubyun.com/) (9 domains)
- [dynv6.com](https://dynv6.com/) (6 domains)
- [gslb.me](https://gslb.me/) (5 domains)
- [dnsexit.com](https://dnsexit.com/) (7 domains)
- [duiadns.net](https://duiadns.net/) (3 domains)
- [cloudns.net](https://cloudns.net/) (2 domains)
- [ydns.io](https://ydns.io/) (1 domains)

Note the above counts are not updated with the new ones.
They will be automatically be updated in the next commits.

## Back matter

### Legal disclaimer

This dynamic DNS domain list is provided for informational purposes only. The inclusion of a domain in this list does not imply that it is malicious or otherwise harmful, nor does it guarantee that it is safe to access.
Users are responsible for their own use of this list and should conduct their own due diligence to determine whether a domain is safe or appropriate for their purposes. The author of this list disclaims any liability for damages or losses that may result from the use of this list.

### License

This project is licensed under the [Unlicense license](LICENSE).
