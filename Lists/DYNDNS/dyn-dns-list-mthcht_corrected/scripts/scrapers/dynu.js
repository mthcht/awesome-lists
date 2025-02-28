const fetch = require('node-fetch');
const cheerio = require('cheerio');
const path = require('path');
const { loadData, saveDomains } = require('../scraperUtils');

const filePath = path.join(__dirname, '..', 'data', 'dynu.com.json');

async function fetchAndParseDomains() {
    try {
        const response = await fetch('https://www.dynu.com/en-US/ControlPanel/AddDDNS');
        const body = await response.text();
        const $ = cheerio.load(body);
        const domains = [];

        $('#Container option').each((_, element) => {
            let domainText = $(element).text();

            domainText = domainText.replace(" - Members only", "");

            domains.push({
                domain: domainText,
                retrievedAt: new Date().toISOString()
            });
        });

        return domains;
    } catch (error) {
        console.error('Error fetching or parsing domains:', error);
        return [];
    }
}

async function scrape() {
    let data = await loadData(filePath);
    const newDomains = await fetchAndParseDomains();
    const uniqueNewDomains = newDomains.filter(nd => !data.some(d => d.domain === nd.domain));
    if (uniqueNewDomains.length > 0) await saveDomains(filePath, [...data, ...uniqueNewDomains]);
    console.log(`Added ${uniqueNewDomains.length} new domains from https://www.dynu.com`);
}

module.exports = { scrape };