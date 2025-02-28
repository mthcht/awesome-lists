const fetch = require('node-fetch');
const cheerio = require('cheerio');
const path = require('path');
const { loadData, saveDomains } = require('../scraperUtils');

const filePath = path.join(__dirname, "..", "data", "ydns.io.json");

async function fetchAndParseDomains() {
    const response = await fetch("https://ydns.io/domains/");
    const body = await response.text();
    const $ = cheerio.load(body);
    const domains = [];

    $("table.table tbody tr").each((_, element) => {
        const domain = $(element).find("td:first-child a").text().trim();
        if (domain) {
            domains.push({
                domain: domain,
                retrievedAt: new Date().toISOString(),
            });
        }
    });

    return domains;
}

async function scrape() {
    const data = await loadData(filePath);
    const newDomains = await fetchAndParseDomains();
    const uniqueNewDomains = newDomains.filter(nd => !data.some(d => d.domain === nd.domain));
    
    if (uniqueNewDomains.length > 0) {
        await saveDomains(filePath, [...data, ...uniqueNewDomains]);
        console.log(`Added ${uniqueNewDomains.length} new domains from https://ydns.io`);
    }
}

module.exports = { scrape };