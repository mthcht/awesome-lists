const fetch = require('node-fetch');
const cheerio = require('cheerio');
const path = require('path');
const { loadData, saveDomains } = require('../scraperUtils');

const filePath = path.join(__dirname, '..', 'data', 'dyn.com.json');

async function scrapeOptions() {
    const response = await fetch('https://account.dyn.com/');
    const body = await response.text();
    const $ = cheerio.load(body);
    const options = $('#hostname-search > select > option');
    const domains = [];

    options.each((_, element) => {
        const domain = $(element).attr('value');
        if (domain) {
            domains.push({
                domain: domain,
                retrievedAt: new Date().toISOString()
            });
        }
    });

    return domains;
}

async function scrape() {
    let data = await loadData(filePath);
    const newDomains = await scrapeOptions();
    const uniqueNewDomains = newDomains.filter(nd => !data.some(d => d.domain === nd.domain));

    if (uniqueNewDomains.length > 0) await saveDomains(filePath, [...data, ...uniqueNewDomains]);
    console.log(`Added ${uniqueNewDomains.length} new domains from https://dyn.com`);
}

module.exports = { scrape };