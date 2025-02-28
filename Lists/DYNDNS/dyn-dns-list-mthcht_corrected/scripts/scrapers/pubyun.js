const fetch = require("node-fetch");
const cheerio = require("cheerio");
const path = require("path");
const { loadData, saveDomains } = require('../scraperUtils');

const filePath = path.join(__dirname, "..", "data", "pubyun.com.json");

async function scrapeDomains() {
    const response = await fetch("https://www.pubyun.com/products/dyndns/product/");
    const body = await response.text();
    const $ = cheerio.load(body);
    const text = $("dl.dynamicDNSExp > dd:nth-child(4)").text();
    const regex = /\b([a-z0-9]+(-[a-z0-9]+)*\.[a-z]{2,})\b/gi;
    const foundDomains = text.match(regex) || [];
    const domains = foundDomains.map(domain => ({
        domain: domain,
        retrievedAt: new Date().toISOString(),
    }));

    return domains;
}

async function scrape() {
    let data = await loadData(filePath);
    const newDomains = await scrapeDomains();
    const uniqueNewDomains = newDomains.filter(nd => !data.some(d => d.domain === nd.domain));

    if (uniqueNewDomains.length > 0) await saveDomains(filePath, [...data, ...uniqueNewDomains]);
    console.log(`Added ${uniqueNewDomains.length} new domains from https://pubyun.com`);
}

module.exports = { scrape };