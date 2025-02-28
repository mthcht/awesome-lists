const fetch = require("node-fetch");
const cheerio = require("cheerio");
const path = require("path");
const { loadData, saveDomains } = require('../scraperUtils');

const filePath = path.join(__dirname, "..", "data", "dnsexit.com.json");

async function scrapeOptions() {
	const response = await fetch("http://dnsexit.com/domains/free-second-level-domains/");
	const body = await response.text();
	const $ = cheerio.load(body);
	const options = $("#iddomain > option");
	const domains = [];

	options.each((_, element) => {
		const domain = $(element).text().trim();
		domains.push({
			domain: domain,
			retrievedAt: new Date().toISOString(),
		});
	});

	return domains;
}

async function scrape() {
	try {
		let data = await loadData(filePath);
		const newDomains = await scrapeOptions();

		const uniqueNewDomains = newDomains.filter(nd => !data.some(d => d.domain === nd.domain));
		if (uniqueNewDomains.length > 0) await saveDomains(filePath, [...data, ...uniqueNewDomains]);
		console.log(`Added ${uniqueNewDomains.length} new domains from http://dnsexit.com`);
	} catch (error) {
		console.error('An error occurred during the scraping process:', error);
	}
}

module.exports = { scrape };