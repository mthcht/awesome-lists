const fetch = require("node-fetch");
const cheerio = require("cheerio");
const path = require("path");
const { loadData, saveDomains } = require('../scraperUtils');

const filePath = path.join(__dirname, "..", "data", "now-dns.com.json");

async function scrapeOptions() {
	const response = await fetch("https://now-dns.com/");
	const body = await response.text();
	const $ = cheerio.load(body);
	const options = $("#domainList > option");
	const domains = [];

	options.each((_, element) => {
		const id = $(element).val();
		const domain = $(element).text().trim().replace(/^\./, "");
		domains.push({
			id: id,
			domain: domain,
			retrievedAt: new Date().toISOString(),
		});
	});

	return domains;
}

async function scrape() {
	let data = await loadData(filePath);
	const newDomains = await scrapeOptions();
	const uniqueNewDomains = newDomains.filter(nd => !data.some(d => d.id === nd.id));
	if (uniqueNewDomains.length > 0) await saveDomains(filePath, [...data, ...uniqueNewDomains]);
	console.log(`Added ${uniqueNewDomains.length} new domains from https://now-dns.com`);
}

module.exports = { scrape };