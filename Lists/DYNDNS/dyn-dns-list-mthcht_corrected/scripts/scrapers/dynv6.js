const path = require("path");
const { loadData, saveDomains } = require('../scraperUtils');

const filePath = path.join(__dirname, "..", "data", "dynv6.com.json");

async function scrapeDomains(browser) {
	const page = await browser.newPage();
	await page.goto("https://dynv6.com/");
	const options = await page.evaluate(() => Array.from(document.querySelectorAll("#domain option"), option => option.textContent.trim()));

	const domains = options.filter(domain => domain !== "delegate your own domain …").map(domain => ({
		domain: domain,
		retrievedAt: new Date().toISOString(),
	}));

	await page.close();
	return domains;
}

async function scrape(browser) {
	let data = await loadData(filePath);
	const newDomains = await scrapeDomains(browser);
	const uniqueNewDomains = newDomains.filter(nd => !data.some(d => d.domain === nd.domain));
	if (uniqueNewDomains.length > 0) await saveDomains(filePath, [...data, ...uniqueNewDomains]);
	console.log(`Added ${uniqueNewDomains.length} new domains from https://dynv6.com`);
}

module.exports = { scrape };