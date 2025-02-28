const fetch = require('node-fetch');
const cheerio = require('cheerio');
const path = require('path');
const { loadData, saveDomains } = require('../scraperUtils');

const filePath = path.join(__dirname, '..', 'data', 'noip.com.json');

async function fetchAndParseDomains() {
	try {
		const response = await fetch('https://www.noip.com/support/faq/frequently-asked-questions');
		const body = await response.text();
		const $ = cheerio.load(body);
		const article = $('#post-450');
		const domains = [];

		Object.entries({
			'Free Domains:': 'free',
			'Enhanced Domains:': 'enhanced'
		}).forEach(([sectionTitle, type]) => {
			article.find(`h2:contains('${sectionTitle}')`).next('p').html()?.split('<br>').forEach(domainHtml => {
				const domainText = cheerio.load(domainHtml).text().trim();
				if (domainText) {
					domains.push({
						domain: domainText,
						type: type,
						retrievedAt: new Date().toISOString()
					});
				}
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
	const uniqueNewDomains = newDomains.filter(nd => !data.some(d => d.domain === nd.domain && d.type === nd.type));
	if (uniqueNewDomains.length > 0) await saveDomains(filePath, [...data, ...uniqueNewDomains]);

	console.log(`Added ${uniqueNewDomains.length} new domains from https://noip.com`);
}

module.exports = { scrape };