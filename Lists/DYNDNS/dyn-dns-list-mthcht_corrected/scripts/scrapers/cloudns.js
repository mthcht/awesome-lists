require("dotenv").config();
const path = require("path");
const { loadData, saveDomains } = require('../scraperUtils');

const filePath = path.join(__dirname, "..", "data", "cloudns.net.json");

async function loginAndScrapeDomains(browser) {
	const page = await browser.newPage();
	await page.goto("https://www.cloudns.net/index/show/login/", { waitUntil: "networkidle0" });

	try {
		await page.waitForSelector('iframe[src*="hcaptcha.com"]', { timeout: 5000 });
		console.log("CAPTCHA found, skipping https://cloudns.net");
		return [];
	} catch (error) {
		// CAPTCHA not found, continuing...
	}

	const usernameInput = await page.waitForSelector('xpath/.//*[@id="login2FAMail"]');
	await usernameInput.type(process.env.CLOUDDNS_USERNAME);

	const passwordInput = await page.waitForSelector('xpath/.//*[@id="login2FAPassword"]');
	await passwordInput.type(process.env.CLOUDDNS_PASSWORD);

	await passwordInput.focus();
	await page.click('xpath/.//*[@id="login2faButton"]');
	await page.waitForSelector("#dashboard-zones", { timeout: 0 });

	await page.goto("https://www.cloudns.net/ajaxPages.php?action=newzone&show=freeZone");

	const domains = await page.evaluate(() => {
		return Array.from(document.querySelectorAll("#freeDomain option")).map(option => option.textContent.trim());
	});

	await page.close();
	return domains.map(domain => ({
		domain: domain,
		retrievedAt: new Date().toISOString(),
	}));
}

async function scrape(browser) {
	let data = await loadData(filePath);
	const newDomains = await loginAndScrapeDomains(browser);
	const uniqueNewDomains = [...data, ...newDomains.filter(nd => !data.some(d => d.domain === nd.domain))];
	if (uniqueNewDomains.length > 0) await saveDomains(filePath, uniqueNewDomains);
	console.log(`Added ${uniqueNewDomains.length} new domains from https://cloudns.net`);
}

module.exports = { scrape };