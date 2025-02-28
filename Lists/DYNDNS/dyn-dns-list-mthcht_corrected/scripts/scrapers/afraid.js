const cheerio = require('cheerio');
const path = require('path');
const { loadData, saveDomains } = require('../scraperUtils');

const filePath = path.join(__dirname, '..', 'data', 'afraid.org.json');

async function navigatePage(page, url) {
    try {
        await page.goto(url, { waitUntil: 'networkidle2' });
        return await page.content();
    } catch (err) {
        console.error(`Failed to load page ${url}: ${err}`);
        throw err;
    }
}

let totalScrapePages = 2;

async function scrapePage(page, pageNumber) {
    let url = pageNumber === 1 ? `http://freedns.afraid.org/domain/registry/` : `http://freedns.afraid.org/domain/registry/page-${pageNumber}.html`;
    let body = await navigatePage(page, url);
    let $ = cheerio.load(body);

    if (pageNumber === 1) {
        let title = $('title').text();
        let match = title.match(/Page \d+ of (\d+)/);
        totalScrapePages = match ? parseInt(match[1], 10) : pageNumber;
    }

    process.stdout.write(`Scraping page ${pageNumber}/${totalScrapePages} of https://afraid.org\r`);

    let newDomains = [];
    $('tr.trd, tr.trl').each((_, row) => {
        let domainIdUrl = $(row).find('td a:first').attr('href');
        let id = domainIdUrl ? domainIdUrl.split('=')[1] : null;
        let domain = $(row).find('td a:first').text().trim();
        let age = $(row).find('td').eq(3).text().trim();
        let retrievedAt = new Date().toISOString();

        newDomains.push({ id, domain, age, retrievedAt });
    });

    return newDomains;
}

async function scrape(browser) {
    let existingDomains = await loadData(filePath);
    const page = await browser.newPage();
    let allNewDomains = [];

    for (let pageNumber = 1; pageNumber <= totalScrapePages; pageNumber++) {
        const pageDomains = await scrapePage(page, pageNumber);
        allNewDomains.push(...pageDomains);
    }

    await page.close();

    let uniqueNewDomains = allNewDomains.filter(nd => !existingDomains.some(d => d.id === nd.id));
    
    if (uniqueNewDomains.length > 0) await saveDomains(filePath, [...existingDomains, ...uniqueNewDomains]);
    console.log(`\nAdded ${uniqueNewDomains.length} new domain(s) from https://afraid.org`);
}

module.exports = { scrape };