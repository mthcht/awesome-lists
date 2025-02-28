const fs = require('fs').promises;
const path = require('path');
const { loadData, saveDomains } = require('../scraperUtils');

const filePath = path.join(__dirname, '..', 'data', 'changeip.com.json');

async function scrapeOptions(browser) {
    const page = await browser.newPage();

    // Navigate to add to cart page
    await page.goto('https://www.changeip.com/accounts/cart.php?a=add&bid=1');

    // Navigate to view domains page
    await page.goto('https://www.changeip.com/accounts/cart.php?a=confproduct&i=0');

    const options = await page.evaluate(() => {
        return Array.from(document.querySelectorAll('#free-domain option')).map(option => ({
            id: option.value,
            domain: option.textContent.trim()
        }));
    });

    await page.close();

    return options;
}

async function scrape(browser) {
    data = await loadData(filePath);
    const options = await scrapeOptions(browser);

    let uniqueNewDomains = [];
    for (const option of options) {
        const exists = data.some(entry => entry.id === option.id);
        if (!exists) {
            uniqueNewDomains.push({
                id: option.id,
                domain: option.domain,
                retrievedAt: new Date().toISOString()
            });
        }
    }

    if (uniqueNewDomains.length > 0) await saveDomains(filePath, [...data, ...uniqueNewDomains]);
    console.log(`Added ${uniqueNewDomains.length} new domains from https://changeip.com`);
}

module.exports = { scrape };