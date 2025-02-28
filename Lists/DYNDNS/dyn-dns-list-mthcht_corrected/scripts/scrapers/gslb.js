require("dotenv").config();
const path = require("path");
const { loadData, saveDomains } = require('../scraperUtils');

const filePath = path.join(__dirname, "..", "data", "gslb.me.json");

async function loginAndScrapeDomains(browser) {
    try {
        const page = await browser.newPage();
        console.log("🔍 Navigating to GSLB login page...");

        await page.goto("https://gui.gslb.me/GSLB.ME-GUI/", {
            waitUntil: "networkidle2",
            timeout: 60000, // 60 seconds timeout
        });

        console.log("✅ Login page loaded, waiting for input fields...");
        await page.waitForSelector('tbody input[type="text"]', { timeout: 20000 });
        await page.waitForSelector('tbody input[type="password"]', { timeout: 20000 });

        console.log("🔑 Typing credentials...");
        await page.type('tbody input[type="text"]', process.env.GSLB_USERNAME, { delay: 100 });
        await page.type('tbody input[type="password"]', process.env.GSLB_PASSWORD, { delay: 100 });

        console.log("🚀 Submitting login form...");
        await Promise.all([
            page.keyboard.press("Enter"),
            page.waitForNavigation({ waitUntil: "networkidle2", timeout: 60000 }),
        ]);

        console.log("✅ Login successful, extracting domains...");
        await new Promise(resolve => setTimeout(resolve, 2000)); // Extra wait to ensure page loads

        const domains = await page.evaluate(() =>
            Array.from(
                document.querySelectorAll(".v-tree-node-caption > div > span"),
                span => span.textContent.trim()
            ).filter(domain => /\b([a-z0-9]+(-[a-z0-9]+)*\.[a-z]{2,})\b/gi.test(domain) && !domain.includes("["))
        );

        await page.close();
        console.log(`✅ Extracted ${domains.length} domains.`);
        return domains.map(domain => ({
            domain: domain,
            retrievedAt: new Date().toISOString(),
        }));

    } catch (error) {
        console.error("❌ Login or scraping failed:", error);
        return []; // Return empty to avoid stopping execution
    }
}

async function scrape(browser) {
    let data = await loadData(filePath);
    const newDomains = await loginAndScrapeDomains(browser);
    
    if (newDomains.length > 0) {
        const uniqueNewDomains = newDomains.filter(nd => !data.some(d => d.domain === nd.domain));
        if (uniqueNewDomains.length > 0) {
            await saveDomains(filePath, [...data, ...uniqueNewDomains]);
            console.log(`✅ Added ${uniqueNewDomains.length} new domains from https://gslb.me`);
        } else {
            console.log("⚠️ No new domains found.");
        }
    } else {
        console.log("⚠️ No domains extracted due to errors.");
    }
}

module.exports = { scrape };
