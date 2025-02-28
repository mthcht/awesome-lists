const fs = require('fs');
const path = require('path');
const createCsvWriter = require('csv-writer').createObjectCsvWriter;

const dataPath = path.join(__dirname, 'data');
const csvFilePath = path.join(__dirname, '..', 'links.csv');
const txtFilePath = path.join(__dirname, '..', 'links.txt');

const files = fs.readdirSync(dataPath).filter(file => file.endsWith('.json'));

const csvWriter = createCsvWriter({
    path: csvFilePath,
    header: [
        { id: 'domain', title: 'Domain' },
        { id: 'retrievedAt', title: 'RetrievedAt' },
        { id: 'provider', title: 'Provider' }
    ],
    append: false
});

async function writeCsv(data) {

}

async function start() {
    console.log('Writing CSV and TXT files...');

    // Combine data from all JSON files
    let combinedData = [];
    for (let file of files) {
        const provider = path.basename(file, '.json');
        const filePath = path.join(dataPath, file);
        const rawData = fs.readFileSync(filePath, 'utf-8');
        const data = JSON.parse(rawData);

        console.log(`${provider}: ${data.length} domains before filtering for uniqueness.`);

        combinedData.push(...data.map(entry => ({
            domain: entry.domain,
            retrievedAt: entry.retrievedAt,
            provider: provider
        })));
    }

    console.log(`Combined data size before filtering: ${combinedData.length}`);

    const uniqueDomains = [...new Set(combinedData.map(entry => entry.domain))];

    // Write to links.txt
    fs.writeFileSync(txtFilePath, uniqueDomains.join('\n'));
    console.log(`TXT file written with ${uniqueDomains.length} unique domains.`);

    // Write to links.csv
    await csvWriter.writeRecords(combinedData)
        .then(() => console.log('CSV file written successfully.'))
        .catch(err => console.error(`Failed to write CSV: ${err}`));
}

module.exports = { start };