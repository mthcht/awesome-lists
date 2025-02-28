const fs = require('fs').promises;
const path = require('path');

async function loadData(filePath) {
    try {
        const fileData = await fs.readFile(filePath);
        return JSON.parse(fileData);
    } catch (err) {
        return [];
    }
}

async function saveDomains(filePath, data) {
    try {
        await fs.writeFile(filePath, JSON.stringify(data, null, 2));
    } catch (error) {
        console.error(`Error saving domains to file ${filePath}:`, error);
    }
}

async function updateCounts() {
    const dataPath = path.join(__dirname, 'data');
    const readmePath = path.join(__dirname, '..', 'README.md');
    let totalDomains = 0;

    try {
        const files = await fs.readdir(dataPath);
        const providerCounts = await Promise.all(files.filter(file => file.endsWith('.json')).map(async file => {
            const filePath = path.join(dataPath, file);
            const data = await loadData(filePath);
            const provider = file.replace('.json', '');
            const count = data.length;
            totalDomains += count;
            return { provider, count };
        }));

        let readmeContent = await fs.readFile(readmePath, 'utf8');
        providerCounts.forEach(({ provider, count }) => {
            readmeContent = readmeContent.replace(new RegExp(`- \\[${provider}\\]\\(https://.+\\) \\(\\d+ domains\\)`, 'g'), `- [${provider}](https://${provider}/) (${count} domains)`);
        });

        // Update total domains count
        readmeContent = readmeContent.replace(/# Dynamic DNS domain list \(2024\) - \d+ domains/g, `# Dynamic DNS domain list (2024) - ${totalDomains} domains`);

        const currentDateTime = new Date().toLocaleString('en-GB', {
            day: '2-digit',
            month: '2-digit',
            year: 'numeric',
            hour: '2-digit',
            minute: '2-digit',
            hour12: false
        });

        // Update "Domains Last Update:" line
        readmeContent = readmeContent.replace(/\*\*Domains Last Update: .+\*\*/g, `**Domains Last Update: ${currentDateTime}**`);


        await fs.writeFile(readmePath, readmeContent);
        console.log('README.md updated with the latest domain counts.');
    } catch (error) {
        console.error('Error updating counts:', error);
    }
}

module.exports = { loadData, saveDomains, updateCounts };