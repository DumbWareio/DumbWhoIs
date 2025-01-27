require('dotenv').config();
const express = require('express');
const cors = require('cors');
const axios = require('axios');
const path = require('path');
const whois = require('node-whois');
const util = require('util');

const app = express();
const PORT = process.env.PORT || 3000;

// Convert whois.lookup to Promise
const lookupPromise = util.promisify(whois.lookup);

app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Helper function to detect query type
function detectQueryType(query) {
    // ASN pattern (AS followed by numbers)
    if (/^(AS|as)?\d+$/i.test(query)) {
        return 'asn';
    }
    // IP pattern (basic IPv4 check)
    if (/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(query)) {
        return 'ip';
    }
    // Domain pattern (anything with a dot that's not an IP)
    if (query.includes('.')) {
        return 'whois';
    }
    return 'unknown';
}

// Helper function to parse WHOIS data
function parseWhoisData(data, domain) {
    // Split into lines and create key-value pairs
    const result = {
        domainName: domain,
        registrar: '',
        creationDate: '',
        expirationDate: '',
        lastUpdated: '',
        status: [],
        nameservers: [],
        raw: data
    };

    // Special handling for .eu domains
    if (domain.toLowerCase().endsWith('.eu')) {
        const lines = data.split('\n');
        let currentSection = '';
        
        for (const line of lines) {
            const trimmedLine = line.trim();
            
            // Skip empty lines and comment lines
            if (!trimmedLine || trimmedLine.startsWith('%')) continue;
            
            // Check for section headers
            if (trimmedLine.endsWith(':')) {
                currentSection = trimmedLine.slice(0, -1).toLowerCase();
                continue;
            }
            
            // Handle indented lines (section content)
            if (line.startsWith('        ')) {
                const [key, ...values] = line.trim().split(':').map(s => s.trim());
                const value = values.join(':').trim();
                
                switch (currentSection) {
                    case 'registrar':
                        if (key === 'Name') {
                            result.registrar = value;
                        }
                        break;
                    case 'name servers':
                        if (!key.includes(':') && key !== 'Please visit www.eurid.eu for more info.') {
                            result.nameservers.push(key);
                        }
                        break;
                    case 'technical':
                        if (key === 'Organisation' && !result.registrar) {
                            result.registrar = value;
                        }
                        break;
                }
            } else if (line.includes(':')) {
                const [key, ...values] = line.split(':').map(s => s.trim());
                const value = values.join(':').trim();
                
                if (key === 'Domain') {
                    result.domainName = value;
                }
            }
        }
        
        // Add default status for .eu domains if none found
        if (result.status.length === 0) {
            result.status.push('registered');
        }
    } else {
        // Original parsing logic for non-.eu domains
        const lines = data.split('\n');
        for (const line of lines) {
            const [key, ...values] = line.split(':').map(s => s.trim());
            const value = values.join(':').trim();

            if (!key || !value) continue;

            const keyLower = key.toLowerCase();

            // Registrar information
            if (keyLower.includes('registrar')) {
                result.registrar = value;
            }
            // Creation date
            else if (keyLower.includes('creation') || keyLower.includes('created') || 
                     keyLower.includes('registered')) {
                result.creationDate = value;
            }
            // Expiration date
            else if (keyLower.includes('expir')) {
                result.expirationDate = value;
            }
            // Last updated
            else if (keyLower.includes('updated') || keyLower.includes('modified')) {
                result.lastUpdated = value;
            }
            // Status
            else if (keyLower.includes('status')) {
                const statuses = value.split(/[,;]/).map(s => s.trim());
                result.status.push(...statuses);
            }
            // Nameservers
            else if (keyLower.includes('name server') || keyLower.includes('nameserver')) {
                const ns = value.split(/[\s,;]+/)[0];
                if (ns && !result.nameservers.includes(ns)) {
                    result.nameservers.push(ns);
                }
            }
        }
    }

    return result;
}

// Universal lookup endpoint
app.get('/api/lookup/:query', async (req, res) => {
    const query = req.params.query;
    const queryType = detectQueryType(query);

    try {
        let response;
        switch (queryType) {
            case 'whois':
                // Set specific options for WHOIS query
                const options = {
                    follow: 3, // Follow up to 3 redirects
                    timeout: 10000, // 10 second timeout
                };

                // Add specific server for .eu domains
                if (query.toLowerCase().endsWith('.eu')) {
                    options.server = 'whois.eu';
                }

                const whoisData = await lookupPromise(query, options);
                const parsedData = parseWhoisData(whoisData, query);
                
                response = {
                    data: {
                        ldhName: parsedData.domainName,
                        handle: query,
                        status: parsedData.status,
                        events: [
                            {
                                eventAction: 'registration',
                                eventDate: parsedData.creationDate
                            },
                            {
                                eventAction: 'expiration',
                                eventDate: parsedData.expirationDate
                            },
                            {
                                eventAction: 'lastChanged',
                                eventDate: parsedData.lastUpdated
                            }
                        ],
                        nameservers: parsedData.nameservers.map(ns => ({ ldhName: ns })),
                        entities: [{
                            roles: ['registrar'],
                            vcardArray: [
                                "vcard",
                                [
                                    ["version", {}, "text", "4.0"],
                                    ["fn", {}, "text", parsedData.registrar],
                                    ["email", {}, "text", ""]
                                ]
                            ]
                        }]
                    }
                };
                break;
            case 'ip':
                response = await axios.get(`https://ipapi.co/${query}/json/`);
                break;
            case 'asn':
                // Remove 'AS' prefix if present
                const asnNumber = query.replace(/^(AS|as)/i, '');
                response = await axios.get(`https://api.bgpview.io/asn/${asnNumber}`);
                break;
            default:
                return res.status(400).json({ 
                    error: 'Invalid input', 
                    message: 'Please enter a valid domain name, IP address, or ASN number' 
                });
        }
        res.json({ type: queryType, data: response.data });
    } catch (error) {
        console.error('Error details:', error);
        if (error.response && error.response.status === 404) {
            res.status(404).json({ error: `${queryType.toUpperCase()} not found` });
        } else {
            res.status(500).json({ 
                error: `Error fetching ${queryType.toUpperCase()} data`, 
                details: error.message 
            });
        }
    }
});

app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
}); 