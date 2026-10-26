require('dotenv').config();
const express = require('express');
const cors = require('cors');
const axios = require('axios');
const path = require('path');
const whois = require('node-whois');
const util = require('util');
const { getCorsOptions, originValidationMiddleware } = require('./scripts/cors');
const { generatePWAManifest } = require('./scripts/pwa-manifest-generator');

const app = express();
const PORT = process.env.PORT || 3000;
const SITE_TITLE = process.env.SITE_TITLE || 'DumbWhois';
const PUBLIC_DIR = path.join(__dirname, 'public');
const ASSETS_DIR = path.join(PUBLIC_DIR, 'assets');

// Shared HTTP client for external APIs. ipapi.co's Cloudflare front blocks
// axios' default User-Agent (403), and RIPEstat can take 15s+ on uncached queries.
const http = axios.create({
    timeout: 20000,
    headers: { 'User-Agent': 'DumbWhois (+https://github.com/DumbWareio/DumbWhois)' }
});

// Convert whois.lookup to Promise
const lookupPromise = util.promisify(whois.lookup);

// Trust proxy - required for secure cookies behind a reverse proxy
app.set('trust proxy', 1);

// CORS setup
const corsOptions = getCorsOptions();
app.use(cors(corsOptions));
app.use(express.json());
app.use(originValidationMiddleware);

generatePWAManifest(SITE_TITLE);

app.use(express.static('public'));

// Helper function to detect query type
function detectQueryType(query) {
    // Clean up the query - remove brackets if present
    const cleanQuery = query.replace(/^\[|\]$/g, '');

    // ASN pattern (AS followed by numbers)
    if (/^(AS|as)?\d+$/i.test(cleanQuery)) {
        return 'asn';
    }

    // IPv6 pattern (with optional CIDR)
    if (/^(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})|:(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(?::[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(?:ffff(?::0{1,4}){0,1}:){0,1}(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])|(?:[0-9a-fA-F]{1,4}:){1,4}:(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])|(?:[0-9a-fA-F]{1,4}:){1,4}:(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9]))(?:\/\d{1,3})?$/.test(cleanQuery)) {
        return 'ip';
    }

    // IPv4 pattern (with optional CIDR)
    if (/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:\/\d{1,2})?$/.test(cleanQuery)) {
        return 'ip';
    }

    // Domain pattern (anything with a dot that's not an IP)
    if (cleanQuery.includes('.')) {
        return 'whois';
    }
    return 'unknown';
}

// Helper function to parse WHOIS data
async function parseWhoisData(data, domain) {
    // Split into lines and create key-value pairs
    const result = {
        domainName: domain,
        registrar: '',
        creationDate: '',
        expirationDate: '',
        lastUpdated: '',
        status: [],
        nameservers: [],
        ipAddresses: {
            v4: [],
            v6: []
        },
        raw: data
    };

    // Get both IPv4 and IPv6 addresses from DNS lookup
    try {
        const dns = require('dns').promises;
        const [ipv4Addresses, ipv6Addresses] = await Promise.all([
            dns.resolve4(domain).catch(() => []),
            dns.resolve6(domain).catch(() => [])
        ]);
        result.ipAddresses.v4 = ipv4Addresses;
        result.ipAddresses.v6 = ipv6Addresses;
    } catch (e) {
        // If DNS lookup fails, keep arrays empty
    }

    // Regular expressions for IP addresses
    const ipv4Regex = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g;
    const ipv6Regex = /(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})|:(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(?::[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(?:ffff(?::0{1,4}){0,1}:){0,1}(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])|(?:[0-9a-fA-F]{1,4}:){1,4}:(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])/g;

    // First try to find IPs in specific fields that might contain them
    const lines = data.split('\n');
    for (const line of lines) {
        const trimmedLine = line.trim().toLowerCase();
        if (trimmedLine.includes('ip address') || 
            trimmedLine.includes('a record') || 
            trimmedLine.includes('aaaa record') ||
            trimmedLine.includes('addresses') ||
            trimmedLine.includes('host') ||
            trimmedLine.includes('dns')) {
            
            const ipv4InLine = line.match(ipv4Regex);
            const ipv6InLine = line.match(ipv6Regex);
            
            if (ipv4InLine) result.ipAddresses.v4.push(...ipv4InLine);
            if (ipv6InLine) result.ipAddresses.v6.push(...ipv6InLine);
        }
    }

    // Remove duplicates
    result.ipAddresses.v4 = [...new Set(result.ipAddresses.v4)];
    result.ipAddresses.v6 = [...new Set(result.ipAddresses.v6)];

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

// IP lookup services with fallbacks
const ipLookupServices = [
    {
        name: 'ipapi.co',
        url: (ip) => `https://ipapi.co/${ip}/json/`,
        transform: (data) => ({
            ...data,
            source: 'ipapi.co'
        })
    },
    {
        name: 'ip-api.com',
        url: (ip) => `http://ip-api.com/json/${ip}`,
        transform: (data) => ({
            ip: data.query,
            version: data.query.includes(':') ? 'IPv6' : 'IPv4',
            city: data.city,
            region: data.regionName,
            region_code: data.region,
            country_code: data.countryCode,
            country_name: data.country,
            postal: data.zip,
            latitude: data.lat,
            longitude: data.lon,
            timezone: data.timezone,
            org: data.org || data.isp,
            asn: data.as,
            source: 'ip-api.com'
        })
    },
    {
        name: 'ipwho.is',
        url: (ip) => `https://ipwho.is/${ip}`,
        transform: (data) => ({
            ip: data.ip,
            version: data.type,
            city: data.city,
            region: data.region,
            region_code: data.region_code,
            country_code: data.country_code,
            country_name: data.country,
            postal: data.postal,
            latitude: data.latitude,
            longitude: data.longitude,
            timezone: data.timezone.id,
            org: data.connection.org,
            asn: data.connection.asn,
            source: 'ipwho.is'
        })
    }
];

// Helper function to fetch ASN data from RIPEstat and PeeringDB
async function fetchASNData(asnNumber) {
    // RIPEstat whois endpoint provides comprehensive ASN information
    // Works for all RIRs: ARIN, RIPE, APNIC, LACNIC, AFRINIC
    const whoisUrl = `https://stat.ripe.net/data/whois/data.json?resource=AS${asnNumber}`;
    const overviewUrl = `https://stat.ripe.net/data/as-overview/data.json?resource=AS${asnNumber}`;
    const peeringDbUrl = `https://www.peeringdb.com/api/net?asn=${asnNumber}`;

    // Fetch all endpoints in parallel (PeeringDB is optional, don't fail if unavailable)
    const [whoisResponse, overviewResponse, peeringDbResponse] = await Promise.all([
        http.get(whoisUrl),
        http.get(overviewUrl),
        http.get(peeringDbUrl).catch(() => ({ data: { data: [] } }))
    ]);

    const whoisData = whoisResponse.data;
    const overviewData = overviewResponse.data;
    const peeringDbData = peeringDbResponse.data?.data?.[0] || {};

    // Parse WHOIS records to extract relevant fields
    const records = whoisData.data?.records || [];
    const flatRecords = records.flat();

    // Helper to find value by key in WHOIS records (case-insensitive)
    const findValue = (key) => {
        const record = flatRecords.find(r => r.key?.toLowerCase() === key.toLowerCase());
        return record?.value || '';
    };

    // Helper to find all values by key (case-insensitive)
    const findAllValues = (key) => {
        return flatRecords
            .filter(r => r.key?.toLowerCase() === key.toLowerCase())
            .map(r => r.value)
            .filter(Boolean);
    };

    // Determine RIR from source field or authority
    const source = findValue('source') || whoisData.data?.authorities?.[0] || '';
    const isARIN = source.toUpperCase() === 'ARIN';

    // Extract holder info from overview (format: "NAME - Description, CC")
    const holder = overviewData.data?.holder || '';
    const holderParts = holder.split(' - ');
    const name = holderParts[0] || findValue('as-name') || findValue('ASName') || findValue('aut-num');

    // Try to extract country code from holder or WHOIS
    let countryCode = findValue('country');
    if (!countryCode && holder) {
        // Try to extract from holder string (e.g., "CLOUDFLARENET - Cloudflare, Inc., US")
        const ccMatch = holder.match(/,\s*([A-Z]{2})$/);
        if (ccMatch) countryCode = ccMatch[1];
    }

    // Extract description - ARIN uses OrgName, RIPE uses descr
    const descriptions = findAllValues('descr');
    const orgName = findValue('OrgName');
    const description = descriptions[0] || orgName || (holderParts.length > 1 ? holderParts.slice(1).join(' - ') : '');

    // Extract email contacts - handle both RIPE and ARIN formats
    let emailContacts = findAllValues('e-mail');
    if (emailContacts.length === 0) {
        // ARIN format: OrgTechEmail, OrgNOCEmail
        const techEmail = findAllValues('OrgTechEmail');
        const nocEmail = findAllValues('OrgNOCEmail');
        emailContacts = [...new Set([...techEmail, ...nocEmail])];
    }
    // Fallback to contact handles if no emails found
    if (emailContacts.length === 0) {
        const techC = findAllValues('tech-c');
        const adminC = findAllValues('admin-c');
        emailContacts = [...techC, ...adminC];
    }

    // Extract abuse contacts - handle both RIPE and ARIN formats
    let abuseContacts = findAllValues('abuse-mailbox');
    if (abuseContacts.length === 0) {
        // ARIN format: OrgAbuseEmail
        abuseContacts = findAllValues('OrgAbuseEmail');
    }
    if (abuseContacts.length === 0) {
        abuseContacts = findAllValues('abuse-c');
    }

    // Extract address - handle both RIPE and ARIN formats
    const remarks = findAllValues('remarks');
    let ownerAddress = findAllValues('address');

    if (ownerAddress.length === 0 && isARIN) {
        // ARIN uses separate fields: Address, City, StateProv, PostalCode, Country
        const streetAddr = findValue('Address');
        const city = findValue('City');
        const state = findValue('StateProv');
        const postal = findValue('PostalCode');
        const addrCountry = findValue('Country');

        const addrParts = [streetAddr];
        if (city || state || postal) {
            addrParts.push([city, state, postal].filter(Boolean).join(', '));
        }
        if (addrCountry) addrParts.push(addrCountry);
        ownerAddress = addrParts.filter(Boolean);
    }

    if (ownerAddress.length === 0) {
        ownerAddress = remarks.filter(r => !r.includes('http'));
    }

    const rirMap = {
        'RIPE': 'RIPE NCC',
        'ARIN': 'ARIN',
        'APNIC': 'APNIC',
        'LACNIC': 'LACNIC',
        'AFRINIC': 'AFRINIC',
        'RADB': 'RADB'
    };
    const rirName = rirMap[source.toUpperCase()] || source || 'Unknown';

    // Extract dates - handle both RIPE and ARIN formats
    // ARIN uses RegDate, RIPE uses created
    const created = findValue('created') || findValue('RegDate') || findValue('reg-date');
    const lastModified = findValue('last-modified') || findValue('Updated') || findValue('changed');

    // Extract website - prefer PeeringDB, fallback to WHOIS remarks
    const website = peeringDbData.website || remarks.find(r => r.includes('http')) || '';

    // Build response in BGPView-compatible format
    return {
        data: {
            asn: parseInt(asnNumber),
            name: name,
            description_short: description,
            country_code: countryCode,
            website: website,
            email_contacts: emailContacts,
            abuse_contacts: abuseContacts.length > 0 ? abuseContacts : emailContacts,
            owner_address: ownerAddress,
            rir_allocation: {
                rir_name: rirName,
                date_allocated: created
            },
            traffic_ratio: peeringDbData.info_ratio || null,  // From PeeringDB
            date_updated: lastModified
        }
    };
}

// Helper function to try IP lookup services in sequence
async function tryIpLookup(ip) {
    // Remove brackets and CIDR notation for the lookup
    const cleanIp = ip.replace(/^\[|\]$/g, '').replace(/\/\d+$/, '');
    let lastError = null;
    
    for (const service of ipLookupServices) {
        try {
            console.log(`Trying IP lookup with ${service.name}...`);
            const response = await http.get(service.url(cleanIp));

            // Check if the service returned an error (ipapi.co: error, ip-api.com: status 'fail', ipwho.is: success false)
            const data = response.data;
            if (data.error || data.status === 'fail' || data.success === false) {
                throw new Error(data.reason || data.message || 'Service returned error');
            }
            
            // Transform the data to our standard format
            return service.transform(response.data);
        } catch (error) {
            console.log(`${service.name} lookup failed:`, error.message);
            lastError = error;
            // Continue to next service
            continue;
        }
    }
    
    // If we get here, all services failed
    throw lastError;
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
                const parsedData = await parseWhoisData(whoisData, query);
                
                response = {
                    data: {
                        ldhName: parsedData.domainName,
                        handle: query,
                        status: parsedData.status,
                        ipAddresses: parsedData.ipAddresses,
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
                const ipData = await tryIpLookup(query);
                response = { data: ipData };
                break;
            case 'asn':
                // Remove 'AS' prefix if present
                const asnNumber = query.replace(/^(AS|as)/i, '');
                const asnData = await fetchASNData(asnNumber);
                response = { data: asnData };
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
        if (error.response) {
            if (error.response.status === 429) {
                res.status(429).json({ 
                    error: 'Rate limit exceeded', 
                    message: 'All IP lookup services are currently rate limited. Please try again later.'
                });
            } else if (error.response.status === 404) {
                res.status(404).json({ error: `${queryType.toUpperCase()} not found` });
            } else {
                res.status(error.response.status).json({ 
                    error: `Error fetching ${queryType.toUpperCase()} data`, 
                    message: error.response.data?.message || error.message 
                });
            }
        } else {
            res.status(500).json({ 
                error: `Error fetching ${queryType.toUpperCase()} data`, 
                message: error.message 
            });
        }
    }
});

// Serve the pwa/asset manifest
app.get('/asset-manifest.json', (req, res) => {
    // generated in pwa-manifest-generator and fetched from service-worker.js
    res.sendFile(path.join(ASSETS_DIR, 'asset-manifest.json'));
});
app.get('/manifest.json', (req, res) => {
    res.sendFile(path.join(ASSETS_DIR, 'manifest.json'));
});

app.get('/config', (req, res) => {
    res.json({
        siteTitle: SITE_TITLE
    });
});

app.get('/managers/toast', (req, res) => {
    res.sendFile(path.join(PUBLIC_DIR, 'managers', 'toast.js'));
});

app.get('/health', (_req, res) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
    console.log(`Server is running on: http://localhost:${PORT}`);
}); 