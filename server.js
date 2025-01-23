require('dotenv').config();
const express = require('express');
const cors = require('cors');
const axios = require('axios');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

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

// Universal lookup endpoint
app.get('/api/lookup/:query', async (req, res) => {
    const query = req.params.query;
    const queryType = detectQueryType(query);

    try {
        let response;
        switch (queryType) {
            case 'whois':
                response = await axios.get(`https://rdap.org/domain/${query}`);
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