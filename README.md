# DumbWhois

A simple web application for looking up WHOIS, IP, and ASN information using free APIs. The application automatically detects the type of query and provides formatted results with a clean, modern UI that supports both light and dark modes.

![image](https://github.com/user-attachments/assets/a4f84c05-c8f8-4e75-9788-dc70adc2ad9b)


## Features

- 🔍 Automatic detection of query type (Domain, IP, or ASN)
- 🌐 Direct WHOIS domain lookup with support for all TLDs
- 🌍 IP geolocation with multiple fallback services
- 🔢 ASN (Autonomous System Number) details
- 🎨 Clean and modern UI with dark mode support
- 📱 Responsive design for mobile and desktop
- 🚫 No authentication required
- ⚙️ Environment variable configuration
- 🔄 Automatic service fallback for IP lookups
- 🌐 Full IPv6 support
- 📋 Clear source attribution for all lookups
- 🔍 DNS resolution for domain IP addresses
- 🔗 URL query parameter support for direct lookups
- 🔖 Permalink anchors for sharing specific result sections
- 🔒 CORS support for cross-origin requests
- 🌐 PWA Support

## APIs Used

The application uses the following free services:

- **WHOIS Lookup**: Direct WHOIS protocol
  - Native WHOIS queries to authoritative servers
  - Support for all TLDs including ccTLDs
  - DNS resolution for IPv4 and IPv6 addresses
  - No API key required
  - No rate limits

- **IP Lookup**: Multiple services with automatic fallback
  1. [ipapi.co](https://ipapi.co)
     - Primary service for IP geolocation
     - Free tier with rate limits
     - No API key required
  2. [ip-api.com](https://ip-api.com)
     - First fallback service
     - Free for non-commercial use
     - No API key required
  3. [ipwho.is](https://ipwho.is)
     - Second fallback service
     - Free with no rate limits
     - No API key required

- **ASN Lookup**: [RIPEstat API](https://stat.ripe.net/docs/data-api/ripestat-data-api) + [PeeringDB](https://www.peeringdb.com/apidocs/)
  - RIPEstat provides ASN details and WHOIS information
  - PeeringDB provides traffic ratio and website info
  - Works for all RIRs (ARIN, RIPE, APNIC, LACNIC, AFRINIC)
  - Free to use
  - No authentication required


## Easypanel

DumbWhois has a one-click deployment template on [Easypanel](https://easypanel.io), a self-hosted Docker deployment platform.

[![Deploy on Easypanel][easypanel-btn]][easypanel-deploy]

[easypanel-btn]: https://easypanel.io/img/deploy-on-easypanel-40.svg
[easypanel-deploy]: https://easypanel.io/templates/dumbwhois

## Setup

### Standard Setup

1. Clone the repository:
```bash
git clone https://github.com/dumbwareio/dumbwhois.git
cd dumbwhois
```

2. Install dependencies:
```bash
npm install
```

3. Configure environment variables:
```bash
cp .env.example .env
# Edit .env to set your desired port (default is 3000)
```

4. Start the server:
```bash
npm start
```

For development with auto-reload:
```bash
npm run dev
```

### Docker Setup

1. Build the Docker image:
```bash
docker build -t dumbwhois .
```

2. Run the container:
```bash
docker run -p 3000:3000 -d dumbwhois
```

Or using Docker Compose:
```bash
docker-compose up -d
```

docker-compose.yml:
```yaml
services:
   dumbwhois:
      image: dumbwareio/dumbwhois:latest
      container_name: dumbwhois
      restart: unless-stopped
      ports:
      - ${DUMBWHOIS_PORT:-3000}:3000
      environment:
      - SITE_TITLE=${DUMBWHOIS_SITE_TITLE:-DumbWhois}
      # (Optional) Restrict origins - ex: https://subdomain.domain.tld,https://auth.proxy.tld,http://internalip:port' (empty/default is '*')
      # - ALLOWED_ORIGINS=${DUMBWHOIS_ALLOWED_ORIGINS:-*}
```

## Usage

1. Visit `http://localhost:3000` in your browser
2. Enter any of the following:
   - Domain name (e.g., `yahoo.com`, `europa.eu`)
   - IP address (IPv4 or IPv6, e.g., `8.8.8.8`, `2001:4860:4860::8888`)
   - ASN number (e.g., `AS13335` or just `13335`)
3. The application will automatically detect the type of query and display formatted results
4. Toggle between light and dark modes using the moon icon in the top-right corner

You can also perform direct lookups by using the `lookup` query parameter in the URL:
- Domain lookup: `http://localhost:3000/?lookup=google.com`
- IP lookup: `http://localhost:3000/?lookup=8.8.8.8`
- ASN lookup: `http://localhost:3000/?lookup=AS13335`

### Permalink Anchors

Each section of the results now has a permalink anchor that allows direct linking to specific information:
- Click the link icon (🔗) next to any section header to copy a direct link to that section
- Share links to specific sections, like nameservers or IP addresses: `http://localhost:3000/?lookup=google.com#nameservers`
- When following a permalink, the page will automatically scroll to the relevant section
- Sections are briefly highlighted when accessed via permalink for better visibility

## Example Queries

- **Domain Lookup**: `google.com`, `europa.eu`, `bbc.co.uk`
- **IPv4 Lookup**: `8.8.8.8`, `1.1.1.1`, `140.82.121.4`
- **IPv6 Lookup**: `2001:4860:4860::8888`, `2606:4700:4700::1111`
- **ASN Lookup**: `AS13335`, `AS15169`, `AS8075`

## Rate Limits

Please note that some APIs used have rate limits:
- WHOIS: No rate limits (uses direct protocol)
- ipapi.co: 1000 requests per day (free tier)
- ip-api.com: 45 requests per minute
- ipwho.is: No rate limits
- RIPEstat: No strict rate limits (fair use policy)
- PeeringDB: No strict rate limits (fair use policy)

The application automatically handles rate limits by falling back to alternative services when needed.

## Support the Project

<a href="https://www.buymeacoffee.com/dumbware" target="_blank">
  <img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" height="60">
</a>

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
