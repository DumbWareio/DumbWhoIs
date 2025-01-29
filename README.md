# DumbWhois

A simple web application for looking up WHOIS, IP, and ASN information using free APIs. The application automatically detects the type of query and provides formatted results with a clean, modern UI that supports both light and dark modes.

![image](https://github.com/user-attachments/assets/1f53b683-8974-4c83-9f14-d97aa862d531)


## Features

- 🔍 Automatic detection of query type (Domain, IP, or ASN)
- 🌐 Direct WHOIS domain lookup with support for all TLDs
- 🌍 IP geolocation and information lookup
- 🔢 ASN (Autonomous System Number) details
- 🎨 Clean and modern UI with dark mode support
- 📱 Responsive design for mobile and desktop
- 🚫 No authentication required
- ⚙️ Environment variable configuration

## APIs Used

The application uses the following free services:

- **WHOIS Lookup**: Direct WHOIS protocol
  - Native WHOIS queries to authoritative servers
  - Support for all TLDs including ccTLDs
  - No API key required
  - No rate limits

- **IP Lookup**: [ipapi.co](https://ipapi.co)
  - Provides geolocation and organization information
  - Free tier with rate limits
  - No API key required

- **ASN Lookup**: [BGPView API](https://bgpview.docs.apiary.io/)
  - Provides ASN details and related information
  - Free to use
  - No authentication required

## Setup

### Standard Setup

1. Clone the repository:
```bash
git clone https://github.com/abiteman/dumbwhois.git
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

## Usage

1. Visit `http://localhost:3000` in your browser
2. Enter any of the following:
   - Domain name (e.g., `yahoo.com`, `europa.eu`)
   - IP address (e.g., `8.8.8.8`)
   - ASN number (e.g., `AS13335` or just `13335`)
3. The application will automatically detect the type of query and display formatted results
4. Toggle between light and dark modes using the moon icon in the top-right corner

## Example Queries

- **Domain Lookup**: `google.com`, `europa.eu`, `bbc.co.uk`
- **IP Lookup**: `8.8.8.8`, `1.1.1.1`, `140.82.121.4`
- **ASN Lookup**: `AS13335`, `AS15169`, `AS8075`

## Rate Limits

Please note that some APIs used have rate limits:
- WHOIS: No rate limits (uses direct protocol)
- ipapi.co: 1000 requests per day (free tier)
- BGPView: Reasonable use policy

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

MIT 
