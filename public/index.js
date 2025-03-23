import { ToastManager } from "./managers/toast";

document.addEventListener('DOMContentLoaded', () => {
    const toastManager = new ToastManager(document.getElementById('toast-container'));
    const siteTitle = document.getElementById('site-title');
    const themeToggleBtn = document.getElementById('theme-toggle');
    const sunIcon = document.getElementById('sunIcon');
    const moonIcon = document.getElementById('moonIcon');
    const queryInput = document.getElementById('queryInput');
    const lookupButton = document.getElementById('lookupButton');
    const printButton = document.getElementById('printButton');
    const resultDiv = document.getElementById('result');
    const resultContent = document.getElementById('resultContent');
    const queryTypeDiv = document.getElementById('queryType');

    function updateThemeIcon() {
        const isDark = document.documentElement.classList.contains('dark');
        if (isDark) {
            sunIcon.classList.add('hidden'); 
            moonIcon.classList.remove('hidden');
        }
        else {
            moonIcon.classList.add('hidden'); 
            sunIcon.classList.remove('hidden');
        }
    }

    function toggleDarkMode() {
        const html = document.documentElement;
        const isDark = html.classList.contains('dark');
        html.classList.toggle('dark');
        localStorage.setItem('darkMode', !isDark);
        document.documentElement.setAttribute('data-theme', isDark ? 'dark' : 'light');
        updateThemeIcon();
    }

    // Set Site Title
    const setSiteTitle = () => {
        fetch('config').then(async res => {
            const data = await res.json();
            if (data.siteTitle) {
                const title = `${data.siteTitle} - Simple WHOIS Lookup`;
                document.title = title;
                siteTitle.textContent = data.siteTitle;
            }
        })
    }

    function formatDate(dateString) {
        return dateString ? new Date(dateString).toLocaleString() : 'N/A';
    }

    function formatWhoisData(data) {
        let html = '<div class="space-y-4">';

        // Domain Info
        html += `
            <div id="domain-info" class="bg-blue-50 p-4 rounded-lg relative">
                <h2 class="text-lg font-bold text-blue-800 mb-2">
                    Domain Information
                    <a href="#domain-info" class="permalink" title="Permalink to this section">
                        <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4 inline-block ml-1 opacity-50 hover:opacity-100" viewBox="0 0 20 20" fill="currentColor">
                            <path fill-rule="evenodd" d="M12.586 4.586a2 2 0 112.828 2.828l-3 3a2 2 0 01-2.828 0 1 1 0 00-1.414 1.414 4 4 0 005.656 0l3-3a4 4 0 00-5.656-5.656l-1.5 1.5a1 1 0 101.414 1.414l1.5-1.5zm-5 5a2 2 0 012.828 0 1 1 0 101.414-1.414 4 4 0 00-5.656 0l-3 3a4 4 0 105.656 5.656l1.5-1.5a1 1 0 10-1.414-1.414l-1.5 1.5a2 2 0 11-2.828-2.828l3-3z" clip-rule="evenodd" />
                        </svg>
                    </a>
                </h2>
                <div class="grid grid-cols-1 md:grid-cols-2 gap-2">
                    <div class="data-row p-2">
                        <span class="font-semibold">Domain:</span> ${data.ldhName}
                    </div>
                    <div class="data-row p-2">
                        <span class="font-semibold">Handle:</span> ${data.handle}
                    </div>
                </div>
            </div>`;

        // IP Addresses - Always show this section for domains
        html += `
            <div id="ip-addresses" class="bg-red-50 dark:bg-red-900/20 p-4 rounded-lg relative">
                <h2 class="text-lg font-bold text-red-800 dark:text-red-400 mb-2">
                    IP Addresses
                    <a href="#ip-addresses" class="permalink" title="Permalink to this section">
                        <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4 inline-block ml-1 opacity-50 hover:opacity-100" viewBox="0 0 20 20" fill="currentColor">
                            <path fill-rule="evenodd" d="M12.586 4.586a2 2 0 112.828 2.828l-3 3a2 2 0 01-2.828 0 1 1 0 00-1.414 1.414 4 4 0 005.656 0l3-3a4 4 0 00-5.656-5.656l-1.5 1.5a1 1 0 101.414 1.414l1.5-1.5zm-5 5a2 2 0 012.828 0 1 1 0 101.414-1.414 4 4 0 00-5.656 0l-3 3a4 4 0 105.656 5.656l1.5-1.5a1 1 0 10-1.414-1.414l-1.5 1.5a2 2 0 11-2.828-2.828l3-3z" clip-rule="evenodd" />
                        </svg>
                    </a>
                </h2>`;

        if (data.ipAddresses && data.ipAddresses.v4 && data.ipAddresses.v4.length > 0) {
            html += `
                <div class="mb-3">
                    <h3 class="text-sm font-semibold text-red-700 dark:text-red-300 mb-2">IPv4</h3>
                    <div class="flex flex-wrap gap-2">
                        ${data.ipAddresses.v4.map(ip => 
                            `<button class="ipLookupButton bg-red-100 dark:bg-red-800 text-red-800 dark:text-red-200 px-3 py-1 rounded-full text-sm hover:bg-red-200 dark:hover:bg-red-700 cursor-pointer transition-colors">
                                ${ip}
                            </button>`
                        ).join('')}
                    </div>
                </div>`;
        } else {
            html += `
                <div class="mb-3">
                    <h3 class="text-sm font-semibold text-red-700 dark:text-red-300 mb-2">IPv4</h3>
                    <div class="text-gray-600 dark:text-gray-400">No IPv4 addresses found</div>
                </div>`;
        }

        if (data.ipAddresses && data.ipAddresses.v6 && data.ipAddresses.v6.length > 0) {
            html += `
                <div>
                    <h3 class="text-sm font-semibold text-red-700 dark:text-red-300 mb-2">IPv6</h3>
                    <div class="flex flex-wrap gap-2">
                        ${data.ipAddresses.v6.map(ip => 
                            `<button class="ipLookupButton bg-red-100 dark:bg-red-800 text-red-800 dark:text-red-200 px-3 py-1 rounded-full text-sm hover:bg-red-200 dark:hover:bg-red-700 cursor-pointer transition-colors">
                                ${ip}
                            </button>`
                        ).join('')}
                    </div>
                </div>`;
        } else {
            html += `
                <div>
                    <h3 class="text-sm font-semibold text-red-700 dark:text-red-300 mb-2">IPv6</h3>
                    <div class="text-gray-600 dark:text-gray-400">No IPv6 addresses found</div>
                </div>`;
        }

        html += `</div>`;

        // Status
        if (data.status && data.status.length > 0) {
            html += `
                <div id="domain-status" class="bg-green-50 p-4 rounded-lg relative">
                    <h2 class="text-lg font-bold text-green-800 mb-2">
                        Domain Status
                        <a href="#domain-status" class="permalink" title="Permalink to this section">
                            <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4 inline-block ml-1 opacity-50 hover:opacity-100" viewBox="0 0 20 20" fill="currentColor">
                                <path fill-rule="evenodd" d="M12.586 4.586a2 2 0 112.828 2.828l-3 3a2 2 0 01-2.828 0 1 1 0 00-1.414 1.414 4 4 0 005.656 0l3-3a4 4 0 00-5.656-5.656l-1.5 1.5a1 1 0 101.414 1.414l1.5-1.5zm-5 5a2 2 0 012.828 0 1 1 0 101.414-1.414 4 4 0 00-5.656 0l-3 3a4 4 0 105.656 5.656l1.5-1.5a1 1 0 10-1.414-1.414l-1.5 1.5a2 2 0 11-2.828-2.828l3-3z" clip-rule="evenodd" />
                            </svg>
                        </a>
                    </h2>
                    <div class="flex flex-wrap gap-2">
                        ${data.status.map(status => 
                            `<span class="bg-green-100 text-green-800 px-2 py-1 rounded-full text-sm">${status}</span>`
                        ).join('')}
                    </div>
                </div>`;
        }

        // Important Dates
        if (data.events && data.events.length > 0) {
            html += `
                <div id="important-dates" class="bg-purple-50 p-4 rounded-lg relative">
                    <h2 class="text-lg font-bold text-purple-800 mb-2">
                        Important Dates
                        <a href="#important-dates" class="permalink" title="Permalink to this section">
                            <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4 inline-block ml-1 opacity-50 hover:opacity-100" viewBox="0 0 20 20" fill="currentColor">
                                <path fill-rule="evenodd" d="M12.586 4.586a2 2 0 112.828 2.828l-3 3a2 2 0 01-2.828 0 1 1 0 00-1.414 1.414 4 4 0 005.656 0l3-3a4 4 0 00-5.656-5.656l-1.5 1.5a1 1 0 101.414 1.414l1.5-1.5zm-5 5a2 2 0 012.828 0 1 1 0 101.414-1.414 4 4 0 00-5.656 0l-3 3a4 4 0 105.656 5.656l1.5-1.5a1 1 0 10-1.414-1.414l-1.5 1.5a2 2 0 11-2.828-2.828l3-3z" clip-rule="evenodd" />
                            </svg>
                        </a>
                    </h2>
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-2">
                        ${data.events.map(event => `
                            <div class="data-row p-2">
                                <span class="font-semibold">${event.eventAction}:</span> 
                                ${formatDate(event.eventDate)}
                            </div>
                        `).join('')}
                    </div>
                </div>`;
        }

        // Nameservers
        if (data.nameservers && data.nameservers.length > 0) {
            html += `
                <div id="nameservers" class="bg-yellow-50 p-4 rounded-lg relative">
                    <h2 class="text-lg font-bold text-yellow-800 mb-2">
                        Nameservers
                        <a href="#nameservers" class="permalink" title="Permalink to this section">
                            <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4 inline-block ml-1 opacity-50 hover:opacity-100" viewBox="0 0 20 20" fill="currentColor">
                                <path fill-rule="evenodd" d="M12.586 4.586a2 2 0 112.828 2.828l-3 3a2 2 0 01-2.828 0 1 1 0 00-1.414 1.414 4 4 0 005.656 0l3-3a4 4 0 00-5.656-5.656l-1.5 1.5a1 1 0 101.414 1.414l1.5-1.5zm-5 5a2 2 0 012.828 0 1 1 0 101.414-1.414 4 4 0 00-5.656 0l-3 3a4 4 0 105.656 5.656l1.5-1.5a1 1 0 10-1.414-1.414l-1.5 1.5a2 2 0 11-2.828-2.828l3-3z" clip-rule="evenodd" />
                            </svg>
                        </a>
                    </h2>
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-2">
                        ${data.nameservers.map(ns => `
                            <div class="data-row p-2">${ns.ldhName}</div>
                        `).join('')}
                    </div>
                </div>`;
        }

        // Registrar Info
        if (data.entities && data.entities.length > 0) {
            const registrar = data.entities.find(e => e.roles.includes('registrar'));
            if (registrar) {
                html += `
                    <div class="bg-indigo-50 p-4 rounded-lg">
                        <h2 class="text-lg font-bold text-indigo-800 mb-2">Registrar Information</h2>
                        <div class="space-y-2">
                            <div class="data-row p-2">
                                <span class="font-semibold">Registrar:</span> 
                                ${registrar.vcardArray[1].find(v => v[0] === 'fn')[3]}
                            </div>
                            ${registrar.entities ? registrar.entities.map(entity => `
                                <div class="data-row p-2">
                                    <span class="font-semibold">Abuse Contact:</span> 
                                    ${entity.vcardArray[1].find(v => v[0] === 'email')?.[3] || 'N/A'}
                                </div>
                            `).join('') : ''}
                        </div>
                    </div>`;
            }
        }

        html += '</div>';
        return html;
    }

    function formatIPData(data) {
        let html = '<div class="space-y-4">';
        
        // Basic Info
        html += `
            <div class="bg-blue-50 p-4 rounded-lg">
                <h2 class="text-lg font-bold text-blue-800 mb-2">IP Information</h2>
                <div class="grid grid-cols-1 md:grid-cols-2 gap-2">
                    <div class="data-row p-2">
                        <span class="font-semibold">IP Address:</span> ${data.ip}
                    </div>
                    <div class="data-row p-2">
                        <span class="font-semibold">Network:</span> ${data.network}
                    </div>
                    <div class="data-row p-2">
                        <span class="font-semibold">Version:</span> ${data.version}
                    </div>
                    <div class="data-row p-2">
                        <span class="font-semibold">Organization:</span> ${data.org}
                    </div>
                </div>
            </div>`;

        // Location Info
        html += `
            <div class="bg-green-50 p-4 rounded-lg">
                <h2 class="text-lg font-bold text-green-800 mb-2">Location Information</h2>
                <div class="grid grid-cols-1 md:grid-cols-2 gap-2">
                    <div class="data-row p-2">
                        <span class="font-semibold">City:</span> ${data.city}
                    </div>
                    <div class="data-row p-2">
                        <span class="font-semibold">Region:</span> ${data.region} (${data.region_code})
                    </div>
                    <div class="data-row p-2">
                        <span class="font-semibold">Country:</span> ${data.country_name} (${data.country_code})
                    </div>
                    <div class="data-row p-2">
                        <span class="font-semibold">Postal Code:</span> ${data.postal}
                    </div>
                    <div class="data-row p-2">
                        <span class="font-semibold">Continent:</span> ${data.continent_code}
                    </div>
                    <div class="data-row p-2">
                        <span class="font-semibold">Timezone:</span> ${data.timezone}
                    </div>
                </div>
            </div>`;

        // Coordinates
        html += `
            <div class="bg-yellow-50 p-4 rounded-lg">
                <h2 class="text-lg font-bold text-yellow-800 mb-2">Geographic Coordinates</h2>
                <div class="grid grid-cols-1 md:grid-cols-2 gap-2">
                    <div class="data-row p-2">
                        <span class="font-semibold">Latitude:</span> ${data.latitude}
                    </div>
                    <div class="data-row p-2">
                        <span class="font-semibold">Longitude:</span> ${data.longitude}
                    </div>
                </div>
            </div>`;

        // Additional Info
        html += `
            <div class="bg-purple-50 p-4 rounded-lg">
                <h2 class="text-lg font-bold text-purple-800 mb-2">Additional Information</h2>
                <div class="grid grid-cols-1 md:grid-cols-2 gap-2">
                    <div class="data-row p-2">
                        <span class="font-semibold">ASN:</span> ${data.asn}
                    </div>
                    <div class="data-row p-2">
                        <span class="font-semibold">Languages:</span> ${data.languages}
                    </div>
                    <div class="data-row p-2">
                        <span class="font-semibold">Currency:</span> ${data.currency} (${data.currency_name})
                    </div>
                    <div class="data-row p-2">
                        <span class="font-semibold">Calling Code:</span> ${data.country_calling_code}
                    </div>
                </div>
            </div>`;

        html += '</div>';
        return html;
    }

    function formatASNData(data) {
        const asnData = data.data;
        let html = '<div class="space-y-4">';
        
        // Basic Info
        html += `
            <div class="bg-blue-50 p-4 rounded-lg">
                <h2 class="text-lg font-bold text-blue-800 mb-2">ASN Information</h2>
                <div class="grid grid-cols-1 md:grid-cols-2 gap-2">
                    <div class="data-row p-2">
                        <span class="font-semibold">ASN:</span> AS${asnData.asn}
                    </div>
                    <div class="data-row p-2">
                        <span class="font-semibold">Name:</span> ${asnData.name}
                    </div>
                    <div class="data-row p-2">
                        <span class="font-semibold">Description:</span> ${asnData.description_short}
                    </div>
                    <div class="data-row p-2">
                        <span class="font-semibold">Country:</span> ${asnData.country_code}
                    </div>
                </div>
            </div>`;

        // Contact Info
        html += `
            <div class="bg-green-50 p-4 rounded-lg">
                <h2 class="text-lg font-bold text-green-800 mb-2">Contact Information</h2>
                <div class="space-y-2">
                    <div class="data-row p-2">
                        <span class="font-semibold">Website:</span> 
                        <a href="${asnData.website}" target="_blank" class="text-blue-600 hover:underline">
                            ${asnData.website}
                        </a>
                    </div>
                    <div class="data-row p-2">
                        <span class="font-semibold">Email Contacts:</span><br>
                        ${asnData.email_contacts.map(email => 
                            `<span class="ml-4">• ${email}</span>`
                        ).join('<br>')}
                    </div>
                    <div class="data-row p-2">
                        <span class="font-semibold">Abuse Contacts:</span><br>
                        ${asnData.abuse_contacts.map(email => 
                            `<span class="ml-4">• ${email}</span>`
                        ).join('<br>')}
                    </div>
                </div>
            </div>`;

        // Address
        if (asnData.owner_address && asnData.owner_address.length > 0) {
            html += `
                <div class="bg-yellow-50 p-4 rounded-lg">
                    <h2 class="text-lg font-bold text-yellow-800 mb-2">Owner Address</h2>
                    <div class="p-2">
                        ${asnData.owner_address.join('<br>')}
                    </div>
                </div>`;
        }

        // RIR & IANA Info
        html += `
            <div class="bg-purple-50 p-4 rounded-lg">
                <h2 class="text-lg font-bold text-purple-800 mb-2">Registry Information</h2>
                <div class="grid grid-cols-1 md:grid-cols-2 gap-2">
                    <div class="data-row p-2">
                        <span class="font-semibold">RIR Name:</span> ${asnData.rir_allocation.rir_name}
                    </div>
                    <div class="data-row p-2">
                        <span class="font-semibold">Allocation Date:</span> ${formatDate(asnData.rir_allocation.date_allocated)}
                    </div>
                    <div class="data-row p-2">
                        <span class="font-semibold">Traffic Ratio:</span> ${asnData.traffic_ratio || 'N/A'}
                    </div>
                    <div class="data-row p-2">
                        <span class="font-semibold">Last Updated:</span> ${formatDate(asnData.date_updated)}
                    </div>
                </div>
            </div>`;

        html += '</div>';
        return html;
    }

    function handleIpLookupClick(ip) {
        queryInput.value = ip;
        performLookup();
    }

    async function performLookup() {
        const query = queryInput.value.trim();
        toastManager.clear();

        if (!query) {
            alert('Please enter a value to lookup');
            return;
        }

        resultDiv.classList.remove('hidden');
        printButton.classList.add('hidden');
        queryTypeDiv.textContent = 'Loading...';
        resultContent.innerHTML = '';

        try {
            const response = await fetch(`/api/lookup/${query}`);
            const data = await response.json();
            
            if (data.error) {
                queryTypeDiv.textContent = 'Error';
                resultContent.innerHTML = `<div class="text-red-600">${data.error}${data.message ? '<br>' + data.message : ''}</div>`;
            } else {
                queryTypeDiv.textContent = `Type: ${data.type.toUpperCase()}${
                    data.type === 'ip' ? ` (Source: ${data.data.source})` :
                    data.type === 'asn' ? ' (Source: BGPView)' :
                    data.type === 'whois' ? ' (Source: Direct WHOIS Server)' : ''
                }`;
                
                switch (data.type) {
                    case 'whois':
                        resultContent.innerHTML = formatWhoisData(data.data);
                        break;
                    case 'ip':
                        resultContent.innerHTML = formatIPData(data.data);
                        break;
                    case 'asn':
                        resultContent.innerHTML = formatASNData(data.data);
                        break;
                    default:
                        resultContent.innerHTML = `<pre class="whitespace-pre-wrap">${JSON.stringify(data.data, null, 2)}</pre>`;
                }

                // Add event listener to IP lookup buttons
                const ipButtons = document.querySelectorAll('.ipLookupButton');
                ipButtons.forEach(button => {
                    button.addEventListener('click', () => handleIpLookupClick(button.textContent.trim()));
                });

                // Show print button after successful lookup
                printButton.classList.remove('hidden');

                toastManager.show('Lookup complete', 'success', false, 1000);
            }
        } catch (error) {
            console.error(error);
            toastManager.show('Error performing lookup. Please try again.', 'error', true);
        }
    }

    function printResults() {
        const title = queryInput.value.trim();
        const originalTitle = document.title;
        document.title = `DumbWhois - ${title}`;
        window.print();
        document.title = originalTitle;
    }

    // Check for lookup query parameter and hash on page load
    const performLookupOnLoad = async () => {
        const urlParams = new URLSearchParams(window.location.search);
        const lookupQuery = urlParams.get('lookup');
        if (lookupQuery) {
            queryInput.value = lookupQuery;
            performLookup().then(() => {
                // After lookup completes, check if there's a hash to scroll to
                if (window.location.hash) {
                    // Small delay to ensure content is rendered
                    setTimeout(() => {
                        const targetElement = document.querySelector(window.location.hash);
                        if (targetElement) {
                            targetElement.scrollIntoView();
                        }
                    }, 500);
                }
            });
        }
    }

    const addButtonEventListeners = () => {
        lookupButton.addEventListener('click', performLookup);  
        themeToggleBtn.addEventListener('click', toggleDarkMode);  themeToggleBtn.addEventListener('click', toggleDarkMode);
        queryInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                performLookup();
            }
        });
        printButton.addEventListener('click', printResults);
    }

    const initialize = async () => {
        // Check local storage, default to dark mode if not set
        if (localStorage.getItem('darkMode') === 'false') {
            document.documentElement.classList.remove('dark');
        }

        // Initialize App
        addButtonEventListeners();
        updateThemeIcon();
        setSiteTitle();
        performLookupOnLoad();

        queryInput.focus();
    }

    initialize();
});