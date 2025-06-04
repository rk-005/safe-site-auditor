document.addEventListener('DOMContentLoaded', () => {
    // Function to add active class to current nav link
    const currentPath = window.location.pathname;
    document.querySelectorAll('nav ul li a').forEach(link => {
        if (link.getAttribute('href') === currentPath) {
            link.classList.add('active');
        }
    });

    // --- Website Scanner Logic ---
    const websiteUrlInput = document.getElementById('websiteUrl');
    const scanButton = document.getElementById('scanButton');
    const loadingIndicator = document.getElementById('loadingIndicator');
    const websiteResultsDiv = document.getElementById('websiteResults');

    // Only activate if elements exist on the page
    if (scanButton && websiteUrlInput && loadingIndicator && websiteResultsDiv) {
        scanButton.addEventListener('click', async () => {
            const url = websiteUrlInput.value.trim();
            if (!url) {
                alert('Please enter a website URL to scan.');
                return;
            }

            websiteResultsDiv.innerHTML = ''; // Clear previous results
            loadingIndicator.classList.remove('hidden'); // Show loading indicator
            scanButton.disabled = true; // Disable button during scan

            try {
                const response = await fetch('/scan', { // POST request to our Flask backend
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ url: url })
                });

                const data = await response.json(); // Parse the JSON response
                
                loadingIndicator.classList.add('hidden'); // Hide loading indicator
                scanButton.disabled = false; // Re-enable button

                if (data.error) {
                    websiteResultsDiv.innerHTML = `<div class="result-item severity-Error"><h3>Error:</h3><p>${data.error}</p></div>`;
                    return;
                }

                // --- Overall Safety Summary (NEW) ---
                let overallSafetyClass = 'severity-Info';
                let overallSafetyText = 'Overall: Looks Safe';
                if (data.overall_verdict === 'Not Safe') {
                    overallSafetyClass = 'severity-Critical'; // Use Critical for "Not Safe"
                    overallSafetyText = 'Overall: Not Safe - High Risk Detected!';
                } else if (data.overall_verdict === 'Potentially Unsafe') {
                    overallSafetyClass = 'severity-High'; // Use High for "Potentially Unsafe"
                    overallSafetyText = 'Overall: Potentially Unsafe - Review Findings.';
                }

                websiteResultsDiv.innerHTML += `
                    <div class="result-item ${overallSafetyClass}" style="text-align: center; font-size: 1.4em; padding: 20px;">
                        <h2>${overallSafetyText}</h2>
                    </div>
                `;

                // Display scan status and scanned URL
                websiteResultsDiv.innerHTML += `
                    <div class="result-item">
                        <h3>Scan Summary:</h3>
                        <p><strong>URL Scanned:</strong> ${data.url}</p>
                        <p><strong>Status:</strong> ${data.status}</p>
                    </div>
                `;

                // Display individual findings
                if (data.findings && data.findings.length > 0) {
                    data.findings.forEach(finding => {
                        const severityClass = `severity-${finding.severity}`; // For CSS styling
                        websiteResultsDiv.innerHTML += `
                            <div class="result-item">
                                <h3>${finding.vulnerability}</h3>
                                <p><strong>Type:</strong> ${finding.type}</p>
                                <p><strong>Severity:</strong> <span class="${severityClass}">${finding.severity}</span></p>
                                <p><strong>Description:</strong> ${finding.description}</p>
                                <p><strong>Recommendation:</strong> ${finding.recommendation}</p>
                            </div>
                        `;
                    });
                } else {
                    websiteResultsDiv.innerHTML += `
                        <div class="result-item severity-Info">
                            <h3>No Major Issues Detected</h3>
                            <p>Based on our basic checks, no immediate high-severity vulnerabilities were found. This does not guarantee complete security, but initial checks passed.</p>
                        </div>
                    `;
                }

                // Optionally display raw headers for advanced users or debugging
                if (Object.keys(data.raw_response_headers).length > 0) {
                    websiteResultsDiv.innerHTML += `
                        <div class="result-item">
                            <h3>Raw Response Headers:</h3>
                            <pre>${JSON.stringify(data.raw_response_headers, null, 2)}</pre>
                        </div>
                    `;
                }

            } catch (error) {
                loadingIndicator.classList.add('hidden');
                scanButton.disabled = false;
                websiteResultsDiv.innerHTML = `<div class="result-item severity-Error"><h3>Network Error:</h3><p>Could not connect to the backend server or an unexpected error occurred: ${error.message}</p><p>Please ensure the backend is running and accessible.</p></div>`;
                console.error('Fetch error:', error);
            }
        });
    }
});