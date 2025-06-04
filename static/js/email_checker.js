document.addEventListener('DOMContentLoaded', () => {
    // Function to add active class to current nav link
    const currentPath = window.location.pathname;
    document.querySelectorAll('nav ul li a').forEach(link => {
        if (link.getAttribute('href') === currentPath) {
            link.classList.add('active');
        }
    });

    // --- Phishing Email Checker Logic ---
    const emailContentTextarea = document.getElementById('emailContent');
    const checkEmailButton = document.getElementById('checkEmailButton');
    const emailLoadingIndicator = document.getElementById('emailLoadingIndicator');
    const emailResultsDiv = document.getElementById('emailResults');

    // Only activate if elements exist on the page
    if (checkEmailButton && emailContentTextarea && emailLoadingIndicator && emailResultsDiv) {
        checkEmailButton.addEventListener('click', async () => {
            const emailContent = emailContentTextarea.value.trim();
            if (!emailContent) {
                alert('Please paste email content to check.');
                return;
            }

            emailResultsDiv.innerHTML = ''; // Clear previous results
            emailLoadingIndicator.classList.remove('hidden'); // Show loading indicator
            checkEmailButton.disabled = true; // Disable button during check

            try {
                const response = await fetch('/check_email', { // POST request to our Flask backend for email check
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ email_content: emailContent })
                });

                const data = await response.json(); // Parse the JSON response

                emailLoadingIndicator.classList.add('hidden'); // Hide loading indicator
                checkEmailButton.disabled = false; // Re-enable button

                if (data.error) {
                    emailResultsDiv.innerHTML = `<div class="result-item severity-Error"><h3>Error:</h3><p>${data.error}</p></div>`;
                    return;
                }

                // --- Overall Safety Summary (NEW) ---
                let overallSafetyClass = 'severity-Info';
                let overallSafetyText = 'Overall: Looks Safe';
                if (data.overall_verdict === 'Not Safe') {
                    overallSafetyClass = 'severity-Critical'; // Use Critical for "Not Safe"
                    overallSafetyText = 'Overall: Not Safe - Likely Phishing!';
                } else if (data.overall_verdict === 'Potentially Unsafe') {
                    overallSafetyClass = 'severity-High'; // Use High for "Potentially Unsafe"
                    overallSafetyText = 'Overall: Potentially Unsafe - Review Indicators.';
                }

                emailResultsDiv.innerHTML += `
                    <div class="result-item ${overallSafetyClass}" style="text-align: center; font-size: 1.4em; padding: 20px;">
                        <h2>${overallSafetyText}</h2>
                    </div>
                `;

                // Display email analysis summary
                emailResultsDiv.innerHTML += `
                    <div class="result-item">
                        <h3>Email Analysis Summary:</h3>
                        <p><strong>Overall Status:</strong> <span class="severity-${data.status.includes('Phishing') ? (data.status.includes('Likely') ? 'High' : 'Medium') : 'Info'}">${data.status}</span></p>
                        <p><strong>Suspicion Score:</strong> ${data.score} (Higher score indicates more suspicion)</p>
                        <p><strong>Note:</strong> ${data.description}</p>
                    </div>
                `;

                if (data.indicators && data.indicators.length > 0) {
                    emailResultsDiv.innerHTML += `
                        <div class="result-item">
                            <h3>Detected Indicators:</h3>
                            <ul>
                                ${data.indicators.map(indicator => `
                                    <li>
                                        <strong>Type:</strong> ${indicator.type}<br>
                                        <strong>Description:</strong> ${indicator.description}<br>
                                        <strong>Severity:</strong> <span class="severity-${indicator.severity}">${indicator.severity}</span>
                                    </li>
                                `).join('')}
                            </ul>
                        </div>
                    `;
                } else {
                    emailResultsDiv.innerHTML += `
                        <div class="result-item severity-Info">
                            <h3>No Specific Phishing Indicators Detected</h3>
                            <p>Based on our basic checks, this email does not show obvious signs of phishing. Always be cautious, as advanced phishing emails can bypass simple checks and require human judgment.</p>
                        </div>
                    `;
                }

            } catch (error) {
                emailLoadingIndicator.classList.add('hidden');
                checkEmailButton.disabled = false;
                emailResultsDiv.innerHTML = `<div class="result-item severity-Error"><h3>Network Error:</h3><p>Could not connect to the backend server for email check: ${error.message}</p><p>Please ensure the backend is running and accessible.</p></div>`;
                console.error('Email fetch error:', error);
            }
        });
    }
});