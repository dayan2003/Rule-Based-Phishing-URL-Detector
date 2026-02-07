const API_URL = '/analyze';

document.addEventListener('DOMContentLoaded', () => {
    const urlInput = document.getElementById('urlInput');
    const analyzeBtn = document.getElementById('analyzeBtn');
    const loadingDiv = document.getElementById('loading');
    const resultsDiv = document.getElementById('results');
    const errorDiv = document.getElementById('error');

    // Results elements
    const verdictBadge = document.getElementById('verdictBadge');
    const riskScore = document.getElementById('riskScore');
    const riskBar = document.getElementById('riskBar');
    const rulesList = document.getElementById('rulesList');
    const urlComponents = document.getElementById('urlComponents');

    analyzeBtn.addEventListener('click', handleAnalysis);
    urlInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') handleAnalysis();
    });

    async function handleAnalysis() {
        const url = urlInput.value.trim();

        if (!url) {
            showError("Please enter a URL.");
            return;
        }

        // Reset UI
        showError(null);
        resultsDiv.classList.add('hidden');
        loadingDiv.classList.remove('hidden');

        try {
            const response = await fetch(API_URL, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ url: url }),
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.error || "Failed to analyze URL.");
            }

            displayResults(data);

        } catch (err) {
            showError(err.message);
        } finally {
            loadingDiv.classList.add('hidden');
        }
    }

    function displayResults(data) {
        // 1. Verdict Styling
        verdictBadge.textContent = data.verdict;
        verdictBadge.className = 'verdict-badge'; // reset

        const verdictUpper = data.verdict ? data.verdict.toUpperCase() : '';

        if (verdictUpper === 'PHISHING') {
            verdictBadge.style.backgroundColor = 'var(--danger)';
            verdictBadge.style.color = 'white';
        } else if (verdictUpper === 'SUSPICIOUS') {
            verdictBadge.style.backgroundColor = 'var(--orange)';
            verdictBadge.style.color = 'white';
        } else {
            verdictBadge.style.backgroundColor = 'var(--success)';
            verdictBadge.style.color = 'white';
        }

        // 2. Score
        riskScore.textContent = Math.min(data.score, 100);
        riskBar.style.width = `${Math.min(data.score, 100)}%`;

        if (data.score >= 75) riskBar.style.backgroundColor = 'var(--danger)';
        else if (data.score >= 40) riskBar.style.backgroundColor = 'var(--warning)';
        else riskBar.style.backgroundColor = 'var(--success)';

        // 3. Rules
        rulesList.innerHTML = '';
        if (data.triggered_rules && data.triggered_rules.length > 0) {
            data.triggered_rules.forEach(rule => {
                const ruleDiv = document.createElement('div');
                ruleDiv.className = 'rule-item';
                ruleDiv.innerHTML = `
                    <div class="rule-header">
                        <span class="rule-name">${rule.name}</span>
                        <span class="rule-score">+${rule.score}</span>
                    </div>
                    <div class="rule-desc">${rule.description}</div>
                `;
                rulesList.appendChild(ruleDiv);
            });
        } else {
            rulesList.innerHTML = '<p class="placeholder-text">No suspicious indicators found.</p>';
        }

        // 4. Components
        urlComponents.innerHTML = '';
        const comps = data.components;
        if (comps) {
            addComponentItem('Protocol', comps.protocol);
            addComponentItem('Domain', comps.domain);
            addComponentItem('Path', comps.path);
        }

        resultsDiv.classList.remove('hidden');
    }

    function addComponentItem(label, value) {
        if (!value) return;
        const li = document.createElement('li');
        li.innerHTML = `<strong>${label}</strong> ${value}`;
        urlComponents.appendChild(li);
    }

    function showError(msg) {
        if (msg) {
            errorDiv.textContent = msg;
            errorDiv.classList.remove('hidden');
        } else {
            errorDiv.classList.add('hidden');
        }
    }
});
