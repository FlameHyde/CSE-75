// script.js
// UI handlers for DNS Filtering + Threat Intel demo

// Basic domain check
document.getElementById('checkBtn').addEventListener('click', function () {
    const domain = document.getElementById('domainInput').value.trim();
    if (!domain) {
        document.getElementById('resultArea').innerHTML = '<div class="alert alert-warning">Please enter a domain name.</div>';
        return;
    }
    fetch('/check', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({domain})
    }).then(r => r.json()).then(data => {
        if (data.error) {
            document.getElementById('resultArea').innerHTML = `<div class="alert alert-danger">${data.error}</div>`;
            return;
        }
        renderResult(data);
    }).catch(err => {
        console.error(err);
        document.getElementById('resultArea').innerHTML = '<div class="alert alert-danger">Error checking domain.</div>';
    });
});

function renderResult(data) {
    let color = data.status === 'Safe' ? 'success' : 'danger';
    let evidenceHtml = `
        <ul class="list-group list-group-sm mt-2">
            <li class="list-group-item"><strong>Reputation:</strong> ${data.reputation}</li>
            <li class="list-group-item"><strong>Resolves:</strong> ${data.evidence.resolves} ${data.evidence.resolved_ips ? '(' + data.evidence.resolved_ips.join(', ') + ')' : ''}</li>
            <li class="list-group-item"><strong>Entropy:</strong> ${data.evidence.entropy}</li>
            <li class="list-group-item"><strong>Length:</strong> ${data.evidence.length}</li>
            <li class="list-group-item"><strong>Heuristic flag:</strong> ${data.evidence.heuristic_suspicious}</li>
            <li class="list-group-item"><strong>Blacklist hit:</strong> ${data.evidence.blacklist_hit}</li>
            <li class="list-group-item"><strong>Allowlist hit:</strong> ${data.evidence.allowlist_hit}</li>
            <li class="list-group-item"><strong>TLD:</strong> ${data.evidence.tld}</li>
            <li class="list-group-item"><strong>Brand similarity:</strong> ${data.evidence.brand_similarity}</li>
        </ul>
    `;
    document.getElementById('resultArea').innerHTML = `
        <div class="alert alert-${color}">Domain <strong>${data.domain}</strong> is <strong>${data.status}</strong>.</div>
        <div class="card p-2">${evidenceHtml}
            <div class="mt-2 text-end">
                <button id="detailsBtn" class="btn btn-outline-secondary btn-sm me-2">Details</button>
                <button id="markSafeBtn" class="btn btn-outline-success btn-sm me-2">Mark Safe</button>
                <button id="markMalBtn" class="btn btn-outline-danger btn-sm">Mark Malicious</button>
            </div>
        </div>
    `;
    document.getElementById('totalChecked').textContent = data.stats.total;
    document.getElementById('safeCount').textContent = data.stats.safe;
    document.getElementById('maliciousCount').textContent = data.stats.malicious;
    updateChart(parseInt(document.getElementById('safeCount').textContent), parseInt(document.getElementById('maliciousCount').textContent));

    document.getElementById('detailsBtn').addEventListener('click', function() {
        showEvidence(data.evidence);
    });
    document.getElementById('markSafeBtn').addEventListener('click', function() { sendFeedback(data.domain, 'safe'); });
    document.getElementById('markMalBtn').addEventListener('click', function() { sendFeedback(data.domain, 'malicious'); });
}

// send feedback
function sendFeedback(domain, label) {
    fetch('/feedback', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({domain, label})
    }).then(r => r.json()).then(resp => {
        if (resp.error) {
            alert('Feedback error: ' + resp.error);
            return;
        }
        document.getElementById('totalChecked').textContent = resp.stats.total;
        document.getElementById('safeCount').textContent = resp.stats.safe;
        document.getElementById('maliciousCount').textContent = resp.stats.malicious;
        updateChart(parseInt(document.getElementById('safeCount').textContent), parseInt(document.getElementById('maliciousCount').textContent));

        const msg = document.createElement('div');
        msg.className = 'alert alert-info mt-2';
        msg.textContent = 'Feedback stored for ' + domain + ' as ' + label;
        const area = document.getElementById('resultArea');
        area.insertBefore(msg, area.firstChild);
        setTimeout(()=> msg.remove(), 3500);
    }).catch(e => {
        console.error(e);
        alert('Could not send feedback');
    });
}

// load history
function loadHistory() {
    fetch('/history').then(r => r.json()).then(data => {
        const h = data.history || [];
        const table = document.getElementById('historyTableBody');
        if (!table) return;
        table.innerHTML = '';
        h.slice().reverse().slice(0, 10).forEach(entry => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td>${new Date((entry.evidence && entry.evidence.timestamp || Date.now())*1000).toLocaleString()}</td>
                <td>${entry.domain}</td>
                <td>${entry.status}</td>
                <td>${entry.reputation}</td>
            `;
            table.appendChild(tr);
        });
    });
}

// allowlist UI
document.getElementById('addAllowBtn').addEventListener('click', function() {
    const domain = document.getElementById('allowInput').value.trim();
    if (!domain) return alert('Enter domain to add to allowlist');
    fetch('/allowlist', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ domain })
    }).then(r => r.json()).then(resp => {
        if (resp.result === 'added') {
            loadAllowlist();
            document.getElementById('allowInput').value = '';
        } else {
            alert('Could not add allowlist');
        }
    });
});
document.getElementById('refreshAllowBtn').addEventListener('click', loadAllowlist);

function loadAllowlist() {
    fetch('/allowlist').then(r => r.json()).then(resp => {
        const ul = document.getElementById('allowList');
        ul.innerHTML = '';
        (resp.allowlist || []).forEach(d => {
            const li = document.createElement('li');
            li.className = 'list-group-item d-flex justify-content-between align-items-center py-1';
            li.innerHTML = `<span>${d}</span><button data-domain="${d}" class="btn btn-sm btn-outline-danger removeAllowBtn">Remove</button>`;
            ul.appendChild(li);
        });
        document.querySelectorAll('.removeAllowBtn').forEach(btn => {
            btn.addEventListener('click', function() {
                const domain = this.getAttribute('data-domain');
                fetch('/allowlist', {
                    method: 'DELETE',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ domain })
                }).then(r => r.json()).then(loadAllowlist);
            });
        });
    });
}

// bulk check handler
document.getElementById('bulkCheckBtn').addEventListener('click', function(){
    const f = document.getElementById('bulkFile').files[0];
    if (!f) return alert('Choose a file first');
    const fd = new FormData();
    fd.append('file', f);
    // Requires API token (use prompt to collect)
    const token = prompt('Enter API token for bulk check (X-API-Token):');
    if (!token) return alert('API token required');
    fetch('/check_bulk', { method: 'POST', body: fd, headers: {'X-API-Token': token} })
    .then(r => r.json()).then(resp => {
        if (resp.error) return alert(resp.error);
        const btn = document.getElementById('bulkDownload');
        let csv = 'domain,status,reputation\n';
        resp.results.forEach(r => csv += `${r.domain},${r.status},${r.reputation}\n`);
        const blob = new Blob([csv], { type: 'text/csv' });
        const url = URL.createObjectURL(blob);
        btn.href = url;
        btn.download = 'bulk_results.csv';
        btn.style.display = 'inline-block';
        alert('Bulk check complete: ' + resp.count + ' domains. Click Download to get CSV.');
    }).catch(e => {
        console.error(e);
        alert('Bulk check failed');
    });
});

// fetch feed modal
document.getElementById('doFetchFeed').addEventListener('click', function(){
    const url = document.getElementById('feedUrl').value.trim();
    const type = document.getElementById('feedType').value;
    const token = document.getElementById('feedToken').value.trim();
    if (!url || !token) return alert('Feed URL and API token required');
    fetch('/fetch_feed', {
        method: 'POST',
        headers: {'Content-Type': 'application/json', 'X-API-Token': token},
        body: JSON.stringify({ url, type })
    }).then(r => r.json()).then(resp => {
        if (resp.error) return alert('Feed error: ' + resp.error);
        alert(`Feed fetched. Added: ${resp.added}`);
        var modal = bootstrap.Modal.getInstance(document.getElementById('fetchFeedModal'));
        modal.hide();
    }).catch(e => {
        console.error(e);
        alert('Could not fetch feed');
    });
});

// permutations button
document.getElementById('permsBtn').addEventListener('click', function(){
    const domain = document.getElementById('domainInput').value.trim();
    if (!domain) return alert('Enter a domain first');
    fetch('/permutations?domain=' + encodeURIComponent(domain)).then(r => r.json()).then(resp => {
        if (resp.error) return alert(resp.error);
        let list = resp.permutations;
        let html = `<div class="card p-2 mt-2"><strong>Permutations (${list.length})</strong><ul class="list-group list-group-sm mt-2">`;
        list.slice(0,50).forEach(l => html += `<li class="list-group-item">${l}</li>`);
        html += '</ul></div>';
        const area = document.getElementById('resultArea');
        area.insertAdjacentHTML('afterbegin', html);
    });
});

// export training button
document.getElementById('exportTrainingBtn').addEventListener('click', function(){
    const token = prompt('Enter API token to export training CSV:');
    if (!token) return;
    window.location = '/export_training?api_token=' + encodeURIComponent(token);
});

// Evidence modal functions
function showEvidence(evidenceObj) {
    document.getElementById('evidenceJson').textContent = JSON.stringify(evidenceObj, null, 2);
    const ev = new bootstrap.Modal(document.getElementById('evidenceModal'));
    ev.show();
}
document.getElementById('copyEvidence').addEventListener('click', function(){
    navigator.clipboard.writeText(document.getElementById('evidenceJson').textContent).then(()=> {
        alert('Copied');
    }, ()=> alert('Copy failed'));
});

// Chart
let statusChart;
function initChart() {
    const ctx = document.getElementById('statusChart').getContext('2d');
    statusChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Safe','Malicious'],
            datasets: [{ data: [parseInt(document.getElementById('safeCount').textContent||0), parseInt(document.getElementById('maliciousCount').textContent||0)] }]
        },
        options: { responsive: true, maintainAspectRatio: false, plugins: {legend: {position:'bottom'}} }
    });
}
function updateChart(safe, mal) {
    if (!statusChart) initChart();
    statusChart.data.datasets[0].data = [safe, mal];
    statusChart.update();
}

window.addEventListener('load', function(){
    loadHistory();
    loadAllowlist();
    initChart();
});
