import sqlite3
import hashlib
from fastapi import FastAPI
from fastapi.responses import HTMLResponse

app = FastAPI(title="Campus Breach Sentinel Enterprise")

def hash_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()

def find_email_breaches(email: str):
    conn = sqlite3.connect("breaches.db")
    cursor = conn.cursor()
    cursor.execute(
        "SELECT breach_name, breach_date, leaked_info, risk_level FROM breaches WHERE LOWER(email) = LOWER(?)",
        (email.strip(),)
    )
    rows = cursor.fetchall()
    conn.close()
    return [{"name": r[0], "date": r[1], "leaked": r[2], "risk": r[3]} for r in rows]

def find_password_breach(password: str):
    pwd_hash = hash_text(password.strip())
    conn = sqlite3.connect("breaches.db")
    cursor = conn.cursor()
    cursor.execute("SELECT times_seen FROM leaked_passwords WHERE password_hash = ?", (pwd_hash,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return {"is_leaked": True, "times_seen": row[0], "sha256": pwd_hash}
    return {"is_leaked": False, "times_seen": 0, "sha256": pwd_hash}

def find_domain_breaches(domain: str):
    domain = domain.strip().lower().replace("@", "")
    conn = sqlite3.connect("breaches.db")
    cursor = conn.cursor()
    cursor.execute(
        "SELECT email, breach_name, breach_date, leaked_info, risk_level FROM breaches WHERE LOWER(email) LIKE ?",
        (f"%@{domain}",)
    )
    rows = cursor.fetchall()
    conn.close()
    return [
        {"email": r[0], "name": r[1], "date": r[2], "leaked": r[3], "risk": r[4]}
        for r in rows
    ]

def get_platform_metrics():
    conn = sqlite3.connect("breaches.db")
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*), COUNT(DISTINCT email) FROM breaches")
    total_records, distinct_emails = cursor.fetchone()
    cursor.execute("SELECT COUNT(*) FROM leaked_passwords")
    total_passwords = cursor.fetchone()[0]
    conn.close()
    return {
        "total_records": total_records or 0,
        "distinct_targets": distinct_emails or 0,
        "indexed_passwords": total_passwords or 0
    }

# --- API Endpoints ---

@app.get("/api/metrics")
def get_metrics():
    return get_platform_metrics()

@app.get("/api/check-email")
def check_email(email: str = ""):
    if not email:
        return {"error": "Please provide an email address."}
    records = find_email_breaches(email)
    return {"email": email, "is_breached": len(records) > 0, "total_breaches": len(records), "breaches": records}

@app.get("/api/check-password")
def check_password(password: str = ""):
    if not password:
        return {"error": "Please provide a password."}
    return find_password_breach(password)

@app.get("/api/check-domain")
def check_domain(domain: str = ""):
    if not domain:
        return {"error": "Please provide a domain."}
    records = find_domain_breaches(domain)
    return {"domain": domain, "total_found": len(records), "results": records}

# --- Professional Frontend ---

@app.get("/", response_class=HTMLResponse)
def home():
    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Campus Breach Sentinel | Threat Intelligence</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    </head>
    <body class="bg-slate-950 text-slate-100 min-h-screen flex flex-col font-sans selection:bg-cyan-500 selection:text-black">
        
        <!-- Navbar -->
        <header class="border-b border-slate-800 bg-slate-900/60 backdrop-blur-md sticky top-0 z-50">
            <div class="max-w-5xl mx-auto px-6 py-4 flex items-center justify-between">
                <div class="flex items-center space-x-3">
                    <div class="w-9 h-9 bg-cyan-500/20 border border-cyan-400 text-cyan-400 rounded-lg flex items-center justify-center text-lg font-bold">
                        <i class="fa-solid fa-shield-halved"></i>
                    </div>
                    <div>
                        <span class="font-extrabold text-lg tracking-wide text-white">SENTINEL<span class="text-cyan-400">.IO</span></span>
                        <span class="text-xs ml-2 px-2 py-0.5 rounded-full bg-cyan-950 text-cyan-400 border border-cyan-800">Campus SecOps</span>
                    </div>
                </div>
                <div class="flex items-center space-x-4 text-xs font-medium text-slate-400">
                    <span class="flex items-center gap-1.5"><span class="h-2 w-2 rounded-full bg-emerald-400 animate-pulse"></span> DB Synchronized</span>
                    <a href="/docs" target="_blank" class="hover:text-cyan-400 transition"><i class="fa-solid fa-code"></i> API Docs</a>
                </div>
            </div>
        </header>

        <!-- Main Content -->
        <main class="flex-1 max-w-5xl w-full mx-auto px-6 py-8">
            
            <!-- Hero Title -->
            <div class="text-center mb-8">
                <h1 class="text-3xl sm:text-4xl font-black tracking-tight text-white mb-2">
                    Institutional Breach & Credential Intelligence
                </h1>
                <p class="text-slate-400 max-w-2xl mx-auto text-sm">
                    Detect exposed university assets, verify password entropy across known leaks, and enforce zero-trust identity safeguards.
                </p>
            </div>

            <!-- Live Metrics Counter -->
            <div class="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-8">
                <div class="bg-slate-900/80 border border-slate-800 rounded-xl p-4 flex items-center gap-4">
                    <div class="p-3 bg-cyan-500/10 text-cyan-400 rounded-lg text-xl"><i class="fa-solid fa-database"></i></div>
                    <div>
                        <div class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Breach Events</div>
                        <div id="metricBreaches" class="text-xl font-bold text-white">Loading...</div>
                    </div>
                </div>
                <div class="bg-slate-900/80 border border-slate-800 rounded-xl p-4 flex items-center gap-4">
                    <div class="p-3 bg-indigo-500/10 text-indigo-400 rounded-lg text-xl"><i class="fa-solid fa-key"></i></div>
                    <div>
                        <div class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Indexed Passwords</div>
                        <div id="metricPasswords" class="text-xl font-bold text-white">Loading...</div>
                    </div>
                </div>
                <div class="bg-slate-900/80 border border-slate-800 rounded-xl p-4 flex items-center gap-4">
                    <div class="p-3 bg-amber-500/10 text-amber-400 rounded-lg text-xl"><i class="fa-solid fa-user-shield"></i></div>
                    <div>
                        <div class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Monitored Targets</div>
                        <div id="metricTargets" class="text-xl font-bold text-white">Loading...</div>
                    </div>
                </div>
            </div>

            <!-- Dashboard Card -->
            <div class="bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl overflow-hidden mb-8">
                <!-- Navigation Tabs -->
                <div class="grid grid-cols-3 border-b border-slate-800 bg-slate-950/40 text-sm">
                    <button id="emailTabBtn" onclick="switchTab('email')" class="py-3.5 font-semibold text-cyan-400 border-b-2 border-cyan-400 flex items-center justify-center gap-2 transition">
                        <i class="fa-regular fa-envelope"></i> Email Audit
                    </button>
                    <button id="passwordTabBtn" onclick="switchTab('password')" class="py-3.5 font-semibold text-slate-400 border-b-2 border-transparent hover:text-slate-200 flex items-center justify-center gap-2 transition">
                        <i class="fa-solid fa-fingerprint"></i> Password Hash
                    </button>
                    <button id="domainTabBtn" onclick="switchTab('domain')" class="py-3.5 font-semibold text-slate-400 border-b-2 border-transparent hover:text-slate-200 flex items-center justify-center gap-2 transition">
                        <i class="fa-solid fa-network-wired"></i> Domain Radar
                    </button>
                </div>

                <div class="p-6">
                    <!-- SECTION 1: Email -->
                    <div id="emailSection">
                        <label class="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2">Target Email Identifier</label>
                        <div class="flex gap-2">
                            <input id="emailInput" type="email" placeholder="e.g. student@college.edu" 
                                   class="flex-1 px-4 py-3 bg-slate-800 border border-slate-700 rounded-xl text-white placeholder-slate-500 focus:outline-none focus:border-cyan-400 transition" />
                            <button onclick="searchEmail()" class="bg-cyan-500 hover:bg-cyan-400 font-bold text-slate-950 px-6 py-3 rounded-xl transition shadow-lg shadow-cyan-500/20">
                                Scan
                            </button>
                        </div>
                    </div>

                    <!-- SECTION 2: Password -->
                    <div id="passwordSection" class="hidden">
                        <label class="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2">Check Plaintext Exposure</label>
                        <div class="flex gap-2">
                            <input id="passwordInput" type="password" oninput="evalPasswordStrength(this.value)" placeholder="Enter test password (e.g. password123)" 
                                   class="flex-1 px-4 py-3 bg-slate-800 border border-slate-700 rounded-xl text-white placeholder-slate-500 focus:outline-none focus:border-cyan-400 transition" />
                            <button onclick="searchPassword()" class="bg-cyan-500 hover:bg-cyan-400 font-bold text-slate-950 px-6 py-3 rounded-xl transition shadow-lg shadow-cyan-500/20">
                                Verify
                            </button>
                        </div>
                        
                        <!-- Password Strength Meter -->
                        <div class="mt-3">
                            <div class="flex justify-between items-center text-xs mb-1">
                                <span class="text-slate-400">Entropy Strength:</span>
                                <span id="strengthLabel" class="font-bold text-slate-500">None</span>
                            </div>
                            <div class="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
                                <div id="strengthBar" class="h-full w-0 bg-slate-600 transition-all duration-300"></div>
                            </div>
                        </div>
                    </div>

                    <!-- SECTION 3: Domain -->
                    <div id="domainSection" class="hidden">
                        <label class="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2">Institutional Domain Identifier</label>
                        <div class="flex gap-2">
                            <input id="domainInput" type="text" placeholder="e.g. college.edu" 
                                   class="flex-1 px-4 py-3 bg-slate-800 border border-slate-700 rounded-xl text-white placeholder-slate-500 focus:outline-none focus:border-cyan-400 transition" />
                            <button onclick="searchDomain()" class="bg-cyan-500 hover:bg-cyan-400 font-bold text-slate-950 px-6 py-3 rounded-xl transition shadow-lg shadow-cyan-500/20">
                                Audit Domain
                            </button>
                        </div>
                    </div>

                    <!-- Results Output Area -->
                    <div id="results" class="hidden mt-6"></div>
                </div>
            </div>
        </main>

        <script>
            let currentEmailResults = null;
            let currentDomainResults = null;

            // Load live platform statistics
            async function loadMetrics() {
                try {
                    const res = await fetch('/api/metrics');
                    const data = await res.json();
                    document.getElementById('metricBreaches').textContent = data.total_records.toLocaleString();
                    document.getElementById('metricPasswords').textContent = data.indexed_passwords.toLocaleString();
                    document.getElementById('metricTargets').textContent = data.distinct_targets.toLocaleString();
                } catch(e) {}
            }
            loadMetrics();

            function switchTab(tab) {
                const tabs = ['email', 'password', 'domain'];
                tabs.forEach(t => {
                    const section = document.getElementById(t + 'Section');
                    const btn = document.getElementById(t + 'TabBtn');
                    if (t === tab) {
                        section.classList.remove('hidden');
                        btn.className = 'py-3.5 font-semibold text-cyan-400 border-b-2 border-cyan-400 flex items-center justify-center gap-2 transition';
                    } else {
                        section.classList.add('hidden');
                        btn.className = 'py-3.5 font-semibold text-slate-400 border-b-2 border-transparent hover:text-slate-200 flex items-center justify-center gap-2 transition';
                    }
                });
                document.getElementById('results').classList.add('hidden');
            }

            function evalPasswordStrength(pwd) {
                const bar = document.getElementById('strengthBar');
                const label = document.getElementById('strengthLabel');
                let score = 0;

                if (!pwd) {
                    bar.style.width = '0%';
                    label.textContent = 'None';
                    label.className = 'font-bold text-slate-500';
                    return;
                }

                if (pwd.length >= 8) score++;
                if (pwd.length >= 12) score++;
                if (/[A-Z]/.test(pwd)) score++;
                if (/[0-9]/.test(pwd)) score++;
                if (/[^A-Za-z0-9]/.test(pwd)) score++;

                if (score <= 2) {
                    bar.style.width = '25%';
                    bar.className = 'h-full bg-rose-500';
                    label.textContent = 'Weak';
                    label.className = 'font-bold text-rose-400';
                } else if (score <= 4) {
                    bar.style.width = '65%';
                    bar.className = 'h-full bg-amber-500';
                    label.textContent = 'Moderate';
                    label.className = 'font-bold text-amber-400';
                } else {
                    bar.style.width = '100%';
                    bar.className = 'h-full bg-emerald-500';
                    label.textContent = 'Strong (High Entropy)';
                    label.className = 'font-bold text-emerald-400';
                }
            }

            function downloadCSV(filename, csvContent) {
                const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
                const link = document.createElement("a");
                link.href = URL.createObjectURL(blob);
                link.download = filename;
                document.body.appendChild(link);
                link.click();
                document.body.removeChild(link);
            }

            function exportEmailCSV() {
                if (!currentEmailResults || !currentEmailResults.breaches.length) return;
                let csv = "Target Email,Breach Source,Incident Date,Compromised Vectors,Threat Level\\n";
                currentEmailResults.breaches.forEach(b => {
                    csv += `"${currentEmailResults.email}","${b.name}","${b.date}","${b.leaked}","${b.risk}"\\n`;
                });
                downloadCSV(`threat_intel_${currentEmailResults.email}.csv`, csv);
            }

            function exportDomainCSV() {
                if (!currentDomainResults || !currentDomainResults.results.length) return;
                let csv = "Domain Perimeter,Account Handle,Breach Name,Incident Date,Compromised Vectors,Threat Level\\n";
                currentDomainResults.results.forEach(r => {
                    csv += `"${currentDomainResults.domain}","${r.email}","${r.name}","${r.date}","${r.leaked}","${r.risk}"\\n`;
                });
                downloadCSV(`domain_audit_${currentDomainResults.domain}.csv`, csv);
            }

            async function searchEmail() {
                const email = document.getElementById('emailInput').value.trim();
                const out = document.getElementById('results');
                if (!email) return alert("Please enter an email address.");

                out.classList.remove('hidden');
                out.innerHTML = '<div class="text-center py-6 text-slate-400"><i class="fa-solid fa-spinner fa-spin text-2xl text-cyan-400"></i><p class="mt-2 text-xs">Querying threat registry...</p></div>';

                const res = await fetch('/api/check-email?email=' + encodeURIComponent(email));
                const data = await res.json();
                currentEmailResults = data;

                if (!data.is_breached) {
                    out.innerHTML = `
                        <div class="p-6 bg-emerald-950/40 border border-emerald-500/40 rounded-xl text-center">
                            <i class="fa-regular fa-circle-check text-emerald-400 text-3xl mb-2"></i>
                            <h3 class="text-base font-bold text-emerald-300">Clean Identity Perimeter</h3>
                            <p class="text-xs text-slate-400 mt-1">No exposure records detected for <span class="font-mono text-emerald-200">${data.email}</span>.</p>
                        </div>
                    `;
                    return;
                }

                let cards = data.breaches.map(b => `
                    <div class="p-4 bg-slate-950/60 border border-slate-800 rounded-lg">
                        <div class="flex justify-between items-center mb-1">
                            <span class="font-bold text-slate-100 text-sm">${b.name}</span>
                            <span class="text-xs px-2 py-0.5 rounded font-bold ${b.risk === 'High' ? 'bg-rose-950 text-rose-400 border border-rose-800' : 'bg-amber-950 text-amber-400 border border-amber-800'}">${b.risk} Risk</span>
                        </div>
                        <div class="text-xs text-slate-500 mb-2">Incident Date: ${b.date}</div>
                        <div class="text-xs text-slate-300 bg-slate-900 p-2 rounded border border-slate-800/80">
                            <span class="text-rose-400 font-semibold">Exposed Vectors:</span> ${b.leaked}
                        </div>
                    </div>
                `).join('');

                out.innerHTML = `
                    <div class="p-5 bg-rose-950/30 border border-rose-500/40 rounded-xl">
                        <div class="flex items-center justify-between mb-4">
                            <div>
                                <h3 class="font-bold text-rose-300 text-sm">Compromise Detected (${data.total_breaches} Incidents)</h3>
                                <p class="text-xs text-slate-400">Account credentials actively circulate in underground dumps.</p>
                            </div>
                            <button onclick="exportEmailCSV()" class="bg-cyan-500 hover:bg-cyan-400 text-slate-950 text-xs font-bold py-1.5 px-3 rounded-lg flex items-center gap-1.5 transition">
                                <i class="fa-solid fa-download"></i> CSV Report
                            </button>
                        </div>
                        <div class="space-y-2 mb-4">${cards}</div>
                        <!-- Remediation Plan -->
                        <div class="p-3 bg-slate-900 border border-slate-800 rounded-lg text-xs">
                            <div class="font-bold text-slate-200 mb-1 flex items-center gap-1.5"><i class="fa-solid fa-list-check text-cyan-400"></i> Immediate Action Plan</div>
                            <ul class="list-disc pl-5 text-slate-400 space-y-1">
                                <li>Rotate account credentials immediately.</li>
                                <li>Enforce hardware-bound Multi-Factor Authentication (MFA).</li>
                                <li>Invalidate active OAuth sessions on connected third-party apps.</li>
                            </ul>
                        </div>
                    </div>
                `;
            }

            async function searchPassword() {
                const pwd = document.getElementById('passwordInput').value;
                const out = document.getElementById('results');
                if (!pwd) return alert("Please enter a password string.");

                out.classList.remove('hidden');
                out.innerHTML = '<div class="text-center py-6 text-slate-400"><i class="fa-solid fa-spinner fa-spin text-2xl text-cyan-400"></i><p class="mt-2 text-xs">Generating hash & querying signatures...</p></div>';

                const res = await fetch('/api/check-password?password=' + encodeURIComponent(pwd));
                const data = await res.json();

                if (!data.is_leaked) {
                    out.innerHTML = `
                        <div class="p-6 bg-emerald-950/40 border border-emerald-500/40 rounded-xl text-center">
                            <i class="fa-regular fa-circle-check text-emerald-400 text-3xl mb-2"></i>
                            <h3 class="text-base font-bold text-emerald-300">Password Signature Not Found</h3>
                            <p class="text-xs text-slate-400 mt-1">This specific SHA-256 signature does not exist in known breach databases.</p>
                            <div class="mt-3 font-mono text-[10px] text-slate-500 break-all bg-slate-900 p-2 rounded border border-slate-800">
                                SHA-256: ${data.sha256}
                            </div>
                        </div>
                    `;
                } else {
                    out.innerHTML = `
                        <div class="p-6 bg-rose-950/40 border border-rose-500/40 rounded-xl text-center">
                            <i class="fa-solid fa-triangle-exclamation text-rose-400 text-3xl mb-2"></i>
                            <h3 class="text-base font-bold text-rose-300">Compromised Password Hash</h3>
                            <p class="text-xs text-slate-300 mt-1">Detected across <strong class="text-rose-400 font-bold">${data.times_seen.toLocaleString()}</strong> public data dumps.</p>
                            <div class="mt-3 font-mono text-[10px] text-slate-500 break-all bg-slate-900 p-2 rounded border border-slate-800">
                                SHA-256: ${data.sha256}
                            </div>
                        </div>
                    `;
                }
            }

            async function searchDomain() {
                const domain = document.getElementById('domainInput').value.trim();
                const out = document.getElementById('results');
                if (!domain) return alert("Please enter a domain handle.");

                out.classList.remove('hidden');
                out.innerHTML = '<div class="text-center py-6 text-slate-400"><i class="fa-solid fa-spinner fa-spin text-2xl text-cyan-400"></i><p class="mt-2 text-xs">Auditing institutional domain records...</p></div>';

                const res = await fetch('/api/check-domain?domain=' + encodeURIComponent(domain));
                const data = await res.json();
                currentDomainResults = data;

                if (data.total_found === 0) {
                    out.innerHTML = `
                        <div class="p-6 bg-emerald-950/40 border border-emerald-500/40 rounded-xl text-center">
                            <i class="fa-regular fa-circle-check text-emerald-400 text-3xl mb-2"></i>
                            <h3 class="text-base font-bold text-emerald-300">Clean Institutional Domain</h3>
                            <p class="text-xs text-slate-400 mt-1">Zero leaks detected matching <span class="font-mono text-emerald-200">@${data.domain}</span>.</p>
                        </div>
                    `;
                } else {
                    let rows = data.results.map(r => `
                        <tr class="border-b border-slate-800 text-xs">
                            <td class="py-2.5 px-3 font-mono text-cyan-300">${r.email}</td>
                            <td class="py-2.5 px-3 text-slate-200">${r.name}</td>
                            <td class="py-2.5 px-3 text-slate-400">${r.leaked}</td>
                            <td class="py-2.5 px-3"><span class="px-2 py-0.5 text-[10px] rounded font-bold ${r.risk === 'High' ? 'bg-rose-950 text-rose-400 border border-rose-800' : 'bg-amber-950 text-amber-400 border border-amber-800'}">${r.risk}</span></td>
                        </tr>
                    `).join('');

                    out.innerHTML = `
                        <div class="p-5 bg-slate-900 border border-amber-500/40 rounded-xl">
                            <div class="flex items-center justify-between mb-4">
                                <div>
                                    <h3 class="font-bold text-amber-300 text-sm">Domain Incident Audit: @${data.domain}</h3>
                                    <p class="text-xs text-slate-400">${data.total_found} institutional accounts exposed.</p>
                                </div>
                                <button onclick="exportDomainCSV()" class="bg-cyan-500 hover:bg-cyan-400 text-slate-950 text-xs font-bold py-1.5 px-3 rounded-lg flex items-center gap-1.5 transition">
                                    <i class="fa-solid fa-download"></i> CSV Report
                                </button>
                            </div>
                            <div class="overflow-x-auto rounded-lg border border-slate-800">
                                <table class="w-full text-left">
                                    <thead class="bg-slate-950/80 text-slate-400 text-xs border-b border-slate-800">
                                        <tr>
                                            <th class="py-2 px-3">Identity</th>
                                            <th class="py-2 px-3">Breach Vector</th>
                                            <th class="py-2 px-3">Compromised Data</th>
                                            <th class="py-2 px-3">Risk Level</th>
                                        </tr>
                                    </thead>
                                    <tbody class="divide-y divide-slate-800 bg-slate-900/50">${rows}</tbody>
                                </table>
                            </div>
                        </div>
                    `;
                }
            }
        </script>
    </body>
    </html>
    """
