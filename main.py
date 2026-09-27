import sqlite3
import hashlib
from fastapi import FastAPI
from fastapi.responses import HTMLResponse

app = FastAPI(title="Campus Breach Sentinel")

def hash_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()

# 1. Search email
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

# 2. Search password hash
def find_password_breach(password: str):
    pwd_hash = hash_text(password.strip())
    conn = sqlite3.connect("breaches.db")
    cursor = conn.cursor()
    cursor.execute("SELECT times_seen FROM leaked_passwords WHERE password_hash = ?", (pwd_hash,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return {"is_leaked": True, "times_seen": row[0]}
    return {"is_leaked": False, "times_seen": 0}

# 3. Search by Domain (e.g. college.edu)
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


# --- API Endpoints ---

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


# --- Frontend Dashboard ---

@app.get("/", response_class=HTMLResponse)
def home():
    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Campus Breach Sentinel</title>
        <script src="https://cdn.tailwindcss.com"></script>
    </head>
    <body class="bg-gray-900 text-gray-100 min-h-screen flex items-center justify-center p-4">
        
        <div class="max-w-xl w-full bg-gray-800 rounded-2xl shadow-xl p-8 border border-gray-700">
            <!-- Header -->
            <div class="text-center mb-6">
                <h1 class="text-3xl font-extrabold text-cyan-400">Campus Breach Sentinel</h1>
                <p class="text-gray-400 text-sm mt-1">Institutional cybersecurity intelligence & breach monitoring.</p>
            </div>

            <!-- Tab Switcher -->
            <div class="flex border-b border-gray-700 mb-6 text-sm">
                <button id="emailTabBtn" onclick="switchTab('email')" class="flex-1 py-2 font-bold text-cyan-400 border-b-2 border-cyan-400">
                    📧 Email
                </button>
                <button id="passwordTabBtn" onclick="switchTab('password')" class="flex-1 py-2 font-bold text-gray-400 border-b-2 border-transparent hover:text-gray-200">
                    🔑 Password
                </button>
                <button id="domainTabBtn" onclick="switchTab('domain')" class="flex-1 py-2 font-bold text-gray-400 border-b-2 border-transparent hover:text-gray-200">
                    🏫 Campus Domain
                </button>
            </div>

            <!-- TAB 1: Email Form -->
            <div id="emailSection">
                <div class="flex gap-2 mb-4">
                    <input id="emailInput" type="email" placeholder="Enter email (e.g. student@college.edu)" 
                           class="flex-1 px-4 py-3 rounded-lg bg-gray-700 text-white placeholder-gray-400 border border-gray-600 focus:outline-none focus:border-cyan-400" />
                    <button onclick="searchEmail()" class="bg-cyan-500 hover:bg-cyan-600 font-semibold text-gray-950 px-5 py-3 rounded-lg transition">
                        Check
                    </button>
                </div>
            </div>

            <!-- TAB 2: Password Form -->
            <div id="passwordSection" class="hidden">
                <div class="flex gap-2 mb-4">
                    <input id="passwordInput" type="text" placeholder="Enter password (e.g. password123)" 
                           class="flex-1 px-4 py-3 rounded-lg bg-gray-700 text-white placeholder-gray-400 border border-gray-600 focus:outline-none focus:border-cyan-400" />
                    <button onclick="searchPassword()" class="bg-cyan-500 hover:bg-cyan-600 font-semibold text-gray-950 px-5 py-3 rounded-lg transition">
                        Check
                    </button>
                </div>
            </div>

            <!-- TAB 3: Domain Form -->
            <div id="domainSection" class="hidden">
                <div class="flex gap-2 mb-4">
                    <input id="domainInput" type="text" placeholder="Enter domain (e.g. college.edu)" 
                           class="flex-1 px-4 py-3 rounded-lg bg-gray-700 text-white placeholder-gray-400 border border-gray-600 focus:outline-none focus:border-cyan-400" />
                    <button onclick="searchDomain()" class="bg-cyan-500 hover:bg-cyan-600 font-semibold text-gray-950 px-5 py-3 rounded-lg transition">
                        Audit
                    </button>
                </div>
                <p class="text-xs text-gray-400 text-center mb-2">Scan institution domain to detect exposed faculty & student accounts.</p>
            </div>

            <!-- Output Box -->
            <div id="results" class="hidden"></div>
        </div>

        <script>
            // Store current query results in memory for CSV export
            let currentEmailResults = null;
            let currentDomainResults = null;

            function switchTab(tab) {
                const sections = {
                    email: document.getElementById('emailSection'),
                    password: document.getElementById('passwordSection'),
                    domain: document.getElementById('domainSection')
                };
                const buttons = {
                    email: document.getElementById('emailTabBtn'),
                    password: document.getElementById('passwordTabBtn'),
                    domain: document.getElementById('domainTabBtn')
                };

                document.getElementById('results').classList.add('hidden');

                for (let key in sections) {
                    if (key === tab) {
                        sections[key].classList.remove('hidden');
                        buttons[key].className = 'flex-1 py-2 font-bold text-cyan-400 border-b-2 border-cyan-400';
                    } else {
                        sections[key].classList.add('hidden');
                        buttons[key].className = 'flex-1 py-2 font-bold text-gray-400 border-b-2 border-transparent hover:text-gray-200';
                    }
                }
            }

            // Generic function to trigger browser CSV download
            function downloadCSV(filename, csvContent) {
                const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
                const link = document.createElement("a");
                const url = URL.createObjectURL(blob);
                link.setAttribute("href", url);
                link.setAttribute("download", filename);
                document.body.appendChild(link);
                link.click();
                document.body.removeChild(link);
            }

            // Export email breach results
            function exportEmailCSV() {
                if (!currentEmailResults || !currentEmailResults.breaches.length) return;
                let csv = "Email,Breach Name,Breach Date,Exposed Data,Risk Level\\n";
                currentEmailResults.breaches.forEach(b => {
                    csv += `"${currentEmailResults.email}","${b.name}","${b.date}","${b.leaked}","${b.risk}"\\n`;
                });
                downloadCSV(`breach_report_${currentEmailResults.email}.csv`, csv);
            }

            // Export domain audit report
            function exportDomainCSV() {
                if (!currentDomainResults || !currentDomainResults.results.length) return;
                let csv = "Domain,Compromised Account,Breach Source,Breach Date,Exposed Data,Risk Level\\n";
                currentDomainResults.results.forEach(r => {
                    csv += `"${currentDomainResults.domain}","${r.email}","${r.name}","${r.date}","${r.leaked}","${r.risk}"\\n`;
                });
                downloadCSV(`domain_audit_${currentDomainResults.domain}.csv`, csv);
            }

            async function searchEmail() {
                const email = document.getElementById('emailInput').value.trim();
                const resultsDiv = document.getElementById('results');
                if (!email) return alert("Please enter an email!");

                resultsDiv.classList.remove('hidden');
                resultsDiv.innerHTML = '<p class="text-center text-gray-400 py-4">Searching database...</p>';

                const res = await fetch('/api/check-email?email=' + encodeURIComponent(email));
                const data = await res.json();
                currentEmailResults = data;

                if (!data.is_breached) {
                    resultsDiv.innerHTML = `
                        <div class="p-5 bg-emerald-950/80 border border-emerald-500/50 rounded-xl text-center">
                            <div class="text-3xl mb-1">✅</div>
                            <h3 class="font-bold text-lg text-emerald-300">Safe! No Breaches Found</h3>
                            <p class="text-xs text-gray-300 mt-1">This email does not appear in our records.</p>
                        </div>
                    `;
                    return;
                }

                let breachCards = data.breaches.map(b => `
                    <div class="p-3 bg-gray-900 border border-gray-700 rounded-lg mt-2 text-left">
                        <div class="flex justify-between items-center">
                            <h4 class="font-bold text-cyan-300 text-sm">${b.name}</h4>
                            <span class="text-xs px-2 py-0.5 rounded font-bold bg-rose-900 text-rose-300">${b.risk} Risk</span>
                        </div>
                        <p class="text-xs text-gray-400">Date: ${b.date}</p>
                        <p class="text-xs text-gray-300 mt-1"><strong class="text-red-400">Exposed:</strong> ${b.leaked}</p>
                    </div>
                `).join('');

                resultsDiv.innerHTML = `
                    <div class="p-4 bg-rose-950/70 border border-rose-500/50 rounded-xl">
                        <div class="flex justify-between items-center mb-2">
                            <h3 class="font-bold text-rose-300">⚠️ Found in ${data.total_breaches} leak(s)</h3>
                            <button onclick="exportEmailCSV()" class="bg-cyan-500 hover:bg-cyan-600 text-gray-950 text-xs font-bold py-1 px-3 rounded flex items-center gap-1 transition">
                                📥 Download CSV
                            </button>
                        </div>
                        <div>${breachCards}</div>
                    </div>
                `;
            }

            async function searchPassword() {
                const pwd = document.getElementById('passwordInput').value;
                const resultsDiv = document.getElementById('results');
                if (!pwd) return alert("Please enter a password!");

                resultsDiv.classList.remove('hidden');
                resultsDiv.innerHTML = '<p class="text-center text-gray-400 py-4">Checking password...</p>';

                const res = await fetch('/api/check-password?password=' + encodeURIComponent(pwd));
                const data = await res.json();

                if (!data.is_leaked) {
                    resultsDiv.innerHTML = `
                        <div class="p-5 bg-emerald-950/80 border border-emerald-500/50 rounded-xl text-center">
                            <div class="text-3xl mb-1">✅</div>
                            <h3 class="font-bold text-emerald-300">Password Not Found</h3>
                            <p class="text-xs text-gray-300 mt-1">This password has not been exposed in known breaches.</p>
                        </div>
                    `;
                } else {
                    resultsDiv.innerHTML = `
                        <div class="p-5 bg-rose-950/70 border border-rose-500/50 rounded-xl text-center">
                            <div class="text-3xl mb-1">🚨</div>
                            <h3 class="font-bold text-rose-300">Compromised Password!</h3>
                            <p class="text-sm text-gray-200 mt-2">Appeared in leaks <strong class="text-amber-300">${data.times_seen.toLocaleString()}</strong> times.</p>
                        </div>
                    `;
                }
            }

            async function searchDomain() {
                const domain = document.getElementById('domainInput').value.trim();
                const resultsDiv = document.getElementById('results');
                if (!domain) return alert("Please enter a domain (e.g. college.edu)!");

                resultsDiv.classList.remove('hidden');
                resultsDiv.innerHTML = '<p class="text-center text-gray-400 py-4">Auditing domain records...</p>';

                const res = await fetch('/api/check-domain?domain=' + encodeURIComponent(domain));
                const data = await res.json();
                currentDomainResults = data;

                if (data.total_found === 0) {
                    resultsDiv.innerHTML = `
                        <div class="p-5 bg-emerald-950/80 border border-emerald-500/50 rounded-xl text-center">
                            <div class="text-3xl mb-1">✅</div>
                            <h3 class="font-bold text-emerald-300">No Breached Accounts Found</h3>
                            <p class="text-xs text-gray-300 mt-1">No exposed credentials detected under @${data.domain}.</p>
                        </div>
                    `;
                } else {
                    let rows = data.results.map(r => `
                        <tr class="border-b border-gray-700 text-xs">
                            <td class="py-2 text-cyan-300 font-mono">${r.email}</td>
                            <td class="py-2 text-gray-300">${r.name}</td>
                            <td class="py-2 text-amber-300">${r.leaked}</td>
                        </tr>
                    `).join('');

                    resultsDiv.innerHTML = `
                        <div class="p-4 bg-gray-900 border border-amber-500/50 rounded-xl">
                            <div class="flex justify-between items-center mb-3">
                                <div>
                                    <h3 class="font-bold text-amber-300 text-sm">Domain Audit Report: @${data.domain}</h3>
                                    <span class="text-xs text-gray-400">${data.total_found} Leaked Accounts</span>
                                </div>
                                <button onclick="exportDomainCSV()" class="bg-cyan-500 hover:bg-cyan-600 text-gray-950 text-xs font-bold py-1.5 px-3 rounded flex items-center gap-1 transition">
                                    📥 Download CSV
                                </button>
                            </div>
                            <div class="overflow-x-auto">
                                <table class="w-full text-left">
                                    <thead>
                                        <tr class="border-b border-gray-600 text-xs text-gray-400">
                                            <th class="py-1">Account</th>
                                            <th class="py-1">Breach Source</th>
                                            <th class="py-1">Exposed Data</th>
                                        </tr>
                                    </thead>
                                    <tbody>${rows}</tbody>
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
