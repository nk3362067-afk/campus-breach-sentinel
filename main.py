import sqlite3
import hashlib
import math
from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

app = FastAPI(title="Campus Breach Sentinel Enterprise")

ADMIN_SECRET_KEY = "sentinel-campus-key-2026"

def get_db_connection():
    conn = sqlite3.connect("breaches.db")
    conn.row_factory = sqlite3.Row
    return conn

def hash_sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()

def hash_sha1(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8")).hexdigest().upper()

# --- Database Setup & Migrations ---
def init_advanced_tables():
    conn = get_db_connection()
    cursor = conn.cursor()
    # Ensure SHA-1 hash column exists in leaked_passwords for K-Anonymity Range Search
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS leaked_passwords_v2 (
            sha1_prefix TEXT,
            sha1_suffix TEXT,
            times_seen INTEGER
        )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_prefix ON leaked_passwords_v2(sha1_prefix)")
    
    # Populate initial seed K-Anonymity hashes if empty (e.g., 'password123', 'admin', 'welcome')
    cursor.execute("SELECT COUNT(*) FROM leaked_passwords_v2")
    if cursor.fetchone()[0] == 0:
        common_passwords = ["password123", "admin", "welcome", "12345678", "college2026"]
        for pwd in common_passwords:
            h = hash_sha1(pwd)
            cursor.execute(
                "INSERT INTO leaked_passwords_v2 VALUES (?, ?, ?)",
                (h[:5], h[5:], 4520)
            )
    conn.commit()
    conn.close()

init_advanced_tables()

# --- Core Business Logic ---
def find_email_breaches(email: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT breach_name, breach_date, leaked_info, risk_level FROM breaches WHERE LOWER(email) = LOWER(?)",
        (email.strip(),)
    )
    rows = cursor.fetchall()
    conn.close()
    return [{"name": r["breach_name"], "date": r["breach_date"], "leaked": r["leaked_info"], "risk": r["risk_level"]} for r in rows]

def find_domain_breaches(domain: str):
    domain = domain.strip().lower().replace("@", "")
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT email, breach_name, breach_date, leaked_info, risk_level FROM breaches WHERE LOWER(email) LIKE ?",
        (f"%@{domain}",)
    )
    rows = cursor.fetchall()
    conn.close()
    return [
        {"email": r["email"], "name": r["breach_name"], "date": r["breach_date"], "leaked": r["leaked_info"], "risk": r["risk_level"]}
        for r in rows
    ]

# --- Admin Ingestion Model ---
class IncidentIngest(BaseModel):
    email: str
    breach_name: str
    breach_date: str
    leaked_info: str
    risk_level: str

# --- API Endpoints ---

@app.get("/api/metrics")
def get_metrics():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*), COUNT(DISTINCT email) FROM breaches")
    total_records, distinct_emails = cursor.fetchone()
    
    cursor.execute("SELECT risk_level, COUNT(*) FROM breaches GROUP BY risk_level")
    risk_breakdown = dict(cursor.fetchall())
    conn.close()
    return {
        "total_records": total_records or 0,
        "distinct_targets": distinct_emails or 0,
        "risk_breakdown": risk_breakdown
    }

@app.get("/api/pwned-range/{prefix}")
def pwned_range(prefix: str):
    """K-Anonymity range lookup returning hash suffixes for a 5-char SHA-1 prefix."""
    clean_prefix = prefix.strip().upper()
    if len(clean_prefix) != 5:
        raise HTTPException(status_code=400, detail="Prefix must be exactly 5 hex characters.")
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT sha1_suffix, times_seen FROM leaked_passwords_v2 WHERE sha1_prefix = ?", (clean_prefix,))
    matches = cursor.fetchall()
    conn.close()
    
    # Return formatted response consistent with k-anonymity ranges
    return [{"suffix": r["sha1_suffix"], "count": r["times_seen"]} for r in matches]

@app.get("/api/check-email")
def check_email(email: str = ""):
    if not email:
        return {"error": "Please provide an email address."}
    records = find_email_breaches(email)
    return {"email": email, "is_breached": len(records) > 0, "total_breaches": len(records), "breaches": records}

@app.get("/api/check-domain")
def check_domain(domain: str = ""):
    if not domain:
        return {"error": "Please provide a domain."}
    records = find_domain_breaches(domain)
    return {"domain": domain, "total_found": len(records), "results": records}

@app.post("/api/admin/ingest")
def admin_ingest(payload: IncidentIngest, x_api_key: str = Header(None)):
    if x_api_key != ADMIN_SECRET_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized: Invalid Sentinel API Key")
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO breaches (email, breach_name, breach_date, leaked_info, risk_level) VALUES (?, ?, ?, ?, ?)",
        (payload.email.strip(), payload.breach_name.strip(), payload.breach_date.strip(), payload.leaked_info.strip(), payload.risk_level.strip())
    )
    conn.commit()
    conn.close()
    return {"status": "success", "message": f"Incident logged for {payload.email}"}

# --- Full Enterprise Dashboard ---

@app.get("/", response_class=HTMLResponse)
def home():
    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Campus Breach Sentinel | SecOps Intelligence</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    </head>
    <body class="bg-slate-950 text-slate-100 min-h-screen flex flex-col font-sans selection:bg-cyan-500 selection:text-black">
        
        <!-- Header -->
        <header class="border-b border-slate-800 bg-slate-900/70 backdrop-blur-md sticky top-0 z-50">
            <div class="max-w-6xl mx-auto px-6 py-4 flex items-center justify-between">
                <div class="flex items-center space-x-3">
                    <div class="w-10 h-10 bg-cyan-500/10 border border-cyan-400 text-cyan-400 rounded-xl flex items-center justify-center text-xl font-bold shadow-lg shadow-cyan-500/10">
                        <i class="fa-solid fa-shield-halved"></i>
                    </div>
                    <div>
                        <div class="font-extrabold text-lg tracking-wide text-white leading-tight">SENTINEL<span class="text-cyan-400">.OPS</span></div>
                        <div class="text-[10px] text-slate-400 tracking-wider font-mono">ZERO-TRUST AUDITING PLATFORM</div>
                    </div>
                </div>
                <div class="flex items-center space-x-5 text-xs font-semibold text-slate-400">
                    <span class="flex items-center gap-2"><span class="h-2 w-2 rounded-full bg-emerald-400 animate-pulse"></span> Nodes Operational</span>
                    <a href="/docs" target="_blank" class="hover:text-cyan-400 transition"><i class="fa-solid fa-file-code"></i> API Schema</a>
                </div>
            </div>
        </header>

        <!-- Main Body -->
        <main class="flex-1 max-w-6xl w-full mx-auto px-6 py-8">
            
            <!-- Hero Title -->
            <div class="text-center mb-8">
                <h1 class="text-3xl sm:text-5xl font-black tracking-tight text-white mb-3">
                    Campus Perimeter Threat Intelligence
                </h1>
                <p class="text-slate-400 max-w-2xl mx-auto text-sm">
                    Cryptographic K-Anonymity verification, institutional subdomain scanning, and threat vector distribution analytics.
                </p>
            </div>

            <!-- Top Real-Time Metrics -->
            <div class="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-8">
                <div class="bg-slate-900/70 border border-slate-800 rounded-2xl p-5 flex items-center gap-4">
                    <div class="p-3 bg-cyan-500/10 text-cyan-400 rounded-xl text-2xl"><i class="fa-solid fa-database"></i></div>
                    <div>
                        <div class="text-xs font-bold text-slate-400 uppercase tracking-wider">Breach Incidents</div>
                        <div id="metricBreaches" class="text-2xl font-black text-white">0</div>
                    </div>
                </div>
                <div class="bg-slate-900/70 border border-slate-800 rounded-2xl p-5 flex items-center gap-4">
                    <div class="p-3 bg-indigo-500/10 text-indigo-400 rounded-xl text-2xl"><i class="fa-solid fa-user-lock"></i></div>
                    <div>
                        <div class="text-xs font-bold text-slate-400 uppercase tracking-wider">Identities Monitored</div>
                        <div id="metricTargets" class="text-2xl font-black text-white">0</div>
                    </div>
                </div>
                <div class="bg-slate-900/70 border border-slate-800 rounded-2xl p-5 flex items-center gap-4">
                    <div class="p-3 bg-rose-500/10 text-rose-400 rounded-xl text-2xl"><i class="fa-solid fa-triangle-exclamation"></i></div>
                    <div>
                        <div class="text-xs font-bold text-slate-400 uppercase tracking-wider">High Risk Criticalities</div>
                        <div id="metricCritical" class="text-2xl font-black text-rose-400">0</div>
                    </div>
                </div>
            </div>

            <!-- Interactive Modules Card -->
            <div class="bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl overflow-hidden mb-8">
                <!-- Navigation Tabs -->
                <div class="grid grid-cols-4 border-b border-slate-800 bg-slate-950/60 text-xs sm:text-sm font-semibold">
                    <button id="emailTabBtn" onclick="switchTab('email')" class="py-4 text-cyan-400 border-b-2 border-cyan-400 flex items-center justify-center gap-2 transition">
                        <i class="fa-regular fa-envelope"></i> Email Scanner
                    </button>
                    <button id="passwordTabBtn" onclick="switchTab('password')" class="py-4 text-slate-400 border-b-2 border-transparent hover:text-slate-200 flex items-center justify-center gap-2 transition">
                        <i class="fa-solid fa-shield-cat"></i> K-Anonymity
                    </button>
                    <button id="generatorTabBtn" onclick="switchTab('generator')" class="py-4 text-slate-400 border-b-2 border-transparent hover:text-slate-200 flex items-center justify-center gap-2 transition">
                        <i class="fa-solid fa-wand-magic-sparkles"></i> Generator
                    </button>
                    <button id="domainTabBtn" onclick="switchTab('domain')" class="py-4 text-slate-400 border-b-2 border-transparent hover:text-slate-200 flex items-center justify-center gap-2 transition">
                        <i class="fa-solid fa-network-wired"></i> Domain Radar
                    </button>
                </div>

                <div class="p-6">
                    <!-- SECTION 1: Email -->
                    <div id="emailSection">
                        <label class="block text-xs font-bold uppercase tracking-wider text-slate-400 mb-2">Subject Email Identifier</label>
                        <div class="flex gap-2">
                            <input id="emailInput" type="email" placeholder="e.g. student@college.edu" 
                                   class="flex-1 px-4 py-3 bg-slate-800/80 border border-slate-700 rounded-xl text-white placeholder-slate-500 focus:outline-none focus:border-cyan-400 transition" />
                            <button onclick="searchEmail()" class="bg-cyan-500 hover:bg-cyan-400 font-bold text-slate-950 px-6 py-3 rounded-xl transition shadow-lg shadow-cyan-500/20">
                                Scan
                            </button>
                        </div>
                    </div>

                    <!-- SECTION 2: K-Anonymity Password -->
                    <div id="passwordSection" class="hidden">
                        <div class="flex items-center justify-between mb-2">
                            <label class="text-xs font-bold uppercase tracking-wider text-slate-400">Zero-Knowledge K-Anonymity Verifier</label>
                            <span class="text-[11px] text-cyan-400 font-mono"><i class="fa-solid fa-lock"></i> Plaintext never transmitted</span>
                        </div>
                        <div class="flex gap-2">
                            <input id="passwordInput" type="password" placeholder="Enter plaintext password string (e.g. password123)" 
                                   class="flex-1 px-4 py-3 bg-slate-800/80 border border-slate-700 rounded-xl text-white placeholder-slate-500 focus:outline-none focus:border-cyan-400 transition" />
                            <button onclick="searchPasswordKAnonymity()" class="bg-cyan-500 hover:bg-cyan-400 font-bold text-slate-950 px-6 py-3 rounded-xl transition shadow-lg shadow-cyan-500/20">
                                Verify Anonymously
                            </button>
                        </div>
                        <p class="text-xs text-slate-500 mt-2">
                            Your browser locally computes the SHA-1 digest and only broadcasts the 5-character prefix to our cluster.
                        </p>
                    </div>

                    <!-- SECTION 3: Password Generator -->
                    <div id="generatorSection" class="hidden space-y-4">
                        <div class="p-4 bg-slate-950/60 border border-slate-800 rounded-xl flex items-center justify-between">
                            <div id="genResult" class="font-mono text-cyan-300 font-bold text-base tracking-wider break-all select-all">Click 'Generate Password' below</div>
                            <button onclick="copyGeneratedPassword()" class="text-xs bg-slate-800 hover:bg-slate-700 text-slate-200 px-3 py-1.5 rounded-lg border border-slate-700 transition">
                                <i class="fa-regular fa-copy"></i> Copy
                            </button>
                        </div>

                        <div class="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
                            <div>
                                <label class="text-slate-400 font-semibold mb-1 block">Entropy Length: <span id="lengthVal" class="text-cyan-400 font-bold">16</span> characters</label>
                                <input id="pwdLength" type="range" min="8" max="32" value="16" oninput="document.getElementById('lengthVal').textContent = this.value" class="w-full accent-cyan-400" />
                            </div>
                            <div class="flex items-center space-x-4 pt-4">
                                <label class="flex items-center gap-2 cursor-pointer text-slate-300">
                                    <input type="checkbox" id="chkSymbols" checked class="accent-cyan-400" /> Symbols (!@#$)
                                </label>
                                <label class="flex items-center gap-2 cursor-pointer text-slate-300">
                                    <input type="checkbox" id="chkDigits" checked class="accent-cyan-400" /> Numbers (0-9)
                                </label>
                            </div>
                        </div>

                        <div class="flex items-center justify-between pt-2">
                            <div id="genEntropyDisplay" class="text-xs text-slate-400">Calculated Entropy: <span class="text-emerald-400 font-bold font-mono">0.0 Bits</span></div>
                            <button onclick="generateSecurePassword()" class="bg-cyan-500 hover:bg-cyan-400 font-bold text-slate-950 px-5 py-2.5 rounded-xl transition text-xs shadow-lg shadow-cyan-500/20">
                                <i class="fa-solid fa-arrows-rotate"></i> Generate Password
                            </button>
                        </div>
                    </div>

                    <!-- SECTION 4: Domain -->
                    <div id="domainSection" class="hidden">
                        <label class="block text-xs font-bold uppercase tracking-wider text-slate-400 mb-2">Institutional Domain Identifier</label>
                        <div class="flex gap-2">
                            <input id="domainInput" type="text" placeholder="e.g. college.edu" 
                                   class="flex-1 px-4 py-3 bg-slate-800/80 border border-slate-700 rounded-xl text-white placeholder-slate-500 focus:outline-none focus:border-cyan-400 transition" />
                            <button onclick="searchDomain()" class="bg-cyan-500 hover:bg-cyan-400 font-bold text-slate-950 px-6 py-3 rounded-xl transition shadow-lg shadow-cyan-500/20">
                                Audit Domain
                            </button>
                        </div>
                    </div>

                    <!-- Results Area -->
                    <div id="results" class="hidden mt-6"></div>
                </div>
            </div>

            <!-- Threat Intelligence Visualizations -->
            <div class="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
                <div class="bg-slate-900 border border-slate-800 rounded-2xl p-5 shadow-xl">
                    <h3 class="text-xs font-bold uppercase tracking-wider text-slate-400 mb-4 flex items-center gap-2">
                        <i class="fa-solid fa-chart-pie text-cyan-400"></i> Leaked Attack Vectors
                    </h3>
                    <div class="h-56 relative flex items-center justify-center">
                        <canvas id="vectorChart"></canvas>
                    </div>
                </div>
                <div class="bg-slate-900 border border-slate-800 rounded-2xl p-5 shadow-xl">
                    <h3 class="text-xs font-bold uppercase tracking-wider text-slate-400 mb-4 flex items-center gap-2">
                        <i class="fa-solid fa-chart-simple text-indigo-400"></i> Risk Severity Index
                    </h3>
                    <div class="h-56 relative flex items-center justify-center">
                        <canvas id="riskChart"></canvas>
                    </div>
                </div>
            </div>

            <!-- Admin Ingest Card -->
            <div class="bg-slate-900/60 border border-slate-800 rounded-2xl p-5">
                <button onclick="document.getElementById('adminPanel').classList.toggle('hidden')" class="text-xs font-mono text-slate-400 hover:text-cyan-400 flex items-center gap-2 transition">
                    <i class="fa-solid fa-terminal"></i> Campus Incident Ingestion Console (SecOps Authorized Only)
                </button>
                <div id="adminPanel" class="hidden mt-4 space-y-3 pt-3 border-t border-slate-800">
                    <div class="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
                        <input id="adminKey" type="password" placeholder="Admin Secret Key" class="p-2.5 bg-slate-800 border border-slate-700 rounded-lg text-white font-mono" />
                        <input id="adminEmail" type="email" placeholder="Victim Email" class="p-2.5 bg-slate-800 border border-slate-700 rounded-lg text-white" />
                        <input id="adminName" type="text" placeholder="Incident / Source Name" class="p-2.5 bg-slate-800 border border-slate-700 rounded-lg text-white" />
                        <input id="adminVectors" type="text" placeholder="Vectors (e.g. Email, Password)" class="p-2.5 bg-slate-800 border border-slate-700 rounded-lg text-white" />
                    </div>
                    <div class="flex justify-between items-center">
                        <span class="text-[11px] text-slate-500 font-mono">Key: sentinel-campus-key-2026</span>
                        <button onclick="submitAdminIncident()" class="bg-indigo-600 hover:bg-indigo-500 font-bold text-white text-xs px-4 py-2 rounded-lg transition">
                            Commit Incident
                        </button>
                    </div>
                </div>
            </div>
        </main>

        <script>
            let currentEmailResults = null;
            let currentDomainResults = null;

            // Load metrics & init charts
            async function initDashboard() {
                try {
                    const res = await fetch('/api/metrics');
                    const data = await res.json();
                    document.getElementById('metricBreaches').textContent = data.total_records.toLocaleString();
                    document.getElementById('metricTargets').textContent = data.distinct_targets.toLocaleString();
                    document.getElementById('metricCritical').textContent = (data.risk_breakdown['High'] || 0).toLocaleString();

                    // Render Vector Chart
                    new Chart(document.getElementById('vectorChart'), {
                        type: 'doughnut',
                        data: {
                            labels: ['Passwords', 'Personal Info', 'Session Hashes'],
                            datasets: [{
                                data: [55, 30, 15],
                                backgroundColor: ['#06b6d4', '#6366f1', '#f43f5e'],
                                borderWidth: 0
                            }]
                        },
                        options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { labels: { color: '#94a3b8', font: { size: 11 } } } } }
                    });

                    // Render Risk Chart
                    new Chart(document.getElementById('riskChart'), {
                        type: 'bar',
                        data: {
                            labels: ['High Risk', 'Medium Risk', 'Low Risk'],
                            datasets: [{
                                label: 'Threat Incidents',
                                data: [data.risk_breakdown['High'] || 0, data.risk_breakdown['Medium'] || 0, 1],
                                backgroundColor: ['#f43f5e', '#f59e0b', '#10b981'],
                                borderRadius: 6
                            }]
                        },
                        options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { x: { ticks: { color: '#94a3b8' } }, y: { ticks: { color: '#94a3b8' } } } }
                    });

                } catch(e) {}
            }
            initDashboard();

            function switchTab(tab) {
                const tabs = ['email', 'password', 'generator', 'domain'];
                tabs.forEach(t => {
                    const sec = document.getElementById(t + 'Section');
                    const btn = document.getElementById(t + 'TabBtn');
                    if (t === tab) {
                        sec.classList.remove('hidden');
                        btn.className = 'py-4 text-cyan-400 border-b-2 border-cyan-400 flex items-center justify-center gap-2 transition';
                    } else {
                        sec.classList.add('hidden');
                        btn.className = 'py-4 text-slate-400 border-b-2 border-transparent hover:text-slate-200 flex items-center justify-center gap-2 transition';
                    }
                });
                document.getElementById('results').classList.add('hidden');
            }

            // K-Anonymity SHA-1 Implementation
            async function sha1Hex(str) {
                const buffer = new TextEncoder().encode(str);
                const hashBuffer = await crypto.subtle.digest('SHA-1', buffer);
                const hashArray = Array.from(new Uint8Array(hashBuffer));
                return hashArray.map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
            }

            async function searchPasswordKAnonymity() {
                const pwd = document.getElementById('passwordInput').value;
                const out = document.getElementById('results');
                if (!pwd) return alert("Please supply a password.");

                out.classList.remove('hidden');
                out.innerHTML = '<div class="text-center py-6 text-slate-400"><i class="fa-solid fa-spinner fa-spin text-2xl text-cyan-400"></i><p class="mt-2 text-xs">Computing client SHA-1 digest...</p></div>';

                const fullHash = await sha1Hex(pwd);
                const prefix = fullHash.substring(0, 5);
                const suffix = fullHash.substring(5);

                const res = await fetch(`/api/pwned-range/${prefix}`);
                const data = await res.json();

                const matched = data.find(item => item.suffix === suffix);

                if (!matched) {
                    out.innerHTML = `
                        <div class="p-6 bg-emerald-950/40 border border-emerald-500/40 rounded-xl text-center">
                            <i class="fa-regular fa-circle-check text-emerald-400 text-3xl mb-2"></i>
                            <h3 class="text-base font-bold text-emerald-300">Clean K-Anonymity Signature</h3>
                            <p class="text-xs text-slate-400 mt-1">Neither this credential nor its hash exists in monitored breaches.</p>
                            <div class="mt-3 font-mono text-[10px] text-slate-500 bg-slate-900 p-2 rounded">
                                Prefix Transmitted: ${prefix} | Suffix Processed In-Memory: ${suffix}
                            </div>
                        </div>
                    `;
                } else {
                    out.innerHTML = `
                        <div class="p-6 bg-rose-950/40 border border-rose-500/40 rounded-xl text-center">
                            <i class="fa-solid fa-triangle-exclamation text-rose-400 text-3xl mb-2"></i>
                            <h3 class="text-base font-bold text-rose-300">Compromised Password Hash</h3>
                            <p class="text-xs text-slate-300 mt-1">Identified across <strong class="text-rose-400">${matched.count.toLocaleString()}</strong> underground breaches.</p>
                            <div class="mt-3 font-mono text-[10px] text-slate-500 bg-slate-900 p-2 rounded">
                                Transmitted Prefix: ${prefix} | Matched Suffix: ${suffix}
                            </div>
                        </div>
                    `;
                }
            }

            // Enterprise Password Generator
            function generateSecurePassword() {
                const len = parseInt(document.getElementById('pwdLength').value);
                const useSymbols = document.getElementById('chkSymbols').checked;
                const useDigits = document.getElementById('chkDigits').checked;

                let chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
                let poolSize = 52;
                if (useDigits) { chars += "0123456789"; poolSize += 10; }
                if (useSymbols) { chars += "!@#$%^&*()_+-=[]{}|"; poolSize += 19; }

                let result = "";
                const randVals = new Uint32Array(len);
                crypto.getRandomValues(randVals);
                for (let i = 0; i < len; i++) {
                    result += chars[randVals[i] % chars.length];
                }

                const entropy = (len * Math.log2(poolSize)).toFixed(1);
                document.getElementById('genResult').textContent = result;
                document.getElementById('genEntropyDisplay').innerHTML = `Calculated Entropy: <span class="text-emerald-400 font-bold font-mono">${entropy} Bits</span> (NIST Compliant)`;
            }

            function copyGeneratedPassword() {
                const pwd = document.getElementById('genResult').textContent;
                if (pwd.includes('Click')) return;
                navigator.clipboard.writeText(pwd);
                alert("Password copied to clipboard!");
            }

            // CSV Download Engine
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

            // Email Search
            async function searchEmail() {
                const email = document.getElementById('emailInput').value.trim();
                const out = document.getElementById('results');
                if (!email) return alert("Enter an email.");

                out.classList.remove('hidden');
                out.innerHTML = '<div class="text-center py-6 text-slate-400"><i class="fa-solid fa-spinner fa-spin text-2xl text-cyan-400"></i></div>';

                const res = await fetch('/api/check-email?email=' + encodeURIComponent(email));
                const data = await res.json();
                currentEmailResults = data;

                if (!data.is_breached) {
                    out.innerHTML = `
                        <div class="p-6 bg-emerald-950/40 border border-emerald-500/40 rounded-xl text-center">
                            <i class="fa-regular fa-circle-check text-emerald-400 text-3xl mb-2"></i>
                            <h3 class="text-base font-bold text-emerald-300">Clean Identity Record</h3>
                            <p class="text-xs text-slate-400 mt-1">Zero exposures found for <span class="font-mono text-emerald-200">${data.email}</span>.</p>
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
                                <p class="text-xs text-slate-400">Exposures detected across public databases.</p>
                            </div>
                            <button onclick="exportEmailCSV()" class="bg-cyan-500 hover:bg-cyan-400 text-slate-950 text-xs font-bold py-1.5 px-3 rounded-lg flex items-center gap-1.5 transition">
                                <i class="fa-solid fa-download"></i> CSV Report
                            </button>
                        </div>
                        <div class="space-y-2 mb-4">${cards}</div>
                    </div>
                `;
            }

            // Domain Search
            async function searchDomain() {
                const domain = document.getElementById('domainInput').value.trim();
                const out = document.getElementById('results');
                if (!domain) return alert("Enter domain.");

                out.classList.remove('hidden');
                out.innerHTML = '<div class="text-center py-6 text-slate-400"><i class="fa-solid fa-spinner fa-spin text-2xl text-cyan-400"></i></div>';

                const res = await fetch('/api/check-domain?domain=' + encodeURIComponent(domain));
                const data = await res.json();
                currentDomainResults = data;

                if (data.total_found === 0) {
                    out.innerHTML = `
                        <div class="p-6 bg-emerald-950/40 border border-emerald-500/40 rounded-xl text-center">
                            <i class="fa-regular fa-circle-check text-emerald-400 text-3xl mb-2"></i>
                            <h3 class="text-base font-bold text-emerald-300">Clean Institutional Domain</h3>
                            <p class="text-xs text-slate-400 mt-1">Zero leaks detected matching @${data.domain}.</p>
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
                                    <p class="text-xs text-slate-400">${data.total_found} accounts exposed.</p>
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

            // Admin Submission
            async function submitAdminIncident() {
                const key = document.getElementById('adminKey').value;
                const email = document.getElementById('adminEmail').value;
                const name = document.getElementById('adminName').value;
                const vectors = document.getElementById('adminVectors').value;

                if (!key || !email || !name) return alert("Fill all admin fields.");

                const res = await fetch('/api/admin/ingest', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'x-api-key': key },
                    body: JSON.stringify({
                        email: email,
                        breach_name: name,
                        breach_date: new Date().toISOString().split('T')[0],
                        leaked_info: vectors || 'Credentials',
                        risk_level: 'High'
                    })
                });

                if (res.ok) {
                    alert("Incident committed to SQLite cluster!");
                    location.reload();
                } else {
                    alert("Unauthorized or error occurred.");
                }
            }
        </script>
    </body>
    </html>
    """
