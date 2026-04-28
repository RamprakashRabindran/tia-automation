"""
TIA Report Generator
Usage: python tia_generator.py --url <URL> [--title "Override Title"] [--out-dir output]
                               [--header-image "Header Image.png"] [--footer-image "Footer Image.png"]

Strategy:
- Overview:           Always AI-generated (Groq) from article content
- Attack Vector:      Extract from article; fallback to AI if not found
- Attack Technique:   Extract from article; fallback to AI if not found
- MITRE ATT&CK:       Strict extraction from article only — blank if not present
- IOCs:               Strict extraction from article only — blank if not present
- Impacts:            AI-generated (Groq) from article content
- Recommended Action: AI-generated (Groq) from article content
- Everything else:    Rule-based extraction
"""

import argparse
import datetime as dt
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Tuple
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup
from docx import Document
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Inches, Pt, RGBColor


# ---------------------------------------------------------------------------
# Groq API Configuration
# ---------------------------------------------------------------------------
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
GROQ_MODEL = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"


# ---------------------------------------------------------------------------
# MITRE ATT&CK ID to Official Technique Name lookup
# ---------------------------------------------------------------------------
MITRE_NAMES: Dict[str, str] = {
    "T1566": "Phishing",
    "T1566.001": "Phishing: Spearphishing Attachment",
    "T1566.002": "Phishing: Spearphishing Link",
    "T1566.003": "Phishing: Spearphishing via Service",
    "T1598": "Phishing for Information",
    "T1598.003": "Phishing for Information: Spearphishing Link",
    "T1059": "Command and Scripting Interpreter",
    "T1059.001": "Command and Scripting Interpreter: PowerShell",
    "T1059.003": "Command and Scripting Interpreter: Windows Command Shell",
    "T1059.005": "Command and Scripting Interpreter: Visual Basic",
    "T1059.006": "Command and Scripting Interpreter: Python",
    "T1059.007": "Command and Scripting Interpreter: JavaScript",
    "T1059.010": "Command and Scripting Interpreter: AutoHotKey & AutoIT",
    "T1053": "Scheduled Task/Job",
    "T1053.005": "Scheduled Task/Job: Scheduled Task",
    "T1176": "Browser Extensions",
    "T1176.001": "Browser Extensions",
    "T1547": "Boot or Logon Autostart Execution",
    "T1547.001": "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
    "T1547.009": "Boot or Logon Autostart Execution: Shortcut Modification",
    "T1543": "Create or Modify System Process",
    "T1543.003": "Create or Modify System Process: Windows Service",
    "T1204": "User Execution",
    "T1204.001": "User Execution: Malicious Link",
    "T1204.002": "User Execution: Malicious File",
    "T1559": "Inter-Process Communication",
    "T1569": "System Services",
    "T1569.002": "System Services: Service Execution",
    "T1068": "Exploitation for Privilege Escalation",
    "T1003": "OS Credential Dumping",
    "T1003.001": "OS Credential Dumping: LSASS Memory",
    "T1003.002": "OS Credential Dumping: Security Account Manager",
    "T1003.003": "OS Credential Dumping: NTDS",
    "T1110": "Brute Force",
    "T1110.001": "Brute Force: Password Guessing",
    "T1110.003": "Brute Force: Password Spraying",
    "T1552": "Unsecured Credentials",
    "T1552.001": "Unsecured Credentials: Credentials In Files",
    "T1550": "Use Alternate Authentication Material",
    "T1550.002": "Use Alternate Authentication Material: Pass the Hash",
    "T1027": "Obfuscated Files or Information",
    "T1027.010": "Obfuscated Files or Information: Command Obfuscation",
    "T1027.015": "Obfuscated Files or Information: Compression",
    "T1036": "Masquerading",
    "T1036.005": "Masquerading: Match Legitimate Resource Name or Location",
    "T1055": "Process Injection",
    "T1070": "Indicator Removal",
    "T1070.004": "Indicator Removal: File Deletion",
    "T1112": "Modify Registry",
    "T1134": "Access Token Manipulation",
    "T1134.001": "Access Token Manipulation: Token Impersonation/Theft",
    "T1140": "Deobfuscate/Decode Files or Information",
    "T1202": "Indirect Command Execution",
    "T1562": "Impair Defenses",
    "T1562.001": "Impair Defenses: Disable or Modify Tools",
    "T1564": "Hide Artifacts",
    "T1564.001": "Hide Artifacts: Hidden Files and Directories",
    "T1622": "Debugger Evasion",
    "T1007": "System Service Discovery",
    "T1012": "Query Registry",
    "T1016": "System Network Configuration Discovery",
    "T1018": "Remote System Discovery",
    "T1033": "System Owner/User Discovery",
    "T1046": "Network Service Discovery",
    "T1057": "Process Discovery",
    "T1082": "System Information Discovery",
    "T1083": "File and Directory Discovery",
    "T1087": "Account Discovery",
    "T1087.001": "Account Discovery: Local Account",
    "T1518": "Software Discovery",
    "T1021": "Remote Services",
    "T1021.001": "Remote Services: Remote Desktop Protocol",
    "T1021.002": "Remote Services: SMB/Windows Admin Shares",
    "T1005": "Data from Local System",
    "T1074": "Data Staged",
    "T1113": "Screen Capture",
    "T1560": "Archive Collected Data",
    "T1560.001": "Archive Collected Data: Archive via Utility",
    "T1020": "Automated Exfiltration",
    "T1041": "Exfiltration Over C2 Channel",
    "T1567": "Exfiltration Over Web Service",
    "T1567.002": "Exfiltration Over Web Service: Exfiltration to Cloud Storage",
    "T1071": "Application Layer Protocol",
    "T1071.001": "Application Layer Protocol: Web Protocols",
    "T1090": "Proxy",
    "T1105": "Ingress Tool Transfer",
    "T1572": "Protocol Tunneling",
    "T1486": "Data Encrypted for Impact",
    "T1489": "Service Stop",
    "T1490": "Inhibit System Recovery",
    "T1491": "Defacement",
    "T1485": "Data Destruction",
    "T1608": "Stage Capabilities",
    "T1608.002": "Stage Capabilities: Upload Tool",
    "T1608.005": "Stage Capabilities: Link Target",
    "T1190": "Exploit Public-Facing Application",
    "T1133": "External Remote Services",
    "T1078": "Valid Accounts",
    "T1078.002": "Valid Accounts: Domain Accounts",
    "T1078.003": "Valid Accounts: Local Accounts",
    "T1195": "Supply Chain Compromise",
    "T1195.001": "Supply Chain Compromise: Compromise Software Dependencies and Development Tools",
    "T1195.002": "Supply Chain Compromise: Compromise Software Supply Chain",
    "T1588": "Obtain Capabilities",
    "T1588.006": "Obtain Capabilities: Vulnerabilities",
    "T1556": "Modify Authentication Process",
    "T1601": "Modify System Image",
    "T1612": "Build Image on Host",
    "T1611": "Escape to Host",
    "T1609": "Container Administration Command",
    "T1610": "Deploy Container",
}


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------
@dataclass
class TIAData:
    title: str
    overview: str
    severity: str
    region: str
    sector: str
    attack_vector: List[Tuple[str, str]]
    attack_technique: str
    mitre: List[Tuple[str, str]]          # strictly from article; empty if none
    iocs: Dict[str, List[str]]            # strictly from article; empty if none
    impacts: List[str]
    affected_products: List[str]
    recommended_action: Dict[str, List[str]]
    references: List[str]


# ---------------------------------------------------------------------------
# Groq API helpers
# ---------------------------------------------------------------------------
def call_gemini(system_prompt: str, user_prompt: str, max_tokens: int = 1000) -> str:
    """Call Groq Chat Completions API and return text response."""
    if not GROQ_API_KEY:
        print("[AI] Groq API key missing. Set GROQ_API_KEY environment variable.")
        return ""

    payload = {
        "model": GROQ_MODEL,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "max_tokens": max_tokens,
        "temperature": 0.2,
    }
    try:
        headers = {
            "Authorization": f"Bearer {GROQ_API_KEY}",
            "Content-Type": "application/json",
        }
        resp = requests.post(GROQ_API_URL, headers=headers, json=payload, timeout=60)
        resp.raise_for_status()
        data = resp.json()
        choices = data.get("choices", [])
        if not choices:
            return ""
        return choices[0].get("message", {}).get("content", "").strip()
    except Exception as e:
        print(f"[AI] Groq API call failed: {e}")
        return ""


def call_gemini_json(system_prompt: str, user_prompt: str, max_tokens: int = 1000) -> object:
    """Call Groq expecting JSON back. Returns parsed object or empty dict on failure."""
    full_system = (
        system_prompt
        + "\n\nCRITICAL: Return ONLY raw JSON with no markdown fences, no ```json, no preamble."
    )
    raw = call_gemini(full_system, user_prompt, max_tokens)
    # Strip any accidental markdown fences
    raw = re.sub(r"^```(?:json)?\s*", "", raw.strip(), flags=re.MULTILINE)
    raw = re.sub(r"```\s*$", "", raw.strip(), flags=re.MULTILINE)
    try:
        return json.loads(raw.strip())
    except Exception:
        return {}


# ---------------------------------------------------------------------------
# HTTP fetch
# ---------------------------------------------------------------------------
def validate_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError(f"Invalid URL: {url}")
    return url


def fetch_url_text(url: str) -> Tuple[str, str]:
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) TIA-Automation/1.0"}
    response = requests.get(url, headers=headers, timeout=30)
    if response.status_code == 403:
        mirror = f"https://r.jina.ai/{url}"
        response = requests.get(mirror, headers=headers, timeout=30)
    response.raise_for_status()
    soup = BeautifulSoup(response.text, "lxml")
    page_title = soup.title.get_text(strip=True) if soup.title else ""
    for bad in soup(["script", "style", "noscript", "header", "footer", "nav", "aside"]):
        bad.decompose()
    text = soup.get_text(separator=" ", strip=True)
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) < 300:
        raise RuntimeError("Fetched content is too short to analyze.")
    return page_title, text


# ---------------------------------------------------------------------------
# Title detection
# ---------------------------------------------------------------------------
def detect_title(url: str, text: str, page_title: str = "", override: str = "") -> str:
    if override:
        return override.strip()
    if page_title:
        normalized = re.sub(r"\s+", " ", page_title).strip()
        normalized = re.sub(r"\bhttps?://\S+\b", "", normalized, flags=re.IGNORECASE).strip()
        normalized = re.sub(r"\bwww\.\S+\b", "", normalized, flags=re.IGNORECASE).strip()
        normalized = re.split(r"\s[\|\-:]\s", normalized)[0].strip()
        normalized = re.sub(r"[^A-Za-z0-9&(),:\- ]+", " ", normalized)
        normalized = re.sub(r"\s+", " ", normalized).strip(" -|:")
        if 6 <= len(normalized) <= 140:
            return normalized
    first_sentence = text.split(".")[0][:120].strip()
    if len(first_sentence.split()) >= 4:
        return first_sentence
    host = urlparse(url).netloc.replace("www.", "")
    return f"Threat Intelligence from {host}"


# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------
def infer_severity(text: str) -> str:
    lowered = text.lower()
    critical_signals = ["ransomware", "wiper", "zero-day", "zero day", "apt", "nation state",
                        "critical infrastructure", "domain controller", "active directory", "ntds"]
    high_signals = ["malware", "credential theft", "data exfiltration", "lateral movement",
                    "backdoor", "remote access", "lsass", "pass the hash", "c2", "command and control",
                    "supply chain", "compromised package", "pypi", "npm"]
    medium_signals = ["phishing", "social engineering", "browser extension", "dropper",
                      "script injection", "github actions"]

    critical_count = sum(1 for k in critical_signals if k in lowered)
    high_count = sum(1 for k in high_signals if k in lowered)
    medium_count = sum(1 for k in medium_signals if k in lowered)

    if critical_count >= 2 or (critical_count >= 1 and high_count >= 2):
        return "Critical"
    if high_count >= 2 or (high_count >= 1 and critical_count >= 1):
        return "High"
    if medium_count >= 1 or high_count >= 1:
        return "Medium"
    return "Low"


# ---------------------------------------------------------------------------
# Region
# ---------------------------------------------------------------------------
def infer_region(text: str) -> str:
    lowered = text.lower()
    region_map = {
        "united states": "United States",
        "north america": "North America",
        "europe": "Europe",
        "asia pacific": "Asia Pacific",
        "southeast asia": "Southeast Asia",
        "middle east": "Middle East",
        "global": "Global",
        "worldwide": "Global",
        "multiple countries": "Global",
        "multiple regions": "Global",
    }
    if re.search(r"\b(global|worldwide|multiple\s+countries|multiple\s+regions)\b", lowered):
        return "Global"
    for region_key, region_val in region_map.items():
        pattern = rf"(?:target|victim|attack|campaign|against|focus).{{0,60}}{re.escape(region_key)}"
        if re.search(pattern, lowered):
            return region_val
    return "Global"


# ---------------------------------------------------------------------------
# Sector
# ---------------------------------------------------------------------------
def infer_sector(text: str) -> str:
    lowered = text.lower()
    sector_map = [
        ("healthcare", "Healthcare"),
        ("financial", "Financial Services"),
        ("government", "Government"),
        ("education", "Education"),
        ("manufacturing", "Manufacturing"),
        ("retail", "Retail"),
        ("energy", "Energy"),
        ("aviation", "Aviation"),
        ("transportation", "Transportation"),
        ("telecommunication", "Telecommunications"),
        ("software", "Technology / Software"),
        ("developer", "Technology / Software"),
        ("open.source", "Technology / Software"),
        ("pypi", "Technology / Software"),
        ("npm", "Technology / Software"),
    ]
    found = []
    seen = set()
    for token, label in sector_map:
        if re.search(re.escape(token), lowered) and label not in seen:
            found.append(label)
            seen.add(label)
    if len(found) > 1:
        return "Multiple Sectors"
    if found:
        return found[0]
    return "Multiple Sectors"


# ---------------------------------------------------------------------------
# IOC extraction — STRICT: only from explicit IOC sections in the article
# ---------------------------------------------------------------------------
def extract_iocs(text: str) -> Dict[str, List[str]]:
    """
    Extract IOCs ONLY from sections explicitly labelled as Indicators of Compromise.
    Returns empty dict if no such section is found — never guesses from body text.
    """
    out: Dict[str, List[str]] = {}

    ioc_section_pattern = re.compile(
        r"(?:indicators?\s+of\s+compromise|network\s+indicators?|file\s+indicators?|iocs?)"
        r"(.{0,8000}?)(?=\n\n[A-Z]|outlook|mitre|acknowledgement|conclusion|references|$)",
        re.IGNORECASE | re.DOTALL,
    )
    ioc_sections = ioc_section_pattern.findall(text)

    if not ioc_sections:
        return {}

    ioc_text = " ".join(ioc_sections)

    # SHA-256 hashes (64 hex chars)
    sha256_pattern = re.compile(r"\b([a-fA-F0-9]{64})\b")
    sha256s = list(dict.fromkeys(sha256_pattern.findall(ioc_text)))
    if sha256s:
        out["SHA-256"] = sha256s[:15]

    # SHA-1 hashes (40 hex chars)
    sha1_pattern = re.compile(r"\b([a-fA-F0-9]{40})\b")
    sha1s = list(dict.fromkeys(sha1_pattern.findall(ioc_text)))
    sha1s = [h for h in sha1s if not any(h in s for s in sha256s)]
    if sha1s:
        out["SHA-1"] = sha1s[:10]

    # MD5 hashes (32 hex chars)
    md5_pattern = re.compile(r"\b([a-fA-F0-9]{32})\b")
    md5s = list(dict.fromkeys(md5_pattern.findall(ioc_text)))
    md5s = [h for h in md5s if not any(h in s for s in sha256s)]
    if md5s:
        out["MD5"] = md5s[:10]

    # Domains — defanged or clearly malicious
    domain_pattern = re.compile(
        r"\b([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\[\.\]|\.)(?:[a-zA-Z0-9\-]{1,61}\.)*"
        r"(?:com|net|org|io|app|cloud|sh|xyz|ru|cn|me|co|gov|edu|info|biz|top))\b",
        re.IGNORECASE,
    )
    legit_exclusions = {
        "google.com", "microsoft.com", "github.com", "virustotal.com",
        "cloud.google.com", "schema.org", "w3.org", "pypi.org",
        "stepsecurity.io", "bleepingcomputer.com",
    }
    raw_domains = domain_pattern.findall(ioc_text)
    clean_domains = []
    for d in raw_domains:
        d_clean = d.replace("[.]", ".").lower()
        if d_clean not in legit_exclusions and len(d_clean) > 4:
            clean_domains.append(d)
    clean_domains = list(dict.fromkeys(clean_domains))
    if clean_domains:
        out["Domain"] = clean_domains[:10]

    # IP addresses
    ip_pattern = re.compile(
        r"\b(\d{1,3}(?:\[\.\]|\.)\d{1,3}(?:\[\.\]|\.)\d{1,3}(?:\[\.\]|\.)\d{1,3})\b"
    )
    ips = list(dict.fromkeys(ip_pattern.findall(ioc_text)))
    if ips:
        out["IP Address"] = ips[:10]

    # URLs
    url_pattern = re.compile(r"https?://[^\s\"<>]+")
    urls = list(dict.fromkeys(url_pattern.findall(ioc_text)))
    non_ioc_domains = [
        "google.com/blog", "virustotal.com/gui/collection", "cloud.google.com",
        "schema.org", "w3.org", "microsoft.com/en-us", "stepsecurity.io/blog",
    ]
    ioc_urls = [u for u in urls if not any(x in u for x in non_ioc_domains)]
    if ioc_urls:
        out["URL"] = ioc_urls[:5]

    # File names
    file_pattern = re.compile(
        r"\b([\w\-]+\.(?:exe|dll|bat|ps1|sh|js|html|ahk|py|txt|zip|log|pth|tar\.gz))\b",
        re.IGNORECASE,
    )
    generic_exclusions = {
        "msedge.exe", "cmd.exe", "powershell.exe", "lsass.exe",
        "tasklist.exe", "taskkill.exe", "psexec.exe",
    }
    file_names = list(dict.fromkeys(file_pattern.findall(ioc_text)))
    ioc_files = [f for f in file_names if f.lower() not in generic_exclusions]
    if ioc_files:
        out["File Name"] = ioc_files[:10]

    return out


# ---------------------------------------------------------------------------
# MITRE ATT&CK — STRICT: only from explicit section in article
# ---------------------------------------------------------------------------
def extract_mitre(text: str) -> List[Tuple[str, str]]:
    """
    Extract MITRE ATT&CK IDs only if the article explicitly lists them in a MITRE section.
    If no MITRE section exists, returns empty list — never infers from body text.
    """
    mitre_section_pattern = re.compile(
        r"(?:mitre\s+att&ck|mitre\s+attack|att&ck\s+technique|mitre\s+ttps?)"
        r"(.{0,6000}?)(?=\n\n[A-Z]|outlook|indicators|references|acknowledgement|$)",
        re.IGNORECASE | re.DOTALL,
    )
    mitre_sections = mitre_section_pattern.findall(text)

    if not mitre_sections:
        return []

    search_text = " ".join(mitre_sections)
    id_pattern = re.compile(r"\b(T\d{4}(?:\.\d{3})?)\b", re.IGNORECASE)
    found_ids = list(dict.fromkeys(m.upper() for m in id_pattern.findall(search_text)))

    rows: List[Tuple[str, str]] = []
    for tid in found_ids:
        name = MITRE_NAMES.get(tid, "")
        if name:
            rows.append((tid, name))
        else:
            rows.append((tid, tid))
    return rows[:20]


# ---------------------------------------------------------------------------
# AI-powered: Overview (always Groq)
# ---------------------------------------------------------------------------
def ai_overview(text: str) -> str:
    """Always use Groq to generate a concise, accurate overview."""
    print("[AI] Generating overview...")
    result = call_gemini(
        system_prompt=(
            "You are a cybersecurity analyst writing Threat Intelligence Advisories. "
            "Write a factual, concise overview paragraph (3-5 sentences) summarizing the threat described "
            "in the provided article text. Focus on: what happened, what was compromised, how it works, "
            "and who is affected. Be specific — use names of packages, CVEs, techniques exactly as mentioned. "
            "Do NOT add information not in the article. Do NOT use bullet points. Plain prose only."
        ),
        user_prompt=f"Article text (truncated to 4000 chars):\n\n{text[:4000]}",
        max_tokens=400,
    )
    if result:
        return result
    # Fallback: pick first meaningful sentences
    sentences = re.split(r"(?<=[.!?])\s+", text)
    picked = []
    for s in sentences:
        s = s.strip()
        if 60 <= len(s) <= 300 and not re.match(r"^(?:http|www|©|cookie|privacy)", s, re.IGNORECASE):
            picked.append(s)
        if len(picked) == 3:
            break
    return " ".join(picked) if picked else text[:400]


# ---------------------------------------------------------------------------
# Attack Vector — extract from article first, fallback to Groq
# ---------------------------------------------------------------------------
def extract_attack_vector_from_text(text: str) -> List[Tuple[str, str]]:
    """Try to find attack vector stages from the article body."""
    stage_definitions = [
        ("Initial Access", [
            "phish", "social engineer", "script injection", "pull request", "comment injection",
            "supply chain", "compromised package", "malicious version", "poisoned",
        ]),
        ("Execution", [
            "autohotkey", "ahk", "script", "dropper", "download", "execute",
            "payload", "binary", ".pth", "import", "python invocation", "startup",
        ]),
        ("Persistence", [
            "persist", "scheduled task", "startup", "registry", "shortcut",
            "site-packages", "pth file", "service worker",
        ]),
        ("Privilege Escalation", ["escalat", "privilege", "token", "impersonat"]),
        ("Credential Access", [
            "lsass", "credential", "dump", "memory", "hash", "ntds",
            "sam", "password", "kerberos", "ssh key", "api key", "secret",
        ]),
        ("Exfiltration", [
            "exfiltrat", "rclone", "s3", "upload", "steal",
            "transfer", "cloud storage", "c2", "command and control",
        ]),
        ("Lateral Movement", [
            "lateral", "pivot", "rdp", "smb", "psexec", "pass-the-hash",
            "domain controller", "winrm", "github token", "inject workflow",
        ]),
    ]

    sentences = [s.strip() for s in re.split(r"(?<=[.!?])\s+", text) if 40 <= len(s.strip()) <= 400]
    result: List[Tuple[str, str]] = []
    used_sentences = set()

    for stage, keywords in stage_definitions:
        pattern = re.compile("|".join(re.escape(k) for k in keywords), re.IGNORECASE)
        for s in sentences:
            if s in used_sentences:
                continue
            if pattern.search(s):
                result.append((stage, s))
                used_sentences.add(s)
                break

    return result


def ai_attack_vector(text: str) -> List[Tuple[str, str]]:
    """Use Groq to generate attack vector stages when extraction is insufficient."""
    print("[AI] Generating attack vector via Groq...")
    result = call_gemini_json(
        system_prompt=(
            "You are a cybersecurity analyst. Based on the article, identify the attack chain stages. "
            "Return ONLY a JSON array of objects, each with 'stage' and 'description' keys. "
            "Use standard stage names: Initial Access, Execution, Persistence, Privilege Escalation, "
            "Credential Access, Lateral Movement, Exfiltration. Only include stages actually described. "
            "Keep each description to 1-2 sentences, factual, from the article."
        ),
        user_prompt=f"Article text:\n\n{text[:4000]}",
        max_tokens=600,
    )
    if isinstance(result, list):
        return [(item.get("stage", ""), item.get("description", "")) for item in result if item.get("stage")]
    return []


def get_attack_vector(text: str) -> List[Tuple[str, str]]:
    result = extract_attack_vector_from_text(text)
    if len(result) >= 2:
        return result
    print("[AI] Insufficient attack vector from article, using Groq...")
    ai_result = ai_attack_vector(text)
    return ai_result if ai_result else result


# ---------------------------------------------------------------------------
# Attack Technique — extract from article first, fallback to Groq
# ---------------------------------------------------------------------------
def extract_attack_technique_from_text(text: str) -> str:
    """Try to find a coherent attack technique paragraph from the article."""
    section_pattern = re.compile(
        r"(?:threat\s+details?|infection\s+chain|attack\s+chain|how\s+it\s+works?|"
        r"the\s+attack|vulnerability|the\s+compromise|exploit)"
        r"[:\s]+(.{200,1500}?)(?=\n\n[A-Z#]|internal\s+recon|lateral|escalat|$)",
        re.IGNORECASE | re.DOTALL,
    )
    match = section_pattern.search(text)
    if match:
        candidate = re.sub(r"\s+", " ", match.group(1)).strip()
        if len(candidate) > 100:
            if len(candidate) > 700:
                cut = candidate[:700].rfind(".")
                candidate = candidate[: cut + 1] if cut > 100 else candidate[:700]
            return candidate
    return ""


def ai_attack_technique(text: str) -> str:
    """Use Groq to summarize the attack technique."""
    print("[AI] Generating attack technique via Groq...")
    result = call_gemini(
        system_prompt=(
            "You are a cybersecurity analyst. Write a concise technical paragraph (3-5 sentences) "
            "describing the attack technique used, as described in the article. "
            "Be specific: name the vulnerability, method, tools, or mechanisms used. "
            "Do NOT add information not in the article. Plain prose only, no bullet points."
        ),
        user_prompt=f"Article text:\n\n{text[:4000]}",
        max_tokens=400,
    )
    return result


def get_attack_technique(text: str) -> str:
    result = extract_attack_technique_from_text(text)
    if result and len(result) > 150:
        return result
    print("[AI] Insufficient attack technique from article, using Groq...")
    ai_result = ai_attack_technique(text)
    return ai_result if ai_result else result or "See referenced source for full attack technique details."


# ---------------------------------------------------------------------------
# AI-powered: Impacts (always Groq)
# ---------------------------------------------------------------------------
def ai_impacts(text: str) -> List[str]:
    """Use Groq to generate impacts based on article content."""
    print("[AI] Generating impacts via Groq...")
    result = call_gemini_json(
        system_prompt=(
            "You are a cybersecurity analyst. Based on the article, list the specific impacts of this threat. "
            "Return ONLY a JSON array of strings — each string is one impact (1-2 sentences, factual). "
            "Only include impacts actually described or clearly implied by the article. "
            "Do not add generic impacts not relevant to this specific threat."
        ),
        user_prompt=f"Article text:\n\n{text[:4000]}",
        max_tokens=500,
    )
    if isinstance(result, list) and result:
        return [str(item) for item in result]
    return ["See referenced source for full impact details."]


# ---------------------------------------------------------------------------
# AI-powered: Recommended Actions (always Groq)
# ---------------------------------------------------------------------------
def ai_recommended_actions(text: str) -> Dict[str, List[str]]:
    """Use Groq to generate recommended actions based on the specific threat."""
    print("[AI] Generating recommended actions via Groq...")
    result = call_gemini_json(
        system_prompt=(
            "You are a cybersecurity analyst writing a Threat Intelligence Advisory. "
            "Based on the article, generate specific, actionable recommended actions. "
            "Return ONLY a JSON object with these exact keys: "
            "\"Organisational Control\", \"Technological Control\", \"People Control\", \"Physical Control\". "
            "Each key maps to an array of strings (2-4 items each). "
            "Actions must be directly relevant to the specific threat described — not generic advice. "
            "Be concrete and specific."
        ),
        user_prompt=f"Article text:\n\n{text[:4000]}",
        max_tokens=800,
    )
    if isinstance(result, dict) and result:
        keys = ["Organisational Control", "Technological Control", "People Control", "Physical Control"]
        return {k: result.get(k, ["See referenced source."]) for k in keys}
    return {
        "Organisational Control": ["See referenced source for organisational recommendations."],
        "Technological Control": ["See referenced source for technical recommendations."],
        "People Control": ["See referenced source for people-related recommendations."],
        "Physical Control": ["See referenced source for physical recommendations."],
    }


# ---------------------------------------------------------------------------
# Affected Products — rule-based (no hallucination)
# ---------------------------------------------------------------------------
def extract_products(text: str) -> List[str]:
    lowered = text.lower()
    checks = [
        (r"pypi|python package index", "PyPI (Python Package Index)"),
        (r"github container registry|ghcr", "GitHub Container Registry (GHCR)"),
        (r"github actions", "GitHub Actions"),
        (r"microsoft teams\b", "Microsoft Teams"),
        (r"microsoft edge\b", "Microsoft Edge"),
        (r"google chrome\b", "Google Chrome"),
        (r"chromium", "Chromium-based Browsers"),
        (r"microsoft windows\b", "Microsoft Windows"),
        (r"windows server\b", "Microsoft Windows Server"),
        (r"\blinux\b", "Linux"),
        (r"vmware esxi", "VMware ESXi"),
        (r"veeam", "Veeam Backup & Replication"),
        (r"microsoft sql", "Microsoft SQL Server"),
        (r"\bnpm\b", "npm (Node Package Manager)"),
        (r"docker", "Docker"),
    ]
    found = []
    seen_labels = set()
    for pattern, label in checks:
        if re.search(pattern, lowered) and label not in seen_labels:
            found.append(label)
            seen_labels.add(label)
    return found if found else ["Not specified."]


# ---------------------------------------------------------------------------
# Build TIAData
# ---------------------------------------------------------------------------
def build_tia_data(urls: List[str], text: str, page_title: str = "", title_override: str = "") -> TIAData:
    title = detect_title(urls[0], text, page_title, title_override)

    # Strict extraction (article only — no AI fallback)
    iocs = extract_iocs(text)
    mitre = extract_mitre(text)
    products = extract_products(text)

    # Rule-based
    severity = infer_severity(text)
    region = infer_region(text)
    sector = infer_sector(text)

    # Hybrid: extract first, Groq fallback
    attack_vector = get_attack_vector(text)
    attack_technique = get_attack_technique(text)

    # Always Groq
    overview = ai_overview(text)
    impacts = ai_impacts(text)
    recommended_action = ai_recommended_actions(text)

    return TIAData(
        title=title,
        overview=overview,
        severity=severity,
        region=region,
        sector=sector,
        attack_vector=attack_vector,
        attack_technique=attack_technique,
        mitre=mitre,
        iocs=iocs,
        impacts=impacts,
        affected_products=products,
        recommended_action=recommended_action,
        references=urls,
    )


# ---------------------------------------------------------------------------
# DOCX rendering helpers
# ---------------------------------------------------------------------------
def set_cell_shading(cell, fill: str) -> None:
    tc_pr = cell._tc.get_or_add_tcPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:fill"), fill)
    tc_pr.append(shd)


def set_default_font(document: Document, font_name: str = "Calibri", size: int = 11) -> None:
    style = document.styles["Normal"]
    style.font.name = font_name
    style.font.size = Pt(size)


def set_table_outer_border(table, outer_size: str = "16", inner_size: str = "6") -> None:
    tbl = table._tbl
    tbl_pr = tbl.tblPr
    borders = tbl_pr.find(qn("w:tblBorders"))
    if borders is None:
        borders = OxmlElement("w:tblBorders")
        tbl_pr.append(borders)

    def set_border(edge: str, size: str) -> None:
        element = borders.find(qn(f"w:{edge}"))
        if element is None:
            element = OxmlElement(f"w:{edge}")
            borders.append(element)
        element.set(qn("w:val"), "single")
        element.set(qn("w:sz"), size)
        element.set(qn("w:space"), "0")
        element.set(qn("w:color"), "000000")

    for edge in ["top", "left", "bottom", "right"]:
        set_border(edge, outer_size)
    for edge in ["insideH", "insideV"]:
        set_border(edge, inner_size)


def set_row_height(row, height_inches: float, exact: bool = True) -> None:
    row.height = Inches(height_inches)
    tr_pr = row._tr.get_or_add_trPr()
    h_rule = tr_pr.find(qn("w:trHeight"))
    if h_rule is not None:
        h_rule.set(qn("w:hRule"), "exact" if exact else "atLeast")


def set_cell_margins(cell, top=70, bottom=70, left=100, right=100) -> None:
    tc_pr = cell._tc.get_or_add_tcPr()
    tc_mar = tc_pr.find(qn("w:tcMar"))
    if tc_mar is None:
        tc_mar = OxmlElement("w:tcMar")
        tc_pr.append(tc_mar)
    for key, value in [("top", top), ("bottom", bottom), ("left", left), ("right", right)]:
        node = tc_mar.find(qn(f"w:{key}"))
        if node is None:
            node = OxmlElement(f"w:{key}")
            tc_mar.append(node)
        node.set(qn("w:w"), str(value))
        node.set(qn("w:type"), "dxa")


def clear_cell(cell) -> None:
    for paragraph in list(cell.paragraphs):
        p = paragraph._element
        p.getparent().remove(p)
    cell.add_paragraph("")


def severity_color(sev: str) -> RGBColor:
    return {
        "Critical": RGBColor(0x8B, 0x00, 0x00),
        "High": RGBColor(0xFF, 0x00, 0x00),
        "Medium": RGBColor(0xFF, 0x8C, 0x00),
        "Low": RGBColor(0x00, 0x80, 0x00),
    }.get(sev, RGBColor(0x00, 0x00, 0x00))


# ---------------------------------------------------------------------------
# Row builders
# ---------------------------------------------------------------------------
def add_label_row(table, label: str, value_builder):
    row = table.add_row()
    left = row.cells[0]
    right = row.cells[1]
    set_cell_margins(left)
    set_cell_margins(right)
    lp = left.paragraphs[0]
    lp.paragraph_format.space_before = Pt(1)
    lp.paragraph_format.space_after = Pt(1)
    lr = lp.add_run(label)
    lr.bold = True
    value_builder(right)


def add_blank_row(table):
    row = table.add_row()
    row.cells[0].text = ""
    row.cells[1].text = ""
    set_row_height(row, 2.55)


def add_title_row(table, title: str):
    row = table.add_row()
    set_row_height(row, 0.38)
    merged = row.cells[0].merge(row.cells[1])
    set_cell_margins(merged, top=50, bottom=50, left=80, right=80)
    p = merged.paragraphs[0]
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.paragraph_format.space_before = Pt(0)
    p.paragraph_format.space_after = Pt(0)
    run = p.add_run(title)
    run.bold = True
    run.font.size = Pt(14)


def add_header_row(table, header_image_path: str, ref_text: str, image_width_inches: float = 7.7):
    row = table.add_row()
    set_row_height(row, 1.25)
    merged = row.cells[0].merge(row.cells[1])
    clear_cell(merged)
    set_cell_margins(merged, top=0, bottom=40, left=40, right=40)
    p = merged.paragraphs[0]
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.paragraph_format.space_before = Pt(0)
    p.paragraph_format.space_after = Pt(0)
    image_path = Path(header_image_path) if header_image_path else Path("Header Image.png")
    if image_path.exists():
        p.add_run().add_picture(str(image_path), width=Inches(image_width_inches))
    ref_p = merged.add_paragraph()
    ref_p.alignment = WD_ALIGN_PARAGRAPH.RIGHT
    ref_p.paragraph_format.space_before = Pt(3)
    ref_p.paragraph_format.space_after = Pt(0)
    ref_run = ref_p.add_run(ref_text)
    ref_run.font.size = Pt(8)
    ref_run.underline = True


def add_footer_image_row(table, footer_image_path: str, image_width_inches: float = 7.7):
    if not footer_image_path:
        return
    image_path = Path(footer_image_path)
    if not image_path.exists():
        return
    row = table.add_row()
    set_row_height(row, 1.75)
    merged = row.cells[0].merge(row.cells[1])
    clear_cell(merged)
    set_cell_margins(merged, top=40, bottom=40, left=40, right=40)
    p = merged.paragraphs[0]
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.paragraph_format.space_before = Pt(0)
    p.paragraph_format.space_after = Pt(0)
    p.add_run().add_picture(str(image_path), width=Inches(image_width_inches))


# ---------------------------------------------------------------------------
# Cell renderers
# ---------------------------------------------------------------------------
def _render_severity(cell, sev: str) -> None:
    p = cell.paragraphs[0]
    r = p.add_run(sev)
    r.bold = True
    r.font.color.rgb = severity_color(sev)


def _render_attack_vector(cell, vector: List[Tuple[str, str]]) -> None:
    clear_cell(cell)
    if not vector:
        p = cell.add_paragraph()
        p.add_run("No explicit attack vector stages identified in the referenced source.")
        return
    for idx, (stage, desc) in enumerate(vector):
        p = cell.add_paragraph()
        p.style = "List Bullet"
        r1 = p.add_run(f"{stage}: ")
        r1.bold = True
        p.add_run(desc)


def _render_attack_technique(cell, technique: str) -> None:
    clear_cell(cell)
    p = cell.add_paragraph()
    p.add_run(technique)


def _render_mitre(cell, mitre_rows: List[Tuple[str, str]]) -> None:
    clear_cell(cell)
    if not mitre_rows:
        p = cell.add_paragraph()
        p.add_run("No MITRE ATT&CK techniques were explicitly listed in the referenced source.")
        return
    tbl = cell.add_table(rows=1, cols=2)
    tbl.style = "Table Grid"
    hdr = tbl.rows[0].cells
    hdr[0].text = "ID"
    hdr[1].text = "Technique"
    set_cell_shading(hdr[0], "2E4057")
    set_cell_shading(hdr[1], "2E4057")
    for c in hdr:
        r = c.paragraphs[0].runs[0]
        r.bold = True
        r.font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
    for mid, name in mitre_rows:
        row = tbl.add_row().cells
        row[0].text = mid
        row[1].text = name


def _render_iocs(cell, iocs: Dict[str, List[str]]) -> None:
    clear_cell(cell)
    if not iocs:
        p = cell.add_paragraph()
        p.add_run("No indicators of compromise were explicitly listed in the referenced source.")
        return
    tbl = cell.add_table(rows=1, cols=2)
    tbl.style = "Table Grid"
    header = tbl.rows[0].cells
    header[0].text = "Type"
    header[1].text = "Value"
    for c in header:
        c.paragraphs[0].runs[0].bold = True
    for key, values in iocs.items():
        for value in values:
            row = tbl.add_row().cells
            row[0].text = key
            row[1].text = value


def _render_bullets(cell, items: List[str]) -> None:
    clear_cell(cell)
    for item in items:
        p = cell.add_paragraph()
        p.style = "List Bullet"
        p.add_run(item)


def _render_recommended(cell, actions: Dict[str, List[str]]) -> None:
    clear_cell(cell)
    for section, bullets in actions.items():
        p = cell.add_paragraph()
        r = p.add_run(section)
        r.bold = True
        for b in bullets:
            bp = cell.add_paragraph()
            bp.style = "List Bullet"
            bp.add_run(b)


def _render_refs(cell, refs: List[str]) -> None:
    clear_cell(cell)
    for idx, ref in enumerate(refs, start=1):
        cell.add_paragraph(f"{idx}. {ref}")


# ---------------------------------------------------------------------------
# Main render
# ---------------------------------------------------------------------------
def render_doc(
    data: TIAData,
    output_path: Path,
    footer_image_path: str = "",
    header_image_path: str = "",
) -> None:
    doc = Document()
    set_default_font(doc, "Calibri", 11)
    section = doc.sections[0]
    usable_width = section.page_width - section.left_margin - section.right_margin
    usable_emu = int(usable_width)
    usable_in = usable_emu / 914400.0

    main = doc.add_table(rows=0, cols=2)
    main.style = "Table Grid"
    main.autofit = False
    left_w = int(usable_emu * 0.24)
    right_w = usable_emu - left_w
    main.columns[0].width = left_w
    main.columns[1].width = right_w
    set_table_outer_border(main)

    ref_text = f"Ref:TIA{dt.datetime.now():%d%m%y} - 01"
    add_header_row(main, header_image_path, ref_text, image_width_inches=usable_in)
    add_title_row(main, data.title)
    add_blank_row(main)
    add_label_row(main, "Overview", lambda c: c.paragraphs[0].add_run(data.overview))
    add_label_row(main, "Threat Severity", lambda c: _render_severity(c, data.severity))
    add_label_row(main, "Targeted Region", lambda c: c.paragraphs[0].add_run(data.region))
    add_label_row(main, "Targeted Sector", lambda c: c.paragraphs[0].add_run(data.sector))
    add_label_row(main, "Attack Vector", lambda c: _render_attack_vector(c, data.attack_vector))
    add_label_row(main, "Attack Technique", lambda c: _render_attack_technique(c, data.attack_technique))
    add_label_row(main, "MITRE ATT&CK Technique", lambda c: _render_mitre(c, data.mitre))
    add_label_row(main, "IOCs", lambda c: _render_iocs(c, data.iocs))
    add_label_row(main, "Impacts", lambda c: _render_bullets(c, data.impacts))
    add_label_row(main, "Affected Products", lambda c: _render_bullets(c, data.affected_products))
    add_label_row(main, "Recommended Action", lambda c: _render_recommended(c, data.recommended_action))
    add_label_row(main, "References", lambda c: _render_refs(c, data.references))
    add_footer_image_row(main, footer_image_path, image_width_inches=usable_in)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    doc.save(output_path)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def sanitize_filename(name: str) -> str:
    cleaned = re.sub(r"[<>:\"/\\|?*]+", "", name).strip()
    cleaned = re.sub(r"\s+", " ", cleaned)
    return cleaned[:120] if cleaned else "Threat Intelligence Advisory"


def build_output_path(out_dir: Path, title: str) -> Path:
    safe = sanitize_filename(title)
    return out_dir / f"[TIA] {safe}.docx"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate TIA report from one or two URLs.")
    parser.add_argument("--url", required=True, nargs="+", help="One or two source URLs.")
    parser.add_argument("--title", default="", help="Optional title override.")
    parser.add_argument("--out-dir", default="output", help="Output directory for generated report.")
    parser.add_argument("--footer-image", default="", help="Optional footer image path.")
    parser.add_argument("--header-image", default="Header Image.png", help="Header image path.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if not (1 <= len(args.url) <= 2):
            raise ValueError("Provide one or two URLs using --url.")
        urls = [validate_url(u) for u in args.url]

        all_texts: List[str] = []
        first_page_title = ""
        for idx, url in enumerate(urls):
            page_title, text = fetch_url_text(url)
            if idx == 0:
                first_page_title = page_title
            all_texts.append(text)
        combined_text = " ".join(all_texts)

        data = build_tia_data(urls, combined_text, first_page_title, args.title)
        out_dir = Path(args.out_dir).resolve()
        out_path = build_output_path(out_dir, data.title)
        render_doc(data, out_path, args.footer_image, args.header_image)
        print(f"Report generated: {out_path}")
        return 0
    except Exception as exc:
        print(f"Error: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())