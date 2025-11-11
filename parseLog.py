#!/usr/bin/env python3
"""parseLog.py - Parser ModSecurity """
import re
import sqlite3
import hashlib
import argparse
from datetime import datetime, timezone
from dateutil import parser as dateparser
from pathlib import Path

# CONFIG
MODSEC_LOG = "/var/log/modsec_audit.log"

# Mappatura rule IDs -> tipo di attacco
ATTACK_TYPES = {
    "941": "XSS",
    "942": "SQL Injection",
    "943": "Session Fixation",
    "930": "LFI/RFI",
    "931": "RFI",
    "932": "RCE",
    "933": "PHP Injection",
    "920": "Protocol Violation",
    "921": "Protocol Attack"
}

# regex utili
ip_re = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}")
request_line_re = re.compile(
    r'(?P<method>GET|POST|PUT|DELETE|OPTIONS|HEAD)\s+(?P<path>/\S*)\s+HTTP/\d\.\d',
    re.I
)

def split_modsec_transactions(content):
    """Divide il log in transazioni"""
    parts = re.split(r'(?=\n--[-A-Za-z0-9]+--A--\n)', "\n" + content)
    return [p.strip("\n") for p in parts if p.strip()]

def extract_payload(text):
    payloads = []
    
    for m in re.finditer(r'found within (?:ARGS|ARGS_NAMES)[^:]*:\s*([^"]+?)(?:"|])', text):
        payload = m.group(1).strip()
        if len(payload) > 2 and not payload.startswith('10.10.'):
            payloads.append(payload)
    
    for m in re.finditer(r'Matched Data:\s*([^"]+?)(?:\s+found within|")', text):
        payload = m.group(1).strip()
        if len(payload) > 2:
            payloads.append(payload)
    
    for m in re.finditer(r'\[data\s+"([^"]+)"\]', text):
        payload = m.group(1).strip()
        if len(payload) > 3 and not re.match(r'^\d+\.\d+\.\d+\.\d+$', payload):
            if not payload.startswith('|') and 'Total Score' not in payload:
                payloads.append(payload)
    
    seen = set()
    unique = []
    for p in payloads:
        p_lower = p.lower()
        if p_lower not in seen:
            seen.add(p_lower)
            unique.append(p)
    
    return " | ".join(unique[:3]) if unique else ""

def classify_by_rules(rule_ids):
    """Classifica l'attacco basandosi sulle rule IDs"""
    if not rule_ids:
        return "Unknown"
    
    attack_types_found = {}
    
    for rule in rule_ids:
        rule_str = str(rule)
        for prefix, attack_type in ATTACK_TYPES.items():
            if rule_str.startswith(prefix):
                attack_types_found[attack_type] = attack_types_found.get(attack_type, 0) + 1
                break
    
    if not attack_types_found:
        return "ModSecurity Alert"
    
    if len(attack_types_found) > 1 and "Protocol Violation" in attack_types_found:
        del attack_types_found["Protocol Violation"]
    
    return max(attack_types_found.items(), key=lambda x: x[1])[0]

def parse_single_transaction(text, min_anomaly=5):
    """Parsa una singola transazione"""
    
    # Client IP (source)
    ip_match = re.search(r'\[([^\]]+)\]\s+([\d.]+)\s+\d+\s+[\d.]+\s+\d+', text)
    if ip_match:
        ip = ip_match.group(2)
    else:
        ip_m2 = ip_re.search(text)
        ip = ip_m2.group(0) if ip_m2 else ""
    
    # IP vittima (destination) - dalla riga A
    dest_ip_match = re.search(r'(\d{1,3}(?:\.\d{1,3}){3})\s+\d+\s+(\d{1,3}(?:\.\d{1,3}){3})\s+80', text)
    victim_ip = dest_ip_match.group(2) if dest_ip_match else ""
    
    # Timestamp
    ts_match = re.search(r'\[(?P<ts>\d{1,2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2} [+\-]\d{4})\]', text)
    if ts_match:
        try:
            ts_str = ts_match.group("ts")
            timestamp = datetime.strptime(ts_str, "%d/%b/%Y:%H:%M:%S %z")
        except Exception as e:
            timestamp = datetime.now(timezone.utc)
    else:
        timestamp = datetime.now(timezone.utc)

    # User-Agent
    ua_match = re.search(r'User-Agent:\s*(.+)', text, re.I)
    user_agent = ua_match.group(1).strip() if ua_match else ""
    
    # Request method e target
    req_m = request_line_re.search(text)
    if req_m:
        method = req_m.group("method")
        target = req_m.group("path")
    else:
        method = ""
        target = "-"
    
    # Host header per URL completo
    host_match = re.search(r'^Host:\s*(.+)$', text, re.MULTILINE | re.IGNORECASE)
    host = host_match.group(1).strip() if host_match else victim_ip
    
    # URL completo
    full_url = f"http://{host}{target}" if host and target != "-" else target
    
    # Rule IDs
    rule_ids = re.findall(r'\[id\s+"?(\d+)"?\]', text)
    # Unique ID - NUOVO
    unique_match = re.search(r'\[unique_id\s+"([^"]+)"\]', text)
    unique_id = unique_match.group(1) if unique_match else ""    
    # Anomaly Score
    anom_m = re.search(r'Total Score:\s*(\d+)', text)
    anomaly_score = int(anom_m.group(1)) if anom_m else 0
    
    # Filtro score
    if anomaly_score < min_anomaly:
        return None
    
    # Skip protocol violations senza altri attacchi
    if rule_ids:
        non_protocol_rules = [r for r in rule_ids if not r.startswith('920') and not r.startswith('949')]
        if not non_protocol_rules and anomaly_score < 10:
            return None
    
    # Classifica attacco
    attack_type = classify_by_rules(rule_ids)
    
    # Estrai payload
    payload = extract_payload(text)
    
    return {
        "timestamp": timestamp.isoformat(),
        "source_ip": ip,
        "victim_ip": victim_ip,
        "method": method,
        "user_agent": user_agent[:100],
        "attack_type": attack_type,
        "payload": payload[:500] if payload else "",
        "target": target[:200],
        "full_url": full_url[:300],
        "anomaly_score": anomaly_score,
        "rule_ids": ",".join(rule_ids) if rule_ids else "",
        "unique_id": unique_id
    }

def parse_modsec_audit(path, limit=0, min_anomaly=5):
    """Parsa il file modsec_audit.log"""
    out = []
    p = Path(path)
    
    if not p.exists():
        print(f"[!] File non trovato: {path}")
        return out
    
    content = p.read_text(errors="ignore")
    transactions = split_modsec_transactions(content)
    
    if limit and limit > 0:
        transactions = transactions[-limit:]
    
    for tx in transactions:
        rec = parse_single_transaction(tx, min_anomaly=min_anomaly)
        if rec:
            out.append(rec)
    
    return out

def save_to_database(records, db_path="attacks.db"):
    """Salva i record nel database SQLite evitando duplicati"""
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    
    # Crea tabella con nuovi campi
    cur.execute("""
        CREATE TABLE IF NOT EXISTS attacks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            victim_ip TEXT,
            method TEXT,
            user_agent TEXT,
            attack_type TEXT NOT NULL,
            payload TEXT,
            target TEXT,
            full_url TEXT,
            anomaly_score INTEGER,
            rule_ids TEXT,
            unique_id TEXT,
            payload_hash TEXT UNIQUE,
            archived INTEGER DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    cur.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS idx_unique_attack 
        ON attacks(payload_hash)
    """)
    
    inserted = 0
    skipped = 0
    
    for r in records:
        # Hash basato su IP + payload
        payload_hash = hashlib.md5(f"{r['source_ip']}{r['payload']}".encode()).hexdigest()
        
        cur.execute("SELECT COUNT(*) FROM attacks WHERE payload_hash = ?", (payload_hash,))
        
        if cur.fetchone()[0] == 0:
            cur.execute("""
                INSERT INTO attacks 
                (timestamp, source_ip, victim_ip, method, user_agent, attack_type, payload, target, full_url, anomaly_score, rule_ids, unique_id, payload_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                r['timestamp'], r['source_ip'], r['victim_ip'], r['method'], r['user_agent'],
                r['attack_type'], r['payload'], r['target'], r['full_url'], 
                r['anomaly_score'], r['rule_ids'], r['unique_id'], payload_hash
            ))
            inserted += 1
        else:
            skipped += 1
    
    conn.commit()
    conn.close()
    
    print(f"[+] Salvati {inserted} nuovi record nel database ({skipped} duplicati ignorati)")

def main():
    parser = argparse.ArgumentParser(
        description="Parser ModSecurity audit log"
    )
    parser.add_argument("--limit", type=int, default=0, help="Processa solo le ultime N transazioni (0 = tutte)")
    parser.add_argument("--min-anomaly", type=int, default=5, help="Soglia anomaly score minima (default: 5)")
    
    args = parser.parse_args()
    
    records = parse_modsec_audit(MODSEC_LOG, limit=args.limit, min_anomaly=args.min_anomaly)
    save_to_database(records)
    
    print(f"[+] Trovati {len(records)} attacchi (soglia score >= {args.min_anomaly})")
    
    
    if records:
        types = {}
        for r in records:
            types[r['attack_type']] = types.get(r['attack_type'], 0) + 1
        
        print("\n[*] Distribuzione attacchi:")
        for atype, count in sorted(types.items(), key=lambda x: -x[1]):
            print(f"    {atype}: {count}")

if __name__ == "__main__":
    main()
