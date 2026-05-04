#!/usr/bin/env python3
"""
ARP Guardian - Web UI
Run: python arp_web.py
Then open: http://localhost:5000
"""
 
from flask import Flask, jsonify, request, render_template_string
import threading, time, random, json
from datetime import datetime
from collections import defaultdict
import logging
 
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
 
try:
    from scapy.all import ARP, Ether, srp, sendp, sniff, conf as scapy_conf
    SCAPY_AVAILABLE = True
except:
    SCAPY_AVAILABLE = False
 
app = Flask(__name__)
 
# ── Global State ──────────────────────────────────────────
state = {
    "monitoring": False,
    "ip_mac_table": {},
    "alerts": [],
    "packets": [],
    "stats": {"total": 0, "spoofs": 0, "floods": 0, "gratuitous": 0, "new_hosts": 0},
    "start_time": None,
}
lock = threading.Lock()
flood_tracker = defaultdict(list)
monitor_thread = None
 
def ts():
    return datetime.now().strftime("%H:%M:%S")
 
def add_alert(atype, src_ip, src_mac, msg, severity="high"):
    with lock:
        state["alerts"].insert(0, {
            "time": ts(), "type": atype,
            "src_ip": src_ip, "src_mac": src_mac,
            "msg": msg, "severity": severity
        })
        if len(state["alerts"]) > 500:
            state["alerts"].pop()
 
def log_packet(src_ip, src_mac, dst_ip, op, status, color):
    op_str = "REQUEST" if op == 1 else "REPLY"
    with lock:
        state["packets"].insert(0, {
            "time": ts(), "op": op_str,
            "src_ip": src_ip, "src_mac": src_mac,
            "dst_ip": dst_ip, "status": status, "color": color
        })
        if len(state["packets"]) > 1000:
            state["packets"].pop()
 
def analyze_packet(pkt):
    if not hasattr(pkt, 'haslayer') or not pkt.haslayer(ARP):
        return
    arp = pkt[ARP]
    src_ip = arp.psrc; src_mac = arp.hwsrc.lower(); op = arp.op
    dst_ip = arp.pdst
 
    with lock:
        state["stats"]["total"] += 1
        if not state["monitoring"]:
            return
 
    now = time.time()
    with lock:
        flood_tracker[src_mac].append(now)
        flood_tracker[src_mac] = [t for t in flood_tracker[src_mac] if now - t < 1]
        count = len(flood_tracker[src_mac])
 
    if count >= 5:
        add_alert("ARP FLOOD", src_ip, src_mac, f"Flood: {count} pkts/sec from {src_mac}", "critical")
        log_packet(src_ip, src_mac, dst_ip, op, "FLOOD", "red")
        with lock: state["stats"]["floods"] += 1
        return
 
    with lock:
        known = state["ip_mac_table"].get(src_ip)
 
    bc = src_mac.lower() in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00")
    if known and known != src_mac and not bc:
        add_alert("SPOOF DETECTED", src_ip, src_mac,
                  f"{src_ip} claimed by {src_mac} — trusted MAC is {known}", "critical")
        log_packet(src_ip, src_mac, dst_ip, op, "SPOOF", "red")
        with lock: state["stats"]["spoofs"] += 1
    elif op == 2 and arp.psrc == arp.pdst:
        add_alert("GRATUITOUS ARP", src_ip, src_mac,
                  f"Unsolicited ARP from {src_ip} — possible cache poisoning", "medium")
        log_packet(src_ip, src_mac, dst_ip, op, "GRATUITOUS", "yellow")
        with lock: state["stats"]["gratuitous"] += 1
    else:
        with lock:
            if src_ip and src_ip not in state["ip_mac_table"] and not bc:
                state["ip_mac_table"][src_ip] = src_mac
                state["stats"]["new_hosts"] += 1
        log_packet(src_ip, src_mac, dst_ip, op, "NORMAL", "green")
 
def monitor_loop(iface, duration):
    try:
        sniff(iface=iface, filter="arp", prn=analyze_packet,
              timeout=duration, store=False,
              stop_filter=lambda p: not state["monitoring"])
    except Exception as e:
        add_alert("ERROR", "-", "-", str(e), "medium")
    with lock:
        state["monitoring"] = False
 
def inject_demo():
    """Inject synthetic packets for demo mode"""
    trusted = {
        "192.168.1.1":   "aa:bb:cc:11:22:33",
        "192.168.1.100": "de:ad:be:ef:00:01",
        "192.168.1.101": "de:ad:be:ef:00:02",
    }
    with lock:
        state["ip_mac_table"].update(trusted)
        state["monitoring"] = True
        state["start_time"] = ts()
 
    scenarios = [
        (1, "192.168.1.100", "de:ad:be:ef:00:01", "192.168.1.1"),
        (2, "192.168.1.1",   "aa:bb:cc:11:22:33", "192.168.1.100"),
        (2, "192.168.1.1",   "ba:d0:ca:fe:13:37", "192.168.1.100"),   # spoof
        (2, "192.168.1.200", "ca:fe:ba:be:00:ff", "192.168.1.200"),   # gratuitous
        (2, "192.168.1.100", "ee:ee:ee:ee:ee:ee", "192.168.1.1"),     # spoof
        (1, "192.168.1.55",  "11:22:33:44:55:66", "192.168.1.1"),     # new host
    ]
 
    for op, psrc, hwsrc, pdst in scenarios:
        if not state["monitoring"]: break
        pkt = Ether(src=hwsrc, dst="ff:ff:ff:ff:ff:ff") / ARP(op=op, psrc=psrc, hwsrc=hwsrc, pdst=pdst)
        analyze_packet(pkt)
        time.sleep(0.6)
 
    # Flood
    flood_mac = "ff:00:11:22:33:44"
    for i in range(12):
        if not state["monitoring"]: break
        pkt = Ether(src=flood_mac) / ARP(op=1, hwsrc=flood_mac,
            psrc=f"10.0.0.{i+1}", pdst="192.168.1.1")
        analyze_packet(pkt)
        time.sleep(0.04)
 
    time.sleep(0.5)
    with lock:
        state["monitoring"] = False
 
# ── Routes ────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template_string(HTML)
 
@app.route("/api/state")
def api_state():
    with lock:
        return jsonify({
            "monitoring": state["monitoring"],
            "stats": state["stats"],
            "alerts": state["alerts"][:50],
            "packets": state["packets"][:200],
            "hosts": state["ip_mac_table"],
            "start_time": state["start_time"],
            "scapy": SCAPY_AVAILABLE,
        })
 
@app.route("/api/demo", methods=["POST"])
def api_demo():
    global monitor_thread
    with lock:
        if state["monitoring"]:
            return jsonify({"ok": False, "msg": "Already running"})
        state["alerts"] = []
        state["stats"] = {"total":0,"spoofs":0,"floods":0,"gratuitous":0,"new_hosts":0}
        state["ip_mac_table"] = {}
    monitor_thread = threading.Thread(target=inject_demo, daemon=True)
    monitor_thread.start()
    return jsonify({"ok": True})
 
@app.route("/api/monitor", methods=["POST"])
def api_monitor():
    global monitor_thread
    data = request.json or {}
    iface = data.get("iface", "Wi-Fi")
    duration = int(data.get("duration", 60))
    with lock:
        if state["monitoring"]:
            return jsonify({"ok": False, "msg": "Already running"})
        state["monitoring"] = True
        state["start_time"] = ts()
        state["alerts"] = []
        state["stats"] = {"total":0,"spoofs":0,"floods":0,"gratuitous":0,"new_hosts":0}
    monitor_thread = threading.Thread(target=monitor_loop, args=(iface, duration), daemon=True)
    monitor_thread.start()
    return jsonify({"ok": True})
 
@app.route("/api/stop", methods=["POST"])
def api_stop():
    with lock:
        state["monitoring"] = False
    return jsonify({"ok": True})
 
@app.route("/api/scan", methods=["POST"])
def api_scan():
    data = request.json or {}
    subnet = data.get("subnet", "192.168.1.0/24")
    def do_scan():
        try:
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=subnet), timeout=3, verbose=False)
            with lock:
                for _, rcv in ans:
                    state["ip_mac_table"][rcv[ARP].psrc] = rcv[ARP].hwsrc.lower()
        except Exception as e:
            add_alert("SCAN ERROR", "-", "-", str(e), "medium")
    threading.Thread(target=do_scan, daemon=True).start()
    return jsonify({"ok": True, "msg": f"Scanning {subnet}..."})
 
@app.route("/api/simulate", methods=["POST"])
def api_simulate():
    data = request.json or {}
    iface = data.get("iface","Wi-Fi"); attack = data.get("attack","spoof")
    target = data.get("target","192.168.1.100"); gw = data.get("gateway","192.168.1.1")
    count = int(data.get("count", 10))
    spoofed_mac = "02:%02x:%02x:%02x:%02x:%02x" % tuple(random.randint(0,255) for _ in range(5))
 
    def do_sim():
        for i in range(count):
            try:
                if attack == "spoof":
                    pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=2,psrc=gw,hwsrc=spoofed_mac,pdst=target)
                elif attack == "gratuitous":
                    pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=2,psrc=target,hwsrc=spoofed_mac,pdst=target)
                else:
                    pkt = Ether(src=spoofed_mac)/ARP(op=1,hwsrc=spoofed_mac,
                        psrc=f"10.0.0.{random.randint(1,254)}",pdst=f"10.0.0.{random.randint(1,254)}")
                sendp(pkt, iface=iface, verbose=False)
                analyze_packet(pkt)
                time.sleep(0.05 if attack=="flood" else 0.2)
            except Exception as e:
                add_alert("SIM ERROR","-","-",str(e),"medium"); break
    threading.Thread(target=do_sim, daemon=True).start()
    return jsonify({"ok": True})
 
@app.route("/api/report")
def api_report():
    with lock:
        alerts = list(state["alerts"])
        hosts  = dict(state["ip_mac_table"])
        stats  = dict(state["stats"])
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    rows = "".join(f"<tr><td>{a['time']}</td><td class='sev-{a['severity']}'>{a['type']}</td><td>{a['src_ip']}</td><td>{a['src_mac']}</td><td>{a['msg']}</td></tr>" for a in alerts)
    host_rows = "".join(f"<tr><td>{ip}</td><td>{mac}</td></tr>" for ip,mac in hosts.items())
    html = f"""<!DOCTYPE html><html><head><meta charset='utf-8'>
<title>ARP Guardian Report</title>
<style>
body{{font-family:'Courier New',monospace;background:#0a0e1a;color:#c9d1e0;margin:0;padding:30px}}
h1{{color:#00d4ff;border-bottom:2px solid #00d4ff;padding-bottom:10px;font-size:28px}}
h2{{color:#7eb8f7;margin-top:30px;font-size:16px;text-transform:uppercase;letter-spacing:2px}}
.meta{{color:#5a6a7a;font-size:13px;margin-bottom:30px}}
.stats{{display:flex;gap:20px;flex-wrap:wrap;margin:20px 0}}
.stat{{background:#111827;border:1px solid #1e293b;border-radius:8px;padding:16px 24px;min-width:130px;text-align:center}}
.stat-val{{font-size:32px;font-weight:bold;color:#00d4ff}}
.stat-label{{font-size:11px;color:#5a6a7a;text-transform:uppercase;letter-spacing:1px;margin-top:4px}}
table{{width:100%;border-collapse:collapse;margin-top:12px;font-size:13px}}
th{{background:#111827;color:#7eb8f7;padding:10px 14px;text-align:left;border-bottom:2px solid #1e293b;text-transform:uppercase;letter-spacing:1px;font-size:11px}}
td{{padding:9px 14px;border-bottom:1px solid #1a2235;color:#c9d1e0}}
tr:hover td{{background:#111827}}
.sev-critical{{color:#ff4d4d;font-weight:bold}}
.sev-high{{color:#ff8c42}}
.sev-medium{{color:#ffd166}}
.footer{{margin-top:40px;color:#3a4a5a;font-size:12px;border-top:1px solid #1e293b;padding-top:16px}}
</style></head><body>
<h1>🛡 ARP GUARDIAN — SECURITY REPORT</h1>
<div class='meta'>Generated: {now}</div>
<h2>Summary</h2>
<div class='stats'>
  <div class='stat'><div class='stat-val'>{stats.get('total',0)}</div><div class='stat-label'>Total Packets</div></div>
  <div class='stat'><div class='stat-val' style='color:#ff4d4d'>{stats.get('spoofs',0)}</div><div class='stat-label'>Spoofs</div></div>
  <div class='stat'><div class='stat-val' style='color:#ff4d4d'>{stats.get('floods',0)}</div><div class='stat-label'>Floods</div></div>
  <div class='stat'><div class='stat-val' style='color:#ffd166'>{stats.get('gratuitous',0)}</div><div class='stat-label'>Gratuitous</div></div>
  <div class='stat'><div class='stat-val' style='color:#4ade80'>{stats.get('new_hosts',0)}</div><div class='stat-label'>New Hosts</div></div>
</div>
<h2>Alert Log</h2>
<table><tr><th>Time</th><th>Type</th><th>Source IP</th><th>Source MAC</th><th>Details</th></tr>{rows if rows else "<tr><td colspan='5' style='color:#3a4a5a;text-align:center'>No alerts recorded</td></tr>"}</table>
<h2>Known Hosts</h2>
<table><tr><th>IP Address</th><th>MAC Address</th></tr>{host_rows if host_rows else "<tr><td colspan='2' style='color:#3a4a5a;text-align:center'>No hosts recorded</td></tr>"}</table>
<div class='footer'>ARP Guardian | Educational Security Research Tool | Use only on networks you own or have permission to test.</div>
</body></html>"""
    return html, 200, {"Content-Type":"text/html"}
 
# ── HTML UI ───────────────────────────────────────────────
HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ARP Guardian</title>
<link href="https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&family=Inter:wght@300;400;500;600&display=swap" rel="stylesheet">
<style>
:root{
  --bg:#080c18;--bg2:#0d1224;--bg3:#111827;
  --border:#1a2540;--border2:#253050;
  --text:#c9d1e0;--text2:#7a8ba0;--text3:#3a4a5a;
  --accent:#00d4ff;--accent2:#0099cc;
  --red:#ff4d6d;--yellow:#ffd166;--green:#4ade80;--orange:#ff8c42;
  --font-mono:'Space Mono',monospace;
  --font:'Inter',sans-serif;
}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:var(--font);min-height:100vh;overflow-x:hidden}
 
/* scan lines effect */
body::before{content:'';position:fixed;inset:0;background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,212,255,.015) 2px,rgba(0,212,255,.015) 4px);pointer-events:none;z-index:1000}
 
/* Sidebar */
.sidebar{position:fixed;left:0;top:0;bottom:0;width:220px;background:var(--bg2);border-right:1px solid var(--border);display:flex;flex-direction:column;z-index:100}
.logo{padding:24px 20px;border-bottom:1px solid var(--border)}
.logo-title{font-family:var(--font-mono);font-size:13px;font-weight:700;color:var(--accent);letter-spacing:2px}
.logo-sub{font-size:11px;color:var(--text3);margin-top:3px;letter-spacing:1px}
.nav{padding:16px 0;flex:1}
.nav-item{display:flex;align-items:center;gap:10px;padding:11px 20px;cursor:pointer;font-size:13px;color:var(--text2);transition:all .15s;border-left:2px solid transparent;letter-spacing:.3px}
.nav-item:hover{color:var(--text);background:rgba(0,212,255,.04)}
.nav-item.active{color:var(--accent);background:rgba(0,212,255,.08);border-left-color:var(--accent)}
.nav-icon{font-size:15px;width:20px;text-align:center}
.status-dot{width:7px;height:7px;border-radius:50%;background:var(--text3);margin-left:auto;flex-shrink:0}
.status-dot.on{background:var(--green);box-shadow:0 0 6px var(--green);animation:pulse 1.5s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
 
/* Main */
.main{margin-left:220px;min-height:100vh;padding:30px}
.page{display:none}
.page.active{display:block}
 
/* Header */
.page-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:28px}
.page-title{font-family:var(--font-mono);font-size:18px;font-weight:700;color:var(--text);letter-spacing:1px}
.page-title span{color:var(--accent)}
 
/* Cards */
.cards{display:grid;grid-template-columns:repeat(5,1fr);gap:14px;margin-bottom:28px}
.card{background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:18px 20px;position:relative;overflow:hidden}
.card::before{content:'';position:absolute;top:0;left:0;right:0;height:2px}
.card.blue::before{background:linear-gradient(90deg,var(--accent),transparent)}
.card.red::before{background:linear-gradient(90deg,var(--red),transparent)}
.card.yellow::before{background:linear-gradient(90deg,var(--yellow),transparent)}
.card.green::before{background:linear-gradient(90deg,var(--green),transparent)}
.card.orange::before{background:linear-gradient(90deg,var(--orange),transparent)}
.card-val{font-family:var(--font-mono);font-size:30px;font-weight:700;margin-bottom:4px}
.card.blue .card-val{color:var(--accent)}
.card.red .card-val{color:var(--red)}
.card.yellow .card-val{color:var(--yellow)}
.card.green .card-val{color:var(--green)}
.card.orange .card-val{color:var(--orange)}
.card-label{font-size:11px;color:var(--text3);text-transform:uppercase;letter-spacing:1.5px}
 
/* Panel */
.panel{background:var(--bg2);border:1px solid var(--border);border-radius:10px;margin-bottom:20px;overflow:hidden}
.panel-head{padding:14px 20px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between}
.panel-title{font-family:var(--font-mono);font-size:12px;color:var(--text2);letter-spacing:2px;text-transform:uppercase}
.panel-body{padding:20px}
 
/* Alert table */
.alert-table{width:100%;border-collapse:collapse;font-size:12px;font-family:var(--font-mono)}
.alert-table th{color:var(--text3);padding:8px 12px;text-align:left;text-transform:uppercase;letter-spacing:1px;font-size:10px;border-bottom:1px solid var(--border)}
.alert-table td{padding:9px 12px;border-bottom:1px solid rgba(26,37,64,.5);vertical-align:middle}
.alert-table tr:last-child td{border-bottom:none}
.alert-table tr:hover td{background:rgba(0,212,255,.03)}
.sev-critical{color:var(--red)}
.sev-medium{color:var(--yellow)}
.sev-low{color:var(--green)}
.badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:10px;font-weight:700;letter-spacing:.5px}
.badge-critical{background:rgba(255,77,109,.15);color:var(--red);border:1px solid rgba(255,77,109,.3)}
.badge-medium{background:rgba(255,209,102,.1);color:var(--yellow);border:1px solid rgba(255,209,102,.25)}
 
/* Forms */
.form-grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}
.form-group{display:flex;flex-direction:column;gap:6px}
.form-label{font-size:11px;color:var(--text3);text-transform:uppercase;letter-spacing:1px}
.form-input{background:var(--bg3);border:1px solid var(--border2);border-radius:6px;padding:9px 12px;color:var(--text);font-family:var(--font-mono);font-size:13px;outline:none;transition:border .15s}
.form-input:focus{border-color:var(--accent)}
select.form-input option{background:var(--bg3)}
 
/* Buttons */
.btn{display:inline-flex;align-items:center;gap:8px;padding:10px 20px;border-radius:7px;border:none;cursor:pointer;font-size:13px;font-family:var(--font-mono);font-weight:700;letter-spacing:.5px;transition:all .15s}
.btn-primary{background:var(--accent);color:#000}
.btn-primary:hover{background:var(--accent2);transform:translateY(-1px)}
.btn-danger{background:var(--red);color:#fff}
.btn-danger:hover{opacity:.85}
.btn-outline{background:transparent;color:var(--accent);border:1px solid var(--accent)}
.btn-outline:hover{background:rgba(0,212,255,.08)}
.btn-sm{padding:7px 14px;font-size:12px}
.btn-row{display:flex;gap:10px;margin-top:18px;flex-wrap:wrap}
 
/* Host table */
.host-table{width:100%;border-collapse:collapse;font-size:12px;font-family:var(--font-mono)}
.host-table th{color:var(--text3);padding:8px 12px;text-align:left;text-transform:uppercase;letter-spacing:1px;font-size:10px;border-bottom:1px solid var(--border)}
.host-table td{padding:8px 12px;border-bottom:1px solid rgba(26,37,64,.5);color:var(--text2)}
.host-table td:first-child{color:var(--accent)}
 
/* Live indicator */
.live-badge{display:inline-flex;align-items:center;gap:6px;background:rgba(74,222,128,.1);border:1px solid rgba(74,222,128,.25);color:var(--green);padding:4px 12px;border-radius:20px;font-size:11px;font-family:var(--font-mono);font-weight:700}
.live-dot{width:6px;height:6px;border-radius:50%;background:var(--green);animation:pulse 1s infinite}
 
.empty{color:var(--text3);text-align:center;padding:40px;font-size:13px;font-family:var(--font-mono)}
 
/* Report btn */
.report-link{display:inline-flex;align-items:center;gap:8px;background:var(--bg3);border:1px solid var(--border2);color:var(--text2);padding:9px 18px;border-radius:7px;font-size:12px;font-family:var(--font-mono);cursor:pointer;text-decoration:none;transition:all .15s}
.report-link:hover{border-color:var(--accent);color:var(--accent)}
 
/* Toast */
.toast{position:fixed;bottom:24px;right:24px;background:var(--bg3);border:1px solid var(--accent);color:var(--text);padding:12px 20px;border-radius:8px;font-size:13px;font-family:var(--font-mono);z-index:9999;transform:translateY(100px);opacity:0;transition:all .3s}
.toast.show{transform:translateY(0);opacity:1}
.toast.error{border-color:var(--red)}
</style>
</head>
<body>
 
<div class="sidebar">
  <div class="logo">
    <div class="logo-title">ARP GUARDIAN</div>
    <div class="logo-sub">NETWORK MONITOR</div>
  </div>
  <nav class="nav">
    <div class="nav-item active" onclick="nav('dashboard')"><span class="nav-icon">📊</span>Dashboard<span class="status-dot" id="dot"></span></div>
    <div class="nav-item" onclick="nav('packets')"><span class="nav-icon">📦</span>Packet Log</div>
    <div class="nav-item" onclick="nav('monitor')"><span class="nav-icon">📡</span>Monitor</div>
    <div class="nav-item" onclick="nav('simulate')"><span class="nav-icon">⚡</span>Simulate</div>
    <div class="nav-item" onclick="nav('hosts')"><span class="nav-icon">🖥️</span>Known Hosts</div>
    <div class="nav-item" onclick="nav('report')"><span class="nav-icon">📋</span>Report</div>
  </nav>
</div>
 
<div class="main">
 
<!-- DASHBOARD -->
<div class="page active" id="page-dashboard">
  <div class="page-header">
    <div class="page-title"><span>//</span> DASHBOARD</div>
    <div id="live-badge" style="display:none" class="live-badge"><span class="live-dot"></span>MONITORING LIVE</div>
  </div>
  <div class="cards">
    <div class="card blue"><div class="card-val" id="stat-total">0</div><div class="card-label">Total Packets</div></div>
    <div class="card red"><div class="card-val" id="stat-spoofs">0</div><div class="card-label">Spoofs Caught</div></div>
    <div class="card red"><div class="card-val" id="stat-floods">0</div><div class="card-label">Floods Caught</div></div>
    <div class="card yellow"><div class="card-val" id="stat-gratuitous">0</div><div class="card-label">Gratuitous ARP</div></div>
    <div class="card green"><div class="card-val" id="stat-hosts">0</div><div class="card-label">Known Hosts</div></div>
  </div>
 
  <div class="panel">
    <div class="panel-head">
      <div class="panel-title">⚠ Alert Log</div>
      <button class="btn btn-sm btn-outline" onclick="clearAlerts()">Clear</button>
    </div>
    <div class="panel-body" style="padding:0">
      <table class="alert-table">
        <thead><tr><th>Time</th><th>Type</th><th>Source IP</th><th>Source MAC</th><th>Details</th></tr></thead>
        <tbody id="alert-body"><tr><td colspan="5" class="empty">No alerts yet. Start monitoring or run demo.</td></tr></tbody>
      </table>
    </div>
  </div>
</div>
 
<!-- PACKET LOG -->
<div class="page" id="page-packets">
  <div class="page-header">
    <div class="page-title"><span>//</span> PACKET LOG</div>
    <div style="display:flex;gap:10px;align-items:center">
      <div style="display:flex;gap:8px;font-size:12px;font-family:var(--font-mono)">
        <span style="color:var(--red)">■ SPOOF/FLOOD</span>
        <span style="color:var(--yellow)">■ GRATUITOUS</span>
        <span style="color:var(--green)">■ NORMAL</span>
      </div>
      <button class="btn btn-sm btn-outline" onclick="clearPackets()">Clear</button>
    </div>
  </div>
  <div class="panel">
    <div class="panel-head">
      <div class="panel-title">All Captured ARP Packets</div>
      <div id="pkt-count" style="font-size:12px;color:var(--text3);font-family:var(--font-mono)">0 packets</div>
    </div>
    <div class="panel-body" style="padding:0">
      <table class="alert-table">
        <thead>
          <tr>
            <th>Time</th>
            <th>Type</th>
            <th>Status</th>
            <th>Source IP</th>
            <th>Source MAC</th>
            <th>Destination IP</th>
          </tr>
        </thead>
        <tbody id="packet-body"><tr><td colspan="6" class="empty">No packets yet. Start monitoring or run demo.</td></tr></tbody>
      </table>
    </div>
  </div>
</div>
 
<!-- MONITOR -->
<div class="page" id="page-monitor">
  <div class="page-header"><div class="page-title"><span>//</span> MONITOR</div></div>
 
  <div class="panel">
    <div class="panel-head"><div class="panel-title">Quick Start — Demo Mode</div></div>
    <div class="panel-body">
      <p style="font-size:13px;color:var(--text2);margin-bottom:16px;line-height:1.7">No root or network needed. Runs offline with synthetic ARP attack packets so you can see all detections working immediately.</p>
      <button class="btn btn-primary" onclick="runDemo()">▶ Run Demo</button>
    </div>
  </div>
 
  <div class="panel">
    <div class="panel-head"><div class="panel-title">Scan Network (Build Trusted Table)</div></div>
    <div class="panel-body">
      <div class="form-grid">
        <div class="form-group">
          <label class="form-label">Subnet</label>
          <input class="form-input" id="scan-subnet" value="192.168.1.0/24" placeholder="e.g. 192.168.1.0/24">
        </div>
      </div>
      <div class="btn-row">
        <button class="btn btn-outline" onclick="runScan()">🔍 Scan Network</button>
      </div>
    </div>
  </div>
 
  <div class="panel">
    <div class="panel-head"><div class="panel-title">Live Monitor</div></div>
    <div class="panel-body">
      <div class="form-grid">
        <div class="form-group">
          <label class="form-label">Network Interface</label>
          <input class="form-input" id="mon-iface" value="Wi-Fi" placeholder="e.g. Wi-Fi, Ethernet, eth0">
        </div>
        <div class="form-group">
          <label class="form-label">Duration (seconds)</label>
          <input class="form-input" id="mon-duration" type="number" value="60">
        </div>
      </div>
      <div class="btn-row">
        <button class="btn btn-primary" onclick="startMonitor()">📡 Start Monitor</button>
        <button class="btn btn-danger" onclick="stopMonitor()">⏹ Stop</button>
      </div>
      <p style="font-size:11px;color:var(--text3);margin-top:12px">⚠ Requires admin/sudo + Npcap (Windows) or root (Linux/Mac)</p>
    </div>
  </div>
</div>
 
<!-- SIMULATE -->
<div class="page" id="page-simulate">
  <div class="page-header"><div class="page-title"><span>//</span> ATTACK SIMULATOR</div></div>
  <div class="panel">
    <div class="panel-head"><div class="panel-title">Configure Attack</div></div>
    <div class="panel-body">
      <div class="form-grid">
        <div class="form-group">
          <label class="form-label">Attack Type</label>
          <select class="form-input" id="sim-attack">
            <option value="spoof">Spoof (Man-in-the-Middle)</option>
            <option value="gratuitous">Gratuitous ARP</option>
            <option value="flood">ARP Flood</option>
          </select>
        </div>
        <div class="form-group">
          <label class="form-label">Interface</label>
          <input class="form-input" id="sim-iface" value="Wi-Fi">
        </div>
        <div class="form-group">
          <label class="form-label">Target IP</label>
          <input class="form-input" id="sim-target" value="192.168.1.100">
        </div>
        <div class="form-group">
          <label class="form-label">Gateway IP</label>
          <input class="form-input" id="sim-gateway" value="192.168.1.1">
        </div>
        <div class="form-group">
          <label class="form-label">Packet Count</label>
          <input class="form-input" id="sim-count" type="number" value="10">
        </div>
      </div>
      <div class="btn-row">
        <button class="btn btn-danger" onclick="runSimulate()">⚡ Launch Simulation</button>
      </div>
      <p style="font-size:11px;color:var(--text3);margin-top:14px">⚠ Use only on networks you own or have explicit permission to test. Sending packets on public/corporate networks is illegal.</p>
    </div>
  </div>
</div>
 
<!-- HOSTS -->
<div class="page" id="page-hosts">
  <div class="page-header"><div class="page-title"><span>//</span> KNOWN HOSTS</div></div>
  <div class="panel">
    <div class="panel-head"><div class="panel-title">Trusted IP → MAC Table</div></div>
    <div class="panel-body" style="padding:0">
      <table class="host-table">
        <thead><tr><th>IP Address</th><th>MAC Address</th></tr></thead>
        <tbody id="host-body"><tr><td colspan="2" class="empty">No hosts yet. Run a scan or start monitoring.</td></tr></tbody>
      </table>
    </div>
  </div>
</div>
 
<!-- REPORT -->
<div class="page" id="page-report">
  <div class="page-header"><div class="page-title"><span>//</span> REPORT</div></div>
  <div class="panel">
    <div class="panel-head"><div class="panel-title">Generate Report</div></div>
    <div class="panel-body">
      <p style="font-size:13px;color:var(--text2);margin-bottom:20px;line-height:1.7">Generate a full HTML security report including all alerts, known hosts, and packet statistics. Opens in a new tab — save it as a file from there.</p>
      <a class="report-link" href="/api/report" target="_blank">📋 Open Full Report in New Tab</a>
      <p style="font-size:11px;color:var(--text3);margin-top:12px">In the report tab: press Ctrl+S (Windows) or Cmd+S (Mac) to save as HTML file.</p>
    </div>
  </div>
</div>
 
</div><!-- end main -->
 
<div class="toast" id="toast"></div>
 
<script>
let currentPage = 'dashboard';
 
function nav(page) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  document.getElementById('page-' + page).classList.add('active');
  event.currentTarget.classList.add('active');
  currentPage = page;
}
 
function showToast(msg, error=false) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.className = 'toast show' + (error ? ' error' : '');
  setTimeout(() => t.className = 'toast', 3000);
}
 
function clearAlerts() {
  document.getElementById('alert-body').innerHTML = '<tr><td colspan="5" class="empty">Cleared.</td></tr>';
}
 
async function runDemo() {
  const r = await fetch('/api/demo', {method:'POST'});
  const d = await r.json();
  if (d.ok) { showToast('Demo started! Watch the Dashboard.'); nav('dashboard'); setTimeout(()=>{document.querySelectorAll('.nav-item')[0].click()},10); }
  else showToast(d.msg, true);
}
 
async function runScan() {
  const subnet = document.getElementById('scan-subnet').value;
  const r = await fetch('/api/scan', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({subnet})});
  const d = await r.json();
  showToast(d.ok ? '🔍 Scanning... check Hosts tab in ~5s' : d.msg, !d.ok);
}
 
async function startMonitor() {
  const iface = document.getElementById('mon-iface').value;
  const duration = document.getElementById('mon-duration').value;
  const r = await fetch('/api/monitor', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({iface, duration})});
  const d = await r.json();
  if (d.ok) { showToast('Monitoring started!'); nav('dashboard'); }
  else showToast(d.msg, true);
}
 
async function stopMonitor() {
  await fetch('/api/stop', {method:'POST'});
  showToast('Monitoring stopped.');
}
 
async function runSimulate() {
  const body = {
    iface: document.getElementById('sim-iface').value,
    attack: document.getElementById('sim-attack').value,
    target: document.getElementById('sim-target').value,
    gateway: document.getElementById('sim-gateway').value,
    count: document.getElementById('sim-count').value,
  };
  const r = await fetch('/api/simulate', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body)});
  const d = await r.json();
  if (d.ok) { showToast('Simulation launched! Check Dashboard.'); }
  else showToast(d.msg, true);
}
 
const SEV_BADGE = {
  critical: '<span class="badge badge-critical">CRITICAL</span>',
  high:     '<span class="badge badge-critical">HIGH</span>',
  medium:   '<span class="badge badge-medium">MEDIUM</span>',
};
 
function clearPackets() {
  document.getElementById('packet-body').innerHTML = '<tr><td colspan="6" class="empty">Cleared.</td></tr>';
  document.getElementById('pkt-count').textContent = '0 packets';
}
 
const STATUS_COLOR = { SPOOF:'var(--red)', FLOOD:'var(--red)', GRATUITOUS:'var(--yellow)', NORMAL:'var(--green)' };
 
async function poll() {
  try {
    const r = await fetch('/api/state');
    const d = await r.json();
 
    // stats
    document.getElementById('stat-total').textContent = d.stats.total;
    document.getElementById('stat-spoofs').textContent = d.stats.spoofs;
    document.getElementById('stat-floods').textContent = d.stats.floods;
    document.getElementById('stat-gratuitous').textContent = d.stats.gratuitous;
    document.getElementById('stat-hosts').textContent = Object.keys(d.hosts).length;
 
    // live badge
    const badge = document.getElementById('live-badge');
    const dot   = document.getElementById('dot');
    badge.style.display = d.monitoring ? 'inline-flex' : 'none';
    dot.className = 'status-dot' + (d.monitoring ? ' on' : '');
 
    // alerts
    if (d.alerts.length > 0) {
      const rows = d.alerts.map(a =>
        `<tr><td>${a.time}</td><td>${SEV_BADGE[a.severity]||''} ${a.type}</td><td>${a.src_ip}</td><td>${a.src_mac}</td><td style="color:var(--text2)">${a.msg}</td></tr>`
      ).join('');
      document.getElementById('alert-body').innerHTML = rows;
    }
 
    // packet log
    if (d.packets && d.packets.length > 0) {
      document.getElementById('pkt-count').textContent = d.stats.total + ' packets total';
      const prows = d.packets.map(p => {
        const col = STATUS_COLOR[p.status] || 'var(--text2)';
        const opBadge = p.op === 'REQUEST'
          ? `<span style="color:var(--accent);font-size:10px">WHO-HAS</span>`
          : `<span style="color:var(--orange);font-size:10px">IS-AT</span>`;
        return `<tr>
          <td>${p.time}</td>
          <td>${opBadge}</td>
          <td><span style="color:${col};font-weight:700;font-size:11px">${p.status}</span></td>
          <td style="color:var(--accent)">${p.src_ip}</td>
          <td style="color:var(--text2)">${p.src_mac}</td>
          <td style="color:var(--text3)">${p.dst_ip}</td>
        </tr>`;
      }).join('');
      document.getElementById('packet-body').innerHTML = prows;
    }
 
    // hosts
    const hosts = Object.entries(d.hosts);
    if (hosts.length > 0) {
      document.getElementById('host-body').innerHTML = hosts.map(([ip,mac]) =>
        `<tr><td>${ip}</td><td>${mac}</td></tr>`).join('');
    }
  } catch(e) {}
  setTimeout(poll, 1500);
}
 
poll();
</script>
</body>
</html>"""
 
if __name__ == "__main__":
    import webbrowser, os
    port = 5000
    print("\n" + "="*55)
    print("  🛡  ARP GUARDIAN — Web UI")
    print("="*55)
    print(f"  Open your browser and go to:")
    print(f"  👉  http://localhost:{port}")
    print("="*55 + "\n")
    threading.Timer(1.2, lambda: webbrowser.open(f"http://localhost:{port}")).start()
    app.run(host="0.0.0.0", port=port, debug=False)