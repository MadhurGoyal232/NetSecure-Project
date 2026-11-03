"""NetSecure engine: discovery, scanning, CVE correlation, risk scoring, anomaly detection."""
import socket, re, subprocess, shutil, json, sqlite3, time, os, ipaddress
import xml.etree.ElementTree as ET
import concurrent.futures as cf
import requests, numpy as np

DB = os.path.join(os.path.dirname(__file__), 'netsecure.db')
NVD = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
PORTS = {21:'ftp',22:'ssh',23:'telnet',25:'smtp',53:'dns',80:'http',110:'pop3',111:'rpcbind',
         139:'netbios',143:'imap',443:'https',445:'smb',3306:'mysql',3389:'rdp',5432:'postgresql',
         5900:'vnc',6379:'redis',8080:'http-proxy',27017:'mongodb'}
WORDS = ['www','mail','dev','test','staging','api','admin','portal','vpn','ftp','blog']

# Rule-based checks: port -> (risk score, finding, remediation)
RULES = {
 23:(9.0,'Telnet sends credentials in plaintext','Disable Telnet and use SSH instead.'),
 21:(5.5,'FTP transmits data unencrypted','Replace FTP with SFTP/FTPS.'),
 445:(7.0,'SMB exposed to the network','Block port 445 at the firewall and patch SMB.'),
 139:(5.0,'NetBIOS exposed','Disable NetBIOS or restrict it to the LAN.'),
 3389:(6.5,'RDP exposed','Place RDP behind a VPN and enable MFA.'),
 3306:(6.0,'Database port reachable remotely','Bind MySQL to localhost or restrict by firewall.'),
 5432:(6.0,'Database port reachable remotely','Restrict PostgreSQL with firewall / pg_hba.conf.'),
 6379:(7.5,'Redis exposed (often no auth)','Bind Redis to localhost and set a password.'),
 27017:(7.5,'MongoDB exposed','Enable authentication and restrict network access.'),
 5900:(6.5,'VNC remote desktop exposed','Tunnel VNC over SSH/VPN, use strong passwords.'),
 111:(4.5,'RPC portmapper exposed','Disable rpcbind if not required.'),
}
# Small offline CVE sample (used for demo mode or when the NVD API is unreachable)
OFFLINE = [
 ('vsftpd','2.3.4','CVE-2011-2523',9.8,'Backdoor in vsftpd 2.3.4 allows remote command execution.'),
 ('openssh','4.7','CVE-2008-1657',6.5,'OpenSSH ForceCommand restriction bypass.'),
 ('openssh','7.2','CVE-2016-6210',5.9,'OpenSSH username enumeration via timing differences.'),
 ('apache','2.2.8','CVE-2011-3192',7.8,'Apache Range header denial of service (Apache Killer).'),
 ('apache','2.4.7','CVE-2017-7679',9.8,'Apache mod_mime buffer over-read.'),
 ('samba','3.0.20','CVE-2007-2447',9.8,'Samba username map script command execution.'),
 ('mysql','5.0','CVE-2012-2122',5.1,'MySQL authentication bypass via memcmp timing flaw.'),
 ('nginx','1.18','CVE-2021-23017',7.7,'nginx DNS resolver off-by-one heap write.'),
 ('redis','4.0','CVE-2018-11218',9.8,'Redis cmsgpack memory corruption.'),
]
DEMO = [
 ('demo.lab','192.168.56.101',[(21,'vsFTPd','2.3.4'),(22,'OpenSSH','4.7'),(23,'telnetd',''),(80,'Apache httpd','2.2.8'),
   (111,'rpcbind',''),(139,'Samba','3.0.20'),(445,'Samba','3.0.20'),(3306,'MySQL','5.0.51a'),(5900,'VNC','')]),
 ('www.demo.lab','192.168.56.102',[(22,'OpenSSH','8.9'),(80,'nginx','1.18.0'),(443,'nginx','1.18.0')]),
 ('dev.demo.lab','192.168.56.103',[(22,'OpenSSH','7.2p2'),(80,'Apache httpd','2.4.7'),(3306,'MySQL','5.7'),(6379,'Redis','4.0.1')]),
 ('mail.demo.lab','192.168.56.104',[(25,'Postfix',''),(143,'Dovecot',''),(443,'nginx','1.24.0')]),
]
BANNERS = {'OpenSSH':r'OpenSSH[_ ]([\d.]+)','vsFTPd':r'vsFTPd ([\d.]+)','ProFTPD':r'ProFTPD ([\d.]+)',
           'Apache httpd':r'Apache/([\d.]+)','nginx':r'nginx/([\d.]+)','Microsoft-IIS':r'IIS/([\d.]+)'}

def db():
    c = sqlite3.connect(DB); c.row_factory = sqlite3.Row; return c

def init():
    with db() as c:
        c.execute('CREATE TABLE IF NOT EXISTS scans(id TEXT PRIMARY KEY,target TEXT,created REAL,score REAL,level TEXT,hosts INT,counts TEXT,data TEXT)')
        c.execute('CREATE TABLE IF NOT EXISTS cve_cache(k TEXT PRIMARY KEY,v TEXT)')

def sev(s): return 'CRITICAL' if s >= 9 else 'HIGH' if s >= 7 else 'MEDIUM' if s >= 4 else 'LOW'

# ---------- discovery ----------
def discover(target, log):
    try: ipaddress.ip_address(target); return [(target, target)]
    except ValueError: pass
    names = {target}
    try:
        log('Querying certificate transparency (crt.sh)...')
        for e in requests.get(f'https://crt.sh/?q=%25.{target}&output=json', timeout=15).json():
            for n in e['name_value'].split('\n'):
                n = n.strip().lower().lstrip('*.')
                if n.endswith(target): names.add(n)
    except Exception: log('crt.sh unavailable - using DNS wordlist only')
    names |= {f'{w}.{target}' for w in WORDS}
    def res(h):
        try: return h, socket.gethostbyname(h)
        except Exception: return None
    with cf.ThreadPoolExecutor(30) as ex: live = [r for r in ex.map(res, sorted(names)) if r]
    return live[:8]

# ---------- scanning ----------
def parse_banner(b):
    for prod, rx in BANNERS.items():
        m = re.search(rx, b, re.I)
        if m: return prod, m.group(1)
    return '', ''

def probe(ip, port):
    try: s = socket.create_connection((ip, port), timeout=1.5)
    except Exception: return None
    b = ''
    try:
        if port in (80, 8080): s.sendall(b'HEAD / HTTP/1.0\r\n\r\n')
        s.settimeout(1.5); b = s.recv(300).decode(errors='ignore')
    except Exception: pass
    s.close(); return b

def scan_host(ip, log):
    if shutil.which('nmap'):
        log('Using Nmap service detection (-sV)')
        try:
            x = subprocess.run(['nmap','-sV','-Pn','-T4','--version-light','-p',','.join(map(str,PORTS)),'-oX','-',ip],
                               capture_output=True, text=True, timeout=240).stdout
            out = []
            for p in ET.fromstring(x).iter('port'):
                if p.find('state').get('state') != 'open': continue
                s = p.find('service'); s = s.attrib if s is not None else {}
                out.append({'port':int(p.get('portid')),'service':s.get('name',''),'product':s.get('product',''),'version':s.get('version','')})
            return out
        except Exception as e: log(f'Nmap failed ({e}); using built-in scanner')
    else: log('Nmap not installed - using built-in TCP scanner')
    with cf.ThreadPoolExecutor(30) as ex: res = list(ex.map(lambda p: (p, probe(ip, p)), PORTS))
    out = []
    for p, b in res:
        if b is None: continue
        prod, ver = parse_banner(b)
        out.append({'port':p,'service':PORTS[p],'product':prod,'version':ver})
    return out

# ---------- CVE correlation ----------
def offline(product, version):
    return [{'id':i,'cvss':c,'desc':d} for p,v,i,c,d in OFFLINE if p in product.lower() and version.startswith(v)]

def cves(product, version, demo, log):
    if demo: return offline(product, version)
    key = f'{product}|{version}'
    with db() as c:
        r = c.execute('SELECT v FROM cve_cache WHERE k=?', (key,)).fetchone()
    if r: return json.loads(r['v'])
    out = []
    try:
        h = {'apiKey': os.environ['NVD_API_KEY']} if os.environ.get('NVD_API_KEY') else {}
        data = requests.get(NVD, params={'keywordSearch':f'{product} {version}','resultsPerPage':5}, headers=h, timeout=12).json()
        for v in data.get('vulnerabilities', []):
            c_ = v['cve']; m = c_.get('metrics', {}); score = None
            for k in ('cvssMetricV31','cvssMetricV30','cvssMetricV2'):
                if k in m: score = m[k][0]['cvssData']['baseScore']; break
            d = next((x['value'] for x in c_['descriptions'] if x['lang']=='en'), '')
            out.append({'id':c_['id'],'cvss':score or 5.0,'desc':d[:170]})
        with db() as c: c.execute('INSERT OR REPLACE INTO cve_cache VALUES(?,?)', (key, json.dumps(out)))
    except Exception:
        log('NVD unreachable - using offline CVE sample'); out = offline(product, version)
    return out

# ---------- anomaly detection (Isolation Forest, advisory only) ----------
_model = None
def _vec(open_ports):
    return [1 if p in open_ports else 0 for p in sorted(PORTS)] + [len(open_ports)]

def anomaly(open_ports):
    global _model
    try:
        if _model is None:
            from sklearn.ensemble import IsolationForest
            rng = np.random.default_rng(42)
            prof = [[80,443],[22,80,443],[80],[443],[22],[25,110,143],[53],[22,80]]
            X = [_vec(set(prof[rng.integers(len(prof))])) for _ in range(300)]
            _model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42).fit(X)
        v = [_vec(set(open_ports))]
        return {'flag': bool(_model.predict(v)[0] == -1 or len(open_ports) >= 6), 'score': round(float(_model.decision_function(v)[0]), 3), 'method': 'IsolationForest'}
    except Exception:
        return {'flag': len(open_ports) >= 6, 'score': 0.0, 'method': 'heuristic'}

# ---------- analysis ----------
def analyze(host, ip, ports, demo, log):
    openset = {p['port'] for p in ports}; out = []
    for p in sorted(ports, key=lambda x: x['port']):
        p['service'] = p.get('service') or PORTS.get(p['port'], 'unknown'); f = []
        if p.get('product') and p.get('version'):
            for c in cves(p['product'], p['version'], demo, log):
                f.append({'id':c['id'],'title':c['desc'],'cvss':c['cvss'],'sev':sev(c['cvss']),'type':'CVE',
                          'fix':f"Upgrade {p['product']} to a supported, patched release."})
        if p['port'] in RULES:
            s, t, fx = RULES[p['port']]
            f.append({'id':f"RULE-{p['port']}",'title':t,'cvss':s,'sev':sev(s),'type':'Rule','fix':fx})
        if p['port'] == 80 and 443 not in openset:
            f.append({'id':'RULE-HTTP','title':'Website served without HTTPS','cvss':3.0,'sev':'LOW','type':'Rule','fix':'Enable HTTPS with a valid TLS certificate.'})
        p['findings'] = f
    fl = [f for p in ports for f in p['findings']]
    score = 0.0
    if fl:
        mx = max(f['cvss'] for f in fl); score = round(min(10, mx + min(1.5, 0.25 * (len(fl) - 1))), 1)
    an = anomaly(openset)
    return {'host':host,'ip':ip,'ports':ports,'score':score,'level':sev(score),'anomaly':an}

def run_scan(sid, target, demo, st):
    t0 = time.time(); log = lambda m: st['log'].append(m)
    try:
        log(f'Scan started for {target}'); st['progress'] = 5
        if demo: targets = [(h, ip) for h, ip, _ in DEMO]; log('Demo mode: simulated lab network')
        else: targets = discover(target, log)
        log(f'{len(targets)} host(s) to scan'); hosts = []
        for i, (h, ip) in enumerate(targets):
            st['progress'] = 15 + int(75 * i / max(1, len(targets))); log(f'Scanning {h} ({ip})')
            if demo:
                ports = [{'port':p,'service':PORTS.get(p,''),'product':pr,'version':v} for hh,_,pl in DEMO if hh==h for p,pr,v in pl]
                time.sleep(0.8)
            else: ports = scan_host(ip, log)
            hosts.append(analyze(h, ip, ports, demo, log))
        counts = {'CRITICAL':0,'HIGH':0,'MEDIUM':0,'LOW':0}
        fixes = []
        for h in hosts:
            for p in h['ports']:
                for f in p['findings']:
                    counts[f['sev']] += 1; fixes.append({**f,'host':h['host'],'port':p['port']})
        fixes.sort(key=lambda x: -x['cvss'])
        score = max([h['score'] for h in hosts], default=0)
        r = {'id':sid,'target':target,'demo':demo,'score':score,'level':sev(score),'counts':counts,'hosts':hosts,
             'top_fixes':fixes[:5],'duration':round(time.time()-t0,1),'created':time.time()}
        with db() as c:
            c.execute('INSERT INTO scans VALUES(?,?,?,?,?,?,?,?)',(sid,target,r['created'],score,r['level'],len(hosts),json.dumps(counts),json.dumps(r)))
        st['result'] = r; st['progress'] = 100; st['status'] = 'done'; log('Scan complete')
    except Exception as e:
        st['status'] = 'error'; st['error'] = str(e); log(f'Error: {e}')
