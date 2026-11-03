import threading, uuid, re, json, time
from flask import Flask, jsonify, request, render_template, send_file
import engine, report

app = Flask(__name__); engine.init(); STATE = {}
HOST_RE = re.compile(r'^(?=.{1,253}$)([a-z0-9][a-z0-9-]*\.)*[a-z0-9][a-z0-9-]*$', re.I)

@app.route('/')
def index(): return render_template('index.html')

@app.post('/api/scan')
def start():
    d = request.get_json(force=True); t = (d.get('target') or '').strip().lower(); demo = bool(d.get('demo'))
    if not d.get('consent'): return jsonify(error='Confirm you are authorised to scan this target.'), 400
    if not demo and not HOST_RE.match(t): return jsonify(error='Enter a valid IP, hostname or domain.'), 400
    sid = uuid.uuid4().hex[:8]; STATE[sid] = {'status':'running','progress':0,'log':[]}
    threading.Thread(target=engine.run_scan, args=(sid, t or 'demo.lab', demo, STATE[sid]), daemon=True).start()
    return jsonify(id=sid)

def load(sid):
    with engine.db() as c: r = c.execute('SELECT data FROM scans WHERE id=?', (sid,)).fetchone()
    return json.loads(r['data']) if r else None

@app.get('/api/scan/<sid>')
def status(sid):
    if sid in STATE and STATE[sid]['status'] != 'done': return jsonify(STATE[sid])
    r = load(sid)
    return (jsonify(status='done', progress=100, result=r) if r else (jsonify(error='Not found'), 404))

@app.delete('/api/scan/<sid>')
def delete(sid):
    with engine.db() as c: c.execute('DELETE FROM scans WHERE id=?', (sid,))
    return jsonify(ok=True)

@app.get('/api/history')
def history():
    with engine.db() as c: rows = c.execute('SELECT id,target,created,score,level,hosts,counts FROM scans ORDER BY created DESC').fetchall()
    return jsonify([{**dict(r), 'counts': json.loads(r['counts'])} for r in rows])

@app.get('/api/stats')
def stats():
    h = json.loads(history().data); tot = {'CRITICAL':0,'HIGH':0,'MEDIUM':0,'LOW':0}
    for r in h:
        for k, v in r['counts'].items(): tot[k] += v
    return jsonify(total=len(h), avg=round(sum(r['score'] for r in h)/len(h), 1) if h else 0,
                   hosts=sum(r['hosts'] for r in h), counts=tot, trend=[{'t':r['target'],'s':r['score']} for r in reversed(h[:10])], recent=h[:5])

@app.get('/api/report/<sid>')
def pdf(sid):
    r = load(sid)
    if not r: return jsonify(error='Not found'), 404
    return send_file(report.build(r), mimetype='application/pdf', as_attachment=True, download_name=f"netsecure_{r['target']}_{sid}.pdf")

if __name__ == '__main__': app.run(debug=False, port=5000)
