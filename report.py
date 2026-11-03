import io
from xml.sax.saxutils import escape as E
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

COL = {'CRITICAL':'#b91c1c','HIGH':'#c2410c','MEDIUM':'#a16207','LOW':'#15803d'}

def build(r):
    buf = io.BytesIO(); S = getSampleStyleSheet()
    doc = SimpleDocTemplate(buf, pagesize=A4, title='NetSecure Report', leftMargin=36, rightMargin=36)
    P = lambda t, s='BodyText': Paragraph(t, S[s])
    el = [P('NetSecure Security Report','Title'),
          P(f"<b>Target:</b> {E(r['target'])} &nbsp; <b>Hosts:</b> {len(r['hosts'])} &nbsp; <b>Duration:</b> {r['duration']}s"),
          P(f"<b>Overall risk:</b> <font color='{COL[r['level']]}'>{r['level']} ({r['score']}/10)</font>"),
          P(' &nbsp; '.join(f"{k}: {v}" for k, v in r['counts'].items())), Spacer(1, 10), P('Top priority fixes','Heading2')]
    for f in r['top_fixes']:
        el.append(P(f"<b>{E(f['host'])}:{f['port']}</b> - {E(f['id'])} ({f['cvss']}) - {E(f['fix'])}"))
    for h in r['hosts']:
        el += [Spacer(1, 10), P(f"{E(h['host'])} ({h['ip']}) - <font color='{COL[h['level']]}'>{h['level']} {h['score']}/10</font>", 'Heading2')]
        if h['anomaly']['flag']: el.append(P('<i>Anomaly advisory: unusual port/service combination.</i>'))
        rows = [['Port','Service','Finding','CVSS','Fix']]
        for p in h['ports']:
            sv = f"{p['service']} {p.get('product','')} {p.get('version','')}".strip()
            if not p['findings']: rows.append([str(p['port']), P(E(sv)), 'No findings', '-', '-'])
            for f in p['findings']:
                rows.append([str(p['port']), P(E(sv)), P(E(f"{f['id']}: {f['title']}")), str(f['cvss']), P(E(f['fix']))])
        t = Table(rows, colWidths=[35, 80, 220, 35, 160], repeatRows=1)
        t.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),colors.HexColor('#0f4c5c')),('TEXTCOLOR',(0,0),(-1,0),colors.white),
            ('GRID',(0,0),(-1,-1),.4,colors.grey),('VALIGN',(0,0),(-1,-1),'TOP'),('FONTSIZE',(0,0),(-1,-1),8)]))
        el.append(t)
    el += [Spacer(1, 14), P('Scanned only with authorisation. NetSecure does not exploit vulnerabilities; the anomaly layer is advisory.', 'Italic')]
    doc.build(el); buf.seek(0); return buf
