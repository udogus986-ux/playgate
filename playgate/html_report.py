"""Single-file, shareable HTML report (`--format html`).

The report embeds its data as JSON and renders it with DOM text nodes, never
innerHTML with finding content: evidence is quoted straight from scanned files,
so a file containing `</script><img onerror=…>` must not execute when someone
opens the report. `</` is escaped inside the embedded JSON for the same reason.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from . import __version__
from .models import Report
from .report import BAND_BLURB, _finding_json, release_json
from .standards import SCOPE

_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>playgate report</title>
<style>
:root{--bg:#f6f6f8;--panel:#fff;--panel2:#f0f0f3;--border:#e0e0e6;--text:#1b1b22;--dim:#63636e;
--accent:#2f6fe4;--critical:#d92d34;--high:#e8590c;--medium:#c98a00;--low:#2f7fd6;--info:#8b8b96;--ok:#2b9a5c;
--mono:ui-monospace,Consolas,Menlo,monospace}
@media (prefers-color-scheme:dark){:root{--bg:#101014;--panel:#17171c;--panel2:#1d1d24;--border:#2a2a33;
--text:#e8e8ec;--dim:#9a9aa5;--info:#70707c}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);
font:15px/1.55 system-ui,"Segoe UI",Roboto,sans-serif}
.wrap{max-width:1000px;margin:0 auto;padding:24px 16px 60px}
h1{font-size:22px;margin:0}h2{font-size:13px;text-transform:uppercase;letter-spacing:.1em;color:var(--dim);margin:28px 0 12px}
.meta{color:var(--dim);font-size:13px;margin:6px 0 18px;font-family:var(--mono);word-break:break-all}
.grid{display:flex;gap:14px;flex-wrap:wrap}.card{flex:1;min-width:260px;background:var(--panel);
border:1px solid var(--border);border-radius:10px;padding:14px}
.chip{display:inline-block;border:1px solid var(--border);background:var(--panel2);border-radius:99px;
padding:3px 10px;font-size:12px;font-weight:600;margin:0 6px 6px 0}.zero{opacity:.4;font-weight:400}
.big{font-size:22px;font-weight:700}.verdict{font-weight:700}
.gate{display:flex;gap:10px;font-size:14px;padding:3px 0}.gate .st{width:92px;font-family:var(--mono);font-size:12px}
.FAIL{color:var(--critical)}.PASS{color:var(--ok)}.NEEDS-INFO{color:var(--medium)}
.bar{display:flex;gap:8px;flex-wrap:wrap;margin:12px 0}
select,input{background:var(--panel2);color:var(--text);border:1px solid var(--border);border-radius:8px;padding:7px 10px;font:inherit;font-size:13px}
.f{background:var(--panel);border:1px solid var(--border);border-left-width:4px;border-radius:10px;margin-bottom:10px}
.f summary{cursor:pointer;padding:11px 14px;display:flex;gap:10px;align-items:center;list-style:none}
.f summary::-webkit-details-marker{display:none}
.sev{font-size:11px;font-weight:700;color:#fff;border-radius:5px;padding:2px 8px;min-width:70px;text-align:center}
.ttl{flex:1;font-weight:600}.loc{font-family:var(--mono);font-size:12px;color:var(--dim)}
.body{border-top:1px solid var(--border);padding:12px 14px;font-size:14px}
.row{margin-bottom:8px}.lab{color:var(--dim);font-size:11px;text-transform:uppercase;letter-spacing:.06em}
.ev{font-family:var(--mono);font-size:13px;background:var(--panel2);border:1px solid var(--border);
border-radius:6px;padding:6px 10px;white-space:pre-wrap;word-break:break-all}
a{color:var(--accent)}ul{margin:0;padding-left:18px;color:var(--dim);font-size:13px}
</style>
</head>
<body>
<div class="wrap" id="app"></div>
<script type="application/json" id="data">__DATA__</script>
<script>
(function(){
"use strict";
var D=JSON.parse(document.getElementById("data").textContent);
var SEV=["CRITICAL","HIGH","MEDIUM","LOW","INFO"];
var COL={CRITICAL:"var(--critical)",HIGH:"var(--high)",MEDIUM:"var(--medium)",LOW:"var(--low)",INFO:"var(--info)"};
function el(tag,attrs,kids){var n=document.createElement(tag);attrs=attrs||{};
 for(var k in attrs){if(k==="text")n.textContent=attrs[k];else if(k==="style")n.style.cssText=attrs[k];else n.setAttribute(k,attrs[k]);}
 (kids||[]).forEach(function(c){if(c)n.appendChild(c);});return n;}
var app=document.getElementById("app");
app.appendChild(el("h1",{text:"playgate report"}));
app.appendChild(el("div",{"class":"meta",text:D.root+"  ·  "+D.kind+"  ·  "+(D.platforms.join(" + ")||"unknown")+"  ·  "+D.generated+"  ·  playgate "+D.version}));
var counts=el("div");SEV.forEach(function(s){counts.appendChild(el("span",{"class":"chip"+(D.counts[s]?"":" zero"),text:s+" "+D.counts[s]}));});
var risk=el("div",{},[el("div",{"class":"big",text:D.rejection_band+"  "+D.rejection_score+"/100"}),el("div",{style:"color:var(--dim);font-size:13px",text:D.blurb})]);
app.appendChild(el("div",{"class":"grid"},[el("div",{"class":"card"},[el("h2",{text:"Findings",style:"margin-top:0"}),counts]),
 el("div",{"class":"card"},[el("h2",{text:"Google Play rejection risk",style:"margin-top:0"}),risk])]));
if(D.release.length){app.appendChild(el("h2",{text:"Release readiness"}));
 var g=el("div",{"class":"grid"});D.release.forEach(function(st){var c=el("div",{"class":"card"});
  c.appendChild(el("div",{"class":"verdict "+(st.verdict==="NO-GO"?"FAIL":"PASS"),text:st.name+" — "+st.verdict}));
  st.phases.forEach(function(p){c.appendChild(el("div",{style:"margin-top:8px;font-size:12px;color:var(--dim)",text:p.phase}));
   p.gates.forEach(function(x){c.appendChild(el("div",{"class":"gate"},[el("span",{"class":"st "+x.status,text:x.status}),el("span",{text:x.name})]));});});
  g.appendChild(c);});app.appendChild(g);}
app.appendChild(el("h2",{text:"Findings"}));
var sevSel=el("select");SEV.forEach(function(s){sevSel.appendChild(el("option",{value:s,text:s==="INFO"?"All severities":s+" and above"}));});sevSel.value="INFO";
var catSel=el("select");[["all","All categories"],["security","Security"],["policy","Policy"]].forEach(function(o){catSel.appendChild(el("option",{value:o[0],text:o[1]}));});
var q=el("input",{type:"search",placeholder:"Filter…"});
app.appendChild(el("div",{"class":"bar"},[sevSel,catSel,q]));
var list=el("div");app.appendChild(list);
function render(){list.textContent="";var min=SEV.indexOf(sevSel.value),term=q.value.toLowerCase(),shown=0;
 D.findings.forEach(function(f){if(SEV.indexOf(f.severity)>min)return;if(catSel.value!=="all"&&f.category!==catSel.value)return;
  if(term&&(f.id+" "+f.title+" "+f.location+" "+f.why).toLowerCase().indexOf(term)<0)return;shown++;
  var body=el("div",{"class":"body"});
  if(f.evidence)body.appendChild(el("div",{"class":"row"},[el("div",{"class":"lab",text:"Found"}),el("div",{"class":"ev",text:f.evidence})]));
  body.appendChild(el("div",{"class":"row"},[el("div",{"class":"lab",text:"Why"}),el("div",{text:f.why})]));
  body.appendChild(el("div",{"class":"row"},[el("div",{"class":"lab",text:"Fix"}),el("div",{text:f.fix})]));
  if(f.standards){var s=el("div");(f.standards.owasp_mobile_top10_2024?["OWASP "+f.standards.owasp_mobile_top10_2024]:[]).concat(f.standards.masvs||[],f.standards.cwe||[]).forEach(function(t){s.appendChild(el("span",{"class":"chip",text:t}));});
   body.appendChild(el("div",{"class":"row"},[el("div",{"class":"lab",text:"Standards"}),s]));}
  if(f.refs&&f.refs.length&&/^https:\\/\\//.test(f.refs[0]))body.appendChild(el("div",{"class":"row"},[el("div",{"class":"lab",text:"Reference"}),el("a",{href:f.refs[0],target:"_blank",rel:"noopener noreferrer",text:f.refs[0]})]));
  body.appendChild(el("div",{"class":"loc",text:f.id+" · "+f.category}));
  var d=el("details",{"class":"f",style:"border-left-color:"+COL[f.severity]},[el("summary",{},[el("span",{"class":"sev",style:"background:"+COL[f.severity],text:f.severity}),el("span",{"class":"ttl",text:f.title}),el("span",{"class":"loc",text:f.location})]),body]);
  list.appendChild(d);});
 if(!shown)list.appendChild(el("div",{style:"color:var(--dim);padding:20px 0",text:D.findings.length?"No findings match the filter.":"No findings. A clean report means the rules did not match — not that the app is secure."}));}
[sevSel,catSel].forEach(function(n){n.addEventListener("change",render);});q.addEventListener("input",render);render();
if(D.notes.length){app.appendChild(el("h2",{text:"Notes"}));var ul=el("ul");D.notes.forEach(function(n){ul.appendChild(el("li",{text:n}));});app.appendChild(ul);}
app.appendChild(el("h2",{text:"Standards & scope"}));var sc=el("ul");
sc.appendChild(el("li",{text:"Maps to: "+D.scope.maps_to.join(", ")}));D.scope.not.forEach(function(n){sc.appendChild(el("li",{text:n}));});app.appendChild(sc);
})();
</script>
</body>
</html>
"""


def to_html(report: Report) -> str:
    band = report.rejection_band()
    data = {
        "root": report.root,
        "kind": report.kind.value,
        "platforms": report.platforms,
        "version": __version__,
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "counts": report.counts(),
        "rejection_score": report.rejection_score(),
        "rejection_band": band,
        "blurb": BAND_BLURB[band],
        "release": release_json(report),
        "findings": [_finding_json(f) for f in report.sorted_findings()],
        "notes": report.notes,
        "scope": SCOPE,
    }
    payload = json.dumps(data, ensure_ascii=False)
    # Scanned content may carry "</script" or "<!--". Escaping every "<" as the
    # JSON escape < means no tag can form inside the <script> block.
    payload = payload.replace("<", "\\u003c")
    return _TEMPLATE.replace("__DATA__", payload)
