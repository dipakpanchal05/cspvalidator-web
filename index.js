/* ========= Encoded Payloads ========= */
const PAYLOADS={
  "script-src":["&lt;script src=&quot;https://evil.example/x.js&quot;&gt;&lt;/script&gt;"],
  "img-src":["&lt;img src=x onerror=alert(1)&gt;"]
};
const decode=e=>{const d=document.createElement("div");d.innerHTML=e;return d.textContent}

/* ========= CSP Parser ========= */
function parseCSP(raw){
  const m={}
  raw.split(/\n/).forEach(l=>{
    l.split(";").forEach(p=>{
      const t=p.trim().split(/\s+/)
      if(!t[0])return
      const d=t[0].toLowerCase()
      m[d]=m[d]||[]
      m[d].push(...t.slice(1))
    })
  })
  Object.keys(m).forEach(k=>m[k]=[...new Set(m[k])])
  return m
}

/* ========= Analyzer ========= */
function analyze(p){
  const f=[]
  if(p["default-src"]?.includes("*"))
    f.push(["default-src","Wildcard * allows everything","high"])
  if(p["script-src"]?.includes("'unsafe-inline'"))
    f.push(["script-src","unsafe-inline allows XSS","high"])
  if(p["script-src"]?.some(v=>v.includes("maps.googleapis.com")))
    f.push(["script-src","JSONP-capable domain preserved","medium"])
  return f
}

/* ========= Harden + Suggestions ========= */
function harden(p){
  const out={}, changes=[]
  const added=[], removed=[]

  out["default-src"]=["'none'"]
  if(p["default-src"]?.includes("*")) removed.push("default-src *")

  const scripts=["'self'","'nonce-{NONCE}'","'strict-dynamic'"]
  ;(p["script-src"]||[]).forEach(v=>{
    if(v==="'unsafe-inline'"){removed.push("script-src 'unsafe-inline'");return}
    if(!v.startsWith("'")) scripts.push(v.replace(/^http:/,"https:"))
  })
  out["script-src"]=[...new Set(scripts)]

  const REQUIRED={
    "style-src":["'self'","'nonce-{NONCE}'"],
    "img-src":["'self'","data:"],
    "font-src":["'self'"],
    "connect-src":["'self'"],
    "media-src":["'self'"],
    "worker-src":["'self'"],
    "manifest-src":["'self'"],
    "object-src":["'none'"],
    "base-uri":["'none'"],
    "form-action":["'self'"],
    "frame-ancestors":["'none'"],
    "plugin-types": ["'none'"],
    "sandbox": []
  }

  const addedDirs=[]
  for(const d in REQUIRED){
    if(!p[d]) addedDirs.push(d)
    out[d]=REQUIRED[d]
  }

  ["upgrade-insecure-requests","block-all-mixed-content"].forEach(d=>{
    if(!p[d]) added.push(d)
    out[d]=[]
  })

  if(!p["require-trusted-types-for"]){
    added.push("require-trusted-types-for 'script'")
    out["require-trusted-types-for"]=["'script'"]
  } else out["require-trusted-types-for"]=p["require-trusted-types-for"]

  if(!p["trusted-types"]){
    added.push("trusted-types default")
    out["trusted-types"]=["default"]
  } else out["trusted-types"]=p["trusted-types"]

  if (!p["report-to"]) {
  out["report-to"] = ["/groupname"];
  addedDirs.push("report-to");
  }

  /* ===== Suggestions ===== */
  if (removed.length) {changes.push("Removed insecure values: " + removed.join(", "));}
  if(!p["script-src"]?.some(v=>v.startsWith("'nonce-")))
    changes.push("Enforced nonce + strict-dynamic for scripts.")
  if(addedDirs.length)
    changes.push("Added missing directives: "+addedDirs.join(", "))
  if(added.length)
    changes.push("Added security directives: "+added.join(", "))
  if(p["script-src"]?.some(v=>v.includes("maps.googleapis.com")))
    changes.push("Preserved risky domain (consider removal): https://maps.googleapis.com")

  let txt=""
  Object.keys(out).forEach(k=>{
    txt+=k+(out[k].length?" "+out[k].join(" "):"")+";\n"
  })
  return {txt,changes}
}

/* ========= Run ========= */
function run(){
  const raw=input.value.trim()

  if(!raw){
    output.textContent="No CSP provided"
    hardened.value=""
    changes.textContent=""
    return
  }

  const p=parseCSP(raw)
  const f=analyze(p)

  output.innerHTML=""
  if(!f.length) output.innerHTML="<div class='warn'>No critical findings</div>"
  f.forEach(x=>{
    const b=document.createElement("div")
    b.className=x[2]==="high"?"vuln":"warn"
    b.textContent=x[0]+" — "+x[1]
    if(PAYLOADS[x[0]]){
      const pb=document.createElement("div")
      pb.className="payloadBox"
      pb.textContent=decode(PAYLOADS[x[0]][0])
      b.appendChild(pb)
    }
    output.appendChild(b)
  })

  const h=harden(p)
  hardened.value=h.txt
  changes.textContent=h.changes.map((c,i)=>`${i+1}. ${c}`).join("\n")
}

scan.onclick=run
sample.onclick=()=>{
  input.value="default-src *; script-src 'unsafe-inline' https://maps.googleapis.com;"
  run()
}

window.onload=()=>{
  input.value=""
  hardened.value=""
  output.textContent="No scan yet."
  changes.textContent=""
}