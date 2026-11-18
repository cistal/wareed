"""WAREED prototype API: JWT auth, RBAC, simulated hospital data, explainable correlation rules."""
import os, random, hmac, hashlib
from datetime import datetime, timedelta, timezone
import jwt
from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import HTTPBearer
from pydantic import BaseModel

SECRET = os.getenv("SECRET_KEY", "dev-only-change-me")
app = FastAPI(title="WAREED API (prototype, simulated data)")
bearer = HTTPBearer(auto_error=False)
h = lambda p: hashlib.sha256(p.encode()).hexdigest()
DEMO_PW = os.getenv("DEMO_PASSWORD", "Wareed@2026")
USERS = {u: {"role": r, "pw": h(DEMO_PW)} for u, r in
         [("admin", "admin"), ("doctor", "doctor"), ("security", "security_analyst"), ("nurse", "nurse")]}
PERMS = {"admin": {"read", "review", "simulate"}, "security_analyst": {"read", "review", "simulate"},
         "doctor": {"read", "review"}, "nurse": {"read"}}
KNOWN = {"dr_ahmed", "dr_sara", "nurse_mona", "admin", "doctor", "security", "nurse"}

NOW = datetime.now(timezone.utc)
def ts(m): return (NOW - timedelta(minutes=m)).isoformat(timespec="seconds")
def pid(i): return f"P-{i:03d}"

def vit(r, bad=None):
    v = dict(hr=r.randint(60, 90), sbp=r.randint(105, 130), spo2=r.randint(95, 99),
             temp=round(r.uniform(36.4, 37.2), 1), glu=r.randint(80, 120))
    if bad == "device": v.update(hr=r.randint(142, 160), spo2=r.randint(76, 84))
    if bad == "patient": v.update(hr=128, spo2=90, temp=38.9)
    return v

def build():
    r = random.Random(42)
    S = dict(patients=[], devices=[], rx=[], logs=[], reviewed=set(), n=0)
    meds = [("Morphine", 10), ("Metformin", 500), ("Amlodipine", 5), ("Atenolol", 50), ("Warfarin", 5)]
    S["devices"] = [dict(id=f"D-{d:02d}", type=t, status="online")
                    for d, t in zip(range(1, 5), ["Vital monitor", "Pulse oximeter", "Vital monitor", "Glucose meter"])]
    for i in range(1, 13):
        dev = f"D-{(i - 1) % 4 + 1:02d}"
        bad = "device" if dev == "D-03" else ("patient" if i == 6 else None)
        S["patients"].append(dict(id=pid(i), name=f"Patient {i:03d}", ward=f"Ward {i % 3 + 1}", device=dev, vitals=vit(r, bad)))
        m, d = meds[i % 5]
        S["rx"].append(dict(patient=pid(i), drug=m, prev=d, dose=d, by="dr_ahmed", ip="10.0.1.%d" % (i + 10), at=ts(600 + i)))
        S["logs"].append(dict(user="dr_ahmed", ip="10.0.1.%d" % (i + 10), event="login_ok", at=ts(700 + i)))
    S["devices"][2]["status"] = "warning"
    tamper(S, "P-004", "Morphine", 10, 100)
    return S

def tamper(S, p, drug, prev, dose):
    for x in S["rx"]:
        if x["patient"] == p: x.update(drug=drug, prev=prev, dose=dose, by="tmp_svc", ip="185.220.101.7", at=ts(14))
    S["logs"] += [dict(user="tmp_svc", ip="185.220.101.7", event="login_failed", at=ts(40 - i)) for i in range(4)]
    S["logs"] += [dict(user="tmp_svc", ip="185.220.101.7", event="login_ok", at=ts(30)),
                  dict(user="tmp_svc", ip="185.220.101.7", event="role_changed", at=ts(25))]

S = build()

def analyze():
    A, handled = [], set()
    pts = {p["id"]: p for p in S["patients"]}
    bad = lambda v: v["spo2"] < 92 or v["hr"] > 120 or v["temp"] > 38.5
    # 1. device anomaly: same device, 3+ patients with abnormal readings
    for d in S["devices"]:
        affected = [p for p in S["patients"] if p["device"] == d["id"] and bad(p["vitals"])]
        if len(affected) >= 3:
            handled |= {p["id"] for p in affected}
            A.append(dict(key=f"dev-{d['id']}", title=f"Possible device fault: {d['id']}", risk="High", category="Medical device",
                          subject=d["id"], related=[f"{p['id']}: SpO2 {p['vitals']['spo2']}%, HR {p['vitals']['hr']}" for p in affected],
                          at=ts(8), why=f"{len(affected)} unrelated patients on the same device show abnormal readings at once, which points to the device or data source rather than separate conditions.",
                          next="Inspect and recalibrate the device, then re-measure patients manually."))
    # 2. prescription changes, correlated with security events
    for x in S["rx"]:
        if x["dose"] / x["prev"] >= 5:
            sus = [l for l in S["logs"] if l["ip"] == x["ip"] or l["user"] == x["by"]]
            odd = x["by"] not in KNOWN or not x["ip"].startswith("10.")
            if odd and sus:
                A.append(dict(key=f"rx-{x['patient']}", title="Potential medication tampering", risk="Critical", category="Correlated",
                              subject=x["patient"], at=x["at"],
                              related=[f"{x['drug']} dose {x['prev']} mg to {x['dose']} mg ({x['patient']})", f"Change made by unknown account '{x['by']}' from IP {x['ip']}"]
                                      + [f"{l['event']} by {l['user']} from {l['ip']}" for l in sus],
                              why="A large dose increase was made by an account outside the known staff list, from an external IP that also shows failed logins and a role change. Together these suggest unauthorized modification.",
                              next="Verify the dose with the prescriber, suspend the account, and review audit logs."))
            else:
                A.append(dict(key=f"rx-{x['patient']}", title="Unusual dose change", risk="Medium", category="Medication", subject=x["patient"], at=x["at"],
                              related=[f"{x['drug']} dose {x['prev']} mg to {x['dose']} mg"], why="Dose increased 5x or more with no related security signals.",
                              next="Confirm with the prescriber."))
    # 3. patient risk
    for p in S["patients"]:
        v = p["vitals"]
        if p["id"] not in handled and bad(v):
            n = sum([v["spo2"] < 92, v["hr"] > 120, v["temp"] > 38.5])
            A.append(dict(key=f"pt-{p['id']}", title=f"Abnormal vital signs: {p['id']}", risk="High" if n >= 2 else "Medium", category="Patient safety",
                          subject=p["id"], at=ts(5), related=[f"HR {v['hr']}, SpO2 {v['spo2']}%, Temp {v['temp']} C, BP {v['sbp']}"],
                          why=f"{n} vital sign(s) outside the safe range and the device is not affected.", next="Medical staff review the patient."))
    for a in A: a["id"] = a["key"]; a["reviewed"] = a["key"] in S["reviewed"]
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    return sorted(A, key=lambda a: order[a["risk"]])

class Login(BaseModel): username: str; password: str
class Sim(BaseModel): scenario: str

def user(c=Depends(bearer)):
    try: return jwt.decode(c.credentials, SECRET, algorithms=["HS256"])
    except Exception: raise HTTPException(401, "Sign in again.")
def need(perm):
    def f(u=Depends(user)):
        if perm not in PERMS[u["role"]]: raise HTTPException(403, "Your role cannot do this.")
        return u
    return f

@app.post("/api/login")
def login(b: Login):
    u = USERS.get(b.username)
    if not u or not hmac.compare_digest(u["pw"], h(b.password)): raise HTTPException(401, "Wrong username or password.")
    exp = datetime.now(timezone.utc) + timedelta(hours=8)
    return dict(token=jwt.encode(dict(sub=b.username, role=u["role"], exp=exp), SECRET, algorithm="HS256"), role=u["role"], perms=sorted(PERMS[u["role"]]))

@app.get("/api/dashboard")
def dash(u=Depends(need("read"))):
    A = analyze(); c = {k: sum(a["risk"] == k and not a["reviewed"] for a in A) for k in ["Critical", "High", "Medium", "Low"]}
    return dict(patients=len(S["patients"]), device_count=len(S["devices"]), active_devices=sum(d["status"] == "online" for d in S["devices"]),
                open_alerts=sum(c.values()), risk=c, alerts=A, devices=S["devices"],
                logs=sorted([l for l in S["logs"] if not l["ip"].startswith("10.")], key=lambda l: l["at"], reverse=True)[:6],
                patient_list=S["patients"], synthetic=True)

@app.post("/api/alerts/{key}/review")
def review(key: str, u=Depends(need("review"))): S["reviewed"].add(key); return dict(ok=True)

@app.post("/api/simulate")
def simulate(b: Sim, u=Depends(need("simulate"))):
    if b.scenario == "tamper": tamper(S, "P-009", "Amlodipine", 5, 50)
    elif b.scenario == "device":
        for p in S["patients"]:
            if p["device"] == "D-01": p["vitals"].update(hr=150, spo2=80)
        S["devices"][0]["status"] = "warning"
    elif b.scenario == "vitals": S["patients"][1]["vitals"].update(hr=131, spo2=89, temp=39.1)
    elif b.scenario == "reset": S.update(build())
    else: raise HTTPException(400, "Unknown scenario.")
    return dict(ok=True)

if os.path.isdir("public"):
    from fastapi.staticfiles import StaticFiles
    app.mount("/", StaticFiles(directory="public", html=True), name="static")
