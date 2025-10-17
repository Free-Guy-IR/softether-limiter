#!/usr/bin/env bash
set -euo pipefail

# --- safety
if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "Run as root: sudo bash $0" >&2; exit 1
fi

# --- tiny helpers
q() { read -r -p "$1" "$2"; }
qs() { read -r -s -p "$1" "$2"; echo; }
default() { local v="$1" d="$2"; [[ -z "$v" ]] && echo "$d" || echo "$v"; }
have() { command -v "$1" >/dev/null 2>&1; }

echo "=== SoftEther -> RADIUS Accounting bridge (IBSng) installer ==="

# --- ask user
q "SoftEther HUB name [vpn0]: " HUB;     HUB=$(default "$HUB" "vpn0")
q "SoftEther mgmt address:port [localhost:5555]: " MGMT; MGMT=$(default "$MGMT" "localhost:5555")
qs "SoftEther ADMIN password: " ADMIN_PASS
q "RADIUS server IP/host (acct): " RADIUS_HOST
q "RADIUS accounting port [1813]: " RADIUS_ACCT_PORT; RADIUS_ACCT_PORT=$(default "$RADIUS_ACCT_PORT" "1813")
qs "RADIUS shared secret: " RADIUS_SECRET

# try to guess NAS IP (public)
GUESSED_IP=""
if have curl; then GUESSED_IP=$(curl -fsS https://ipinfo.io/ip || true); fi
if [[ -z "$GUESSED_IP" ]]; then
  # fallback: pick 1st non-RFC1918 from ip addr
  GUESSED_IP=$(ip -4 -o addr show | awk '{print $4}' | cut -d/ -f1 \
    | awk '!( $1 ~ /^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)/ ) {print; exit}' )
fi
q "NAS IP address [${GUESSED_IP:-0.0.0.0}]: " NAS_IP; NAS_IP=$(default "$NAS_IP" "${GUESSED_IP:-0.0.0.0}")

q "Polling seconds [5]: " POLL_SECONDS; POLL_SECONDS=$(default "$POLL_SECONDS" "5")
q "Interim-Update every N seconds [30]: " INTERIM_EVERY; INTERIM_EVERY=$(default "$INTERIM_EVERY" "30")

echo
echo "Summary:"
echo "  HUB=${HUB}"
echo "  MGMT=${MGMT}"
echo "  ADMIN_PASS=********"
echo "  RADIUS_HOST=${RADIUS_HOST}"
echo "  RADIUS_ACCT_PORT=${RADIUS_ACCT_PORT}"
echo "  RADIUS_SECRET=********"
echo "  NAS_IP=${NAS_IP}"
echo "  POLL_SECONDS=${POLL_SECONDS}  INTERIM_EVERY=${INTERIM_EVERY}"
read -r -p "Proceed? [Y/n] " ok; ok=${ok,,}; [[ "$ok" == "n" ]] && { echo "Aborted."; exit 1; }

# --- deps
echo ">> Installing prerequisites..."
if have apt; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y python3 python3-minimal freeradius-utils curl coreutils
elif have dnf; then
  dnf install -y python3 freeradius-utils curl coreutils || true
elif have yum; then
  yum install -y python3 freeradius-utils curl coreutils || true
else
  echo "WARN: unknown package manager; make sure python3 and radclient exist."
fi

# --- paths
install -d -m 755 /opt/se-acc2radius
install -d -m 755 /var/lib/se-acc2radius

# --- config
echo ">> Writing /etc/se-acc2radius.conf"
cat >/etc/se-acc2radius.conf <<CFG
HUB=${HUB}
VPNCMD=/usr/local/vpnserver/vpncmd
MGMT=${MGMT}
ADMIN_PASS=${ADMIN_PASS}
RADIUS_HOST=${RADIUS_HOST}
RADIUS_ACCT_PORT=${RADIUS_ACCT_PORT}
RADIUS_SECRET=${RADIUS_SECRET}
NAS_IDENTIFIER=softether-vpn
NAS_IP=${NAS_IP}
POLL_SECONDS=${POLL_SECONDS}
INTERIM_EVERY=${INTERIM_EVERY}
STATE=/var/lib/se-acc2radius/state.json
LOG_JSON=/var/lib/se-acc2radius/se-acc2radius.log.json
MAX_PARALLEL=250
CFG
chmod 600 /etc/se-acc2radius.conf

# --- python app
echo ">> Writing /opt/se-acc2radius/se_acc2radius.py"
cat >/opt/se-acc2radius/se_acc2radius.py <<'PY'
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import subprocess, json, time, os, threading, queue, re
from datetime import datetime

CONF_PATH="/etc/se-acc2radius.conf"
def load_config(path=CONF_PATH):
    cfg={}
    with open(path,"r") as f:
        for raw in f:
            line=raw.split("#",1)[0].strip()
            if not line or "=" not in line: continue
            k,v=line.split("=",1); cfg[k.strip()]=v.strip()
    return cfg

CFG = load_config()
HUB              = CFG.get("HUB","DEFAULT")
VPNCMD           = CFG.get("VPNCMD","/usr/local/vpnserver/vpncmd")
MGMT             = CFG.get("MGMT","localhost:5555")
ADMIN_PASS       = CFG.get("ADMIN_PASS","")
RADIUS_HOST      = CFG.get("RADIUS_HOST","127.0.0.1")
RADIUS_ACCT_PORT = int(CFG.get("RADIUS_ACCT_PORT","1813"))
RADIUS_SECRET    = CFG.get("RADIUS_SECRET","")
NAS_IDENTIFIER   = CFG.get("NAS_IDENTIFIER","softether-vpn")
NAS_IP           = CFG.get("NAS_IP","0.0.0.0")
POLL_SECONDS     = int(CFG.get("POLL_SECONDS","20"))
INTERIM_EVERY    = int(CFG.get("INTERIM_EVERY","60"))
STATE_FILE       = CFG.get("STATE","/var/lib/se-acc2radius/state.json")
LOG_JSON         = CFG.get("LOG_JSON","/var/lib/se-acc2radius/se-acc2radius.log.json")
MAX_PARALLEL     = int(CFG.get("MAX_PARALLEL","250"))

os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
os.makedirs(os.path.dirname(LOG_JSON),  exist_ok=True)

def jlog(ev, **kw):
    rec={"ts":datetime.utcnow().isoformat()+"Z","ev":ev}; rec.update(kw)
    with open(LOG_JSON,"a") as f: f.write(json.dumps(rec, ensure_ascii=False)+"\n")

def run(cmd, input_text=None, timeout=30):
    try:
        p=subprocess.run(cmd, input=(input_text.encode() if input_text else None),
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         check=False, timeout=timeout)
        return p.returncode, p.stdout.decode(errors="ignore"), p.stderr.decode(errors="ignore")
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except Exception as e:
        return 1, "", str(e)

def onlyint(s):
    s2=re.sub(r"[^\d]","",s or "")
    return int(s2) if s2 else 0

def vpncmd_session_list():
    cmd=[VPNCMD, MGMT, "/SERVER", "/PASSWORD:"+ADMIN_PASS, "/HUB:"+HUB, "/CMD", "SessionList"]
    rc,out,err=run(cmd)
    jlog("poll", rc=rc, err=err, note="after_run")
    if rc!=0: raise RuntimeError("vpncmd SessionList failed: "+(err or out))
    sids=[]
    for line in out.splitlines():
        m=re.search(r"^\s*Session Name\s*\|\s*(.+)$", line)
        if m: sids.append(m.group(1).strip())
    jlog("poll_ok", count=len(sids))
    return sids

def vpncmd_session_get(sid):
    cmd=[VPNCMD, MGMT, "/SERVER", "/PASSWORD:"+ADMIN_PASS, "/HUB:"+HUB, "/CMD", "SessionGet", sid]
    rc,out,err=run(cmd)
    if rc!=0: return None
    d={}
    for line in out.splitlines():
        if "|" in line:
            k,v=[x.strip() for x in line.split("|",1)]
            d[k]=v
    return {
        "sid": d.get("Session Name",""),
        "user": d.get("User Name (Authentication)", d.get("User Name","")),
        "framed_ip": d.get("Client IP Address",""),
        "in":  onlyint(d.get("Incoming Data Size", d.get("Receive Size","0"))),
        "out": onlyint(d.get("Outgoing Data Size", d.get("Send Size","0"))),
    }

def load_state():
    try:
        with open(STATE_FILE) as f: return json.load(f)
    except: return {}

def save_state(st):
    tmp=STATE_FILE+".tmp"
    with open(tmp,"w") as f: json.dump(st,f)
    os.replace(tmp, STATE_FILE)

def gw32(v): return (v & 0xFFFFFFFF, v >> 32)

def base_attrs(s):
    a=[
        f'User-Name = "{s["user"]}"',
        f'Acct-Session-Id = "{s["sid"]}"',
        f'NAS-Identifier = "{NAS_IDENTIFIER}"',
        f'NAS-IP-Address = {NAS_IP}',
        "NAS-Port = 0",
        "NAS-Port-Type = Virtual",
    ]
    if s.get("framed_ip"): a.append(f'Framed-IP-Address = {s["framed_ip"]}')
    return a

def pkt_start(s): return ["Acct-Status-Type = Start"] + base_attrs(s)
def pkt_interim(s):
    in32,iGW=gw32(s["in"]); out32,oGW=gw32(s["out"])
    return ["Acct-Status-Type = Interim-Update"] + base_attrs(s) + [
        f"Acct-Input-Octets = {in32}", f"Acct-Output-Octets = {out32}",
        f"Acct-Input-Gigawords = {iGW}", f"Acct-Output-Gigawords = {oGW}",
    ]
def pkt_stop(s):
    in32,iGW=gw32(s["in"]); out32,oGW=gw32(s["out"])
    return ["Acct-Status-Type = Stop"] + base_attrs(s) + [
        f"Acct-Input-Octets = {in32}", f"Acct-Output-Octets = {out32}",
        f"Acct-Input-Gigawords = {iGW}", f"Acct-Output-Gigawords = {oGW}",
    ]

def rad_send(lines):
    msg="\n".join(lines)+"\n"
    cmd=["/usr/bin/radclient","-x",f"{RADIUS_HOST}:{RADIUS_ACCT_PORT}","acct",RADIUS_SECRET]
    rc,out,err=run(cmd, input_text=msg)
    ok=(rc==0 and "Accounting-Response" in out)
    jlog("radclient", rc=rc, out=out[-400:], err=err[-400:])
    return ok

def worker(q):
    while True:
        item=q.get()
        if item is None: return
        typ,s=item
        try:
            pkt = pkt_start(s) if typ=="start" else pkt_interim(s) if typ=="interim" else pkt_stop(s)
            ok=rad_send(pkt)
            jlog("sent", type=typ, sid=s.get("sid"), user=s.get("user"), ok=ok, inb=s.get("in",0), outb=s.get("out",0))
        except Exception as e:
            jlog("error_send", type=typ, sid=s.get("sid"), err=str(e))
        q.task_done()

def main():
    jlog("boot", msg="service_start", hub=HUB, mgmt=MGMT, log=LOG_JSON)
    st=load_state()
    q=queue.Queue()
    workers=[]
    for _ in range(min(MAX_PARALLEL,200)):
        t=threading.Thread(target=worker,args=(q,),daemon=True); t.start(); workers.append(t)

    while True:
        try:
            sids=vpncmd_session_list()
            now=int(time.time())
            seen=set()
            for sid in sids:
                s=vpncmd_session_get(sid)
                if (not s) or (not s["user"]) or (s["user"]=="SecureNAT"):
                    continue
                seen.add(sid)
                cur=st.get(sid,{"started":False,"last_in":0,"last_out":0,"last_ts":0,"user":s["user"]})
                if not cur["started"]:
                    q.put(("start",s)); cur["started"]=True; cur["last_ts"]=now
                delta=(now-cur.get("last_ts",0))>=INTERIM_EVERY
                moved=(s["in"]>cur["last_in"] or s["out"]>cur["last_out"])
                if delta or moved:
                    q.put(("interim",s)); cur["last_ts"]=now
                cur["last_in"]=s["in"]; cur["last_out"]=s["out"]; cur["user"]=s["user"]; st[sid]=cur
            for sid in list(st.keys()):
                if sid not in seen and st[sid].get("started"):
                    s={"sid":sid,"user":st[sid].get("user",""),"framed_ip":"",
                       "in":st[sid]["last_in"],"out":st[sid]["last_out"]}
                    q.put(("stop",s)); del st[sid]
            save_state(st); time.sleep(POLL_SECONDS)
        except KeyboardInterrupt:
            break
        except Exception as e:
            jlog("loop_error", err=str(e)); time.sleep(3)

    for _ in workers: q.put(None)
    for t in workers: t.join()

if __name__=="__main__":
    main()
PY
chmod +x /opt/se-acc2radius/se_acc2radius.py

# --- systemd service
echo ">> Writing systemd unit"
cat >/etc/systemd/system/se-acc2radius.service <<'SVC'
[Unit]
Description=SoftEther -> RADIUS Accounting bridge (IBSng)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=/etc/se-acc2radius.conf
ExecStart=/usr/bin/env python3 /opt/se-acc2radius/se_acc2radius.py
Restart=always
RestartSec=2
User=root
NoNewPrivileges=true
CapabilityBoundingSet=
ProtectSystem=full
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
SVC

# --- test vpncmd once (non-fatal)
echo ">> Testing vpncmd connectivity (non-fatal)…"
if [[ -x /usr/local/vpnserver/vpncmd ]]; then
  /usr/local/vpnserver/vpncmd "$MGMT" /SERVER /PASSWORD:"$ADMIN_PASS" /HUB:"$HUB" /CMD SessionList >/dev/null 2>&1 \
    && echo "vpncmd test: OK" || echo "vpncmd test: FAILED (will still try to run)"
else
  echo "WARN: /usr/local/vpnserver/vpncmd not found."
fi

# --- enable & start
systemctl daemon-reload
systemctl enable --now se-acc2radius.service

# --- logs
touch /var/lib/se-acc2radius/se-acc2radius.log.json
echo "{\"ev\":\"probe\",\"ts\":\"$(date -u +%FT%TZ)\"}" >> /var/lib/se-acc2radius/se-acc2radius.log.json

echo
systemctl --no-pager --full status se-acc2radius.service || true
echo
echo "Tail log:"
tail -n 30 /var/lib/se-acc2radius/se-acc2radius.log.json || true

echo
echo "Done ✅  |  Edit config: /etc/se-acc2radius.conf  |  Restart: systemctl restart se-acc2radius.service"
