set -euo pipefail

red(){ echo -e "\e[31m$*\e[0m"; }
grn(){ echo -e "\e[32m$*\e[0m"; }
ylw(){ echo -e "\e[33m$*\e[0m"; }
blu(){ echo -e "\e[34m$*\e[0m"; }

REQ_PKGS=(coreutils curl python3 python3-minimal freeradius-utils)
CONF=/etc/se-acc2radius.conf
PY=/opt/se-acc2radius/se_acc2radius.py
UNIT=/etc/systemd/system/se-acc2radius.service
LOG=/var/lib/se-acc2radius/se-acc2radius.log.json
STATE=/var/lib/se-acc2radius/state.json
VPNCMD=/usr/local/vpnserver/vpncmd
RADCLIENT=/usr/bin/radclient

ensure_pkgs() {
  ylw ">> Installing prerequisites..."
  apt-get update -y >/dev/null
  apt-get install -y "${REQ_PKGS[@]}"
}

ask() {
  local prompt="$1" default="${2-}" var
  if [[ -n "$default" ]]; then
    read -r -p "$prompt [$default]: " var || true
    echo "${var:-$default}"
  else
    read -r -p "$prompt: " var || true
    echo "$var"
  fi
}

ask_secret() {
  local prompt="$1" var
  read -r -s -p "$prompt: " var || true
  echo
  echo "$var"
}

vpncmd_run() {
  # $1..: args after vpncmd
  "$VPNCMD" "$@" </dev/null
}

validate_vpncmd() {
  if [[ ! -x "$VPNCMD" ]]; then
    red "vpncmd not found at $VPNCMD"
    echo "If SoftEther is installed elsewhere, set VPNCMD path manually in $CONF after install."
    exit 1
  fi
}

validate_radclient() {
  if [[ ! -x "$RADCLIENT" ]]; then
    red "radclient not found at $RADCLIENT"
    echo "Install freeradius-utils or adjust RADCLIENT path in script."
    exit 1
  fi
}

probe_vpn() {
  local MGMT="$1" HUB="$2" PASS="$3"
  local out rc=0
  set +e
  out=$(vpncmd_run "$MGMT" /SERVER /PASSWORD:"$PASS" /HUB:"$HUB" /CMD SessionList 2>&1)
  rc=$?
  set -e
  # موفق وقتی "The command completed successfully." داخل out باشد
  if [[ $rc -ne 0 || "$out" != *"The command completed successfully."* ]]; then
    echo "$out"
    return 1
  fi
  return 0
}

list_hubs() {
  local MGMT="$1" PASS="$2"
  vpncmd_run "$MGMT" /SERVER /PASSWORD:"$PASS" /CMD HubList 2>/dev/null \
    | awk -F'|' '/^\s*Hub Name/ {gsub(/ /,"",$2); print $2}'
}

probe_radius() {
  local HOST="$1" PORT="$2" SECRET="$3" NASIP="$4"
  local PUBIP="$NASIP"
  [[ -z "$PUBIP" ]] && PUBIP="$(curl -fsS https://ipinfo.io/ip || echo "0.0.0.0")"
  ylw ">> Sending Accounting-On probe to RADIUS ($HOST:$PORT)..."
  local msg="Acct-Status-Type = Accounting-On
NAS-IP-Address   = $PUBIP
NAS-Identifier   = \"softether-vpn\""
  set +e
  local out
  out=$(printf "%s\n" "$msg" | "$RADCLIENT" -x "${HOST}:${PORT}" acct "$SECRET" 2>&1)
  local rc=$?
  set -e
  echo "$out" | tail -n2
  return $rc
}

write_conf() {
  install -d -m 755 /opt/se-acc2radius
  install -d -m 755 /var/lib/se-acc2radius
  cat >"$CONF" <<EOF
HUB=$HUB
VPNCMD=$VPNCMD
MGMT=$MGMT
ADMIN_PASS=$ADMIN_PASS
RADIUS_HOST=$RADIUS_HOST
RADIUS_ACCT_PORT=$RADIUS_ACCT_PORT
RADIUS_SECRET=$RADIUS_SECRET
NAS_IDENTIFIER=softether-vpn
NAS_IP=$NAS_IP
POLL_SECONDS=$POLL_SECONDS
INTERIM_EVERY=$INTERIM_EVERY
STATE=$STATE
LOG_JSON=$LOG
MAX_PARALLEL=250
EOF
  chmod 600 "$CONF"
  grn ">> Wrote $CONF"
}

write_py() {
  cat >"$PY" <<'PYCODE'
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import subprocess, json, time, os, threading, queue, re, signal
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
POLL_SECONDS     = int(CFG.get("POLL_SECONDS","5"))
INTERIM_EVERY    = int(CFG.get("INTERIM_EVERY","30"))
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
    rc,out,err=run(cmd, timeout=25)
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
    rc,out,err=run(cmd, timeout=25)
    if rc!=0: return None
    d={}
    for line in out.splitlines():
        if "|" in line:
            k,v=[x.strip() for x in line.split("|",1)]
            d[k]=v
    user = d.get("User Name (Authentication)", d.get("User Name",""))
    return {
        "sid": d.get("Session Name",""),
        "user": user,
        "framed_ip": d.get("Client IP Address",""),
        "in":  onlyint(d.get("Outgoing Data Size","0")) + onlyint(d.get("Receive Size","0")),
        "out": onlyint(d.get("Incoming Data Size","0")) + onlyint(d.get("Send Size","0")),
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
        'NAS-Port = 0',
        'NAS-Port-Type = Virtual',
    ]
    if s.get("framed_ip"): a.append(f'Framed-IP-Address = {s["framed_ip"]}')
    return a

def pkt_start(s): return ['Acct-Status-Type = Start'] + base_attrs(s)
def pkt_interim(s):
    in32,iGW=gw32(s["in"]); out32,oGW=gw32(s["out"])
    return ['Acct-Status-Type = Interim-Update'] + base_attrs(s) + [
        f'Acct-Input-Octets = {in32}', f'Acct-Output-Octets = {out32}',
        f'Acct-Input-Gigawords = {iGW}', f'Acct-Output-Gigawords = {oGW}',
    ]
def pkt_stop(s):
    in32,iGW=gw32(s["in"]); out32,oGW=gw32(s["out"])
    return ['Acct-Status-Type = Stop'] + base_attrs(s) + [
        f'Acct-Input-Octets = {in32}', f'Acct-Output-Octets = {out32}',
        f'Acct-Input-Gigawords = {iGW}', f'Acct-Output-Gigawords = {oGW}',
    ]

def rad_send(lines):
    msg="\n".join(lines)+"\n"
    cmd=["/usr/bin/radclient","-x",f"{RADIUS_HOST}:{RADIUS_ACCT_PORT}","acct",RADIUS_SECRET]
    rc,out,err=run(cmd, input_text=msg, timeout=10)
    ok=(rc==0 and "Accounting-Response" in out)
    jlog("radclient", rc=rc, out=out[-200:], err=err[-200:])
    return ok

def worker(q):
    while True:
        item=q.get()
        if item is None: return
        typ,s=item
        try:
            if s.get("user")=="SecureNAT":
                q.task_done(); continue
            pkt = pkt_start(s) if typ=="start" else pkt_interim(s) if typ=="interim" else pkt_stop(s)
            ok=rad_send(pkt)
            jlog("sent",type=typ,sid=s.get("sid",""),user=s.get("user",""),ok=ok,inb=s.get("in",0),outb=s.get("out",0))
        except Exception as e:
            jlog("error_send",type=typ,sid=s.get("sid"),err=str(e))
        q.task_done()

def main():
    jlog("boot", msg="service_start", hub=HUB, mgmt=MGMT, log=LOG_JSON)
    st=load_state()  # sid -> {started,last_in,last_out,last_ts}
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
                cur=st.get(sid,{"started":False,"last_in":0,"last_out":0,"last_ts":0})
                if not cur["started"]:
                    q.put(("start",s)); cur["started"]=True; cur["last_ts"]=now
                delta=(now-cur.get("last_ts",0))>=INTERIM_EVERY
                moved=(s["in"]>cur["last_in"] or s["out"]>cur["last_out"])
                if delta or moved:
                    q.put(("interim",s)); cur["last_ts"]=now
                cur["last_in"]=s["in"]; cur["last_out"]=s["out"]; st[sid]=cur
            # detect stopped sessions
            for sid in list(st.keys()):
                if sid not in seen and st[sid].get("started"):
                    s={"sid":sid,"user":"","framed_ip":"","in":st[sid]["last_in"],"out":st[sid]["last_out"]}
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
PYCODE
  chmod +x "$PY"
  grn ">> Wrote $PY"
}

write_unit() {
  cat >"$UNIT" <<EOF
[Unit]
Description=SoftEther -> RADIUS Accounting bridge (IBSng)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=$CONF
ExecStart=/usr/bin/env python3 $PY
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
EOF
  systemctl daemon-reload
  grn ">> Wrote $UNIT"
}

start_service() {
  systemctl enable --now se-acc2radius.service
  sleep 1
  systemctl status se-acc2radius --no-pager | sed -n '1,12p'
  ylw "\nTail log:"
  [[ -f "$LOG" ]] || : > "$LOG"
  echo "{\"ev\":\"probe\",\"ts\":\"$(date -u +%FT%TZ)\"}" >> "$LOG"
  tail -n 10 "$LOG"
}

### main
blu "=== SoftEther -> RADIUS Accounting bridge (IBSng) SAFE installer ==="
ensure_pkgs
validate_vpncmd
validate_radclient

# inputs
HUB_DEFAULT="vpn0"
MGMT_DEFAULT="localhost:5555"
HUB="$HUB_DEFAULT"
MGMT="$MGMT_DEFAULT"

# ابتدا MGMT و PASS را بپرس؛ سپس HubList را پیشنهاد بده
MGMT="$(ask "SoftEther mgmt address:port" "$MGMT_DEFAULT")"
ADMIN_PASS="$(ask_secret 'SoftEther ADMIN password')"

# تلاش برای خواندن هاب‌ها (در صورت خطا، جلو می‌رویم)
ylw ">> Trying to fetch hubs list (optional)…"
if hubs=$(list_hubs "$MGMT" "$ADMIN_PASS" | tr -d '\r'); then
  if [[ -n "$hubs" ]]; then
    ylw "Found hubs:"
    echo "$hubs" | nl -ba
    CH=$(ask "Pick hub number or press Enter to type name" "")
    if [[ -n "$CH" ]] && [[ "$CH" =~ ^[0-9]+$ ]]; then
      HUB=$(echo "$hubs" | sed -n "${CH}p")
    else
      HUB=$(ask "SoftEther HUB name" "$HUB_DEFAULT")
    fi
  else
    HUB=$(ask "SoftEther HUB name" "$HUB_DEFAULT")
  fi
else
  HUB=$(ask "SoftEther HUB name" "$HUB_DEFAULT")
fi

# تا وقتی SessionList اوکی نشد، اجازه ادامه نده
while true; do
  ylw ">> Validating vpncmd connectivity (Hub=$HUB @ $MGMT)…"
  if probe_vpn "$MGMT" "$HUB" "$ADMIN_PASS"; then
    grn "vpncmd OK ✓"
    break
  else
    red "vpncmd test FAILED. Re-enter values."
    MGMT="$(ask "SoftEther mgmt address:port" "$MGMT")"
    ADMIN_PASS="$(ask_secret 'SoftEther ADMIN password')"
    HUB="$(ask "SoftEther HUB name" "$HUB")"
  fi
done

RADIUS_HOST="$(ask 'RADIUS server IP/host (acct)' '')"
RADIUS_ACCT_PORT="$(ask 'RADIUS accounting port' '1813')"
RADIUS_SECRET="$(ask_secret 'RADIUS shared secret')"

# NAS IP: بهتره آی‌پی پابلیک همین سرور (همونی که در IBSng برای NAS ثبت کردی)
DEFAULT_NASIP="$(hostname -I 2>/dev/null | awk '{print $1}')"
NAS_IP="$(ask 'NAS IP address' "${DEFAULT_NASIP:-$(curl -fsS https://ipinfo.io/ip || echo 0.0.0.0)}")"

POLL_SECONDS="$(ask 'Polling seconds' '5')"
INTERIM_EVERY="$(ask 'Interim-Update every N seconds' '30')"

echo
blu "Summary:
  HUB=$HUB
  MGMT=$MGMT
  ADMIN_PASS=********
  RADIUS_HOST=$RADIUS_HOST
  RADIUS_ACCT_PORT=$RADIUS_ACCT_PORT
  RADIUS_SECRET=********
  NAS_IP=$NAS_IP
  POLL_SECONDS=$POLL_SECONDS  INTERIM_EVERY=$INTERIM_EVERY
"
read -r -p "Proceed? [Y/n] " ok; ok=${ok:-Y}
[[ "$ok" =~ ^[Yy]$ ]] || { red "Aborted."; exit 1; }

write_conf
write_py
write_unit

# پروب حسابداری رادیوس (غیراجباری، ولی مفید)
if probe_radius "$RADIUS_HOST" "$RADIUS_ACCT_PORT" "$RADIUS_SECRET" "$NAS_IP"; then
  grn "RADIUS probe OK ✓"
else
  ylw "RADIUS probe failed (will still start service)."
fi

start_service
grn "Done ✅  |  Edit config: $CONF  |  Restart: systemctl restart se-acc2radius.service"
