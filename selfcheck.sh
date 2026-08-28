#!/usr/bin/env bash
# =============================================================================
# selfcheck.sh — is a deployment exposed to log4j2 #4255?  (self-contained)
#
#   --scan DIR            STATIC: flag any log4j-core jar in the affected range
#                         2.8.0–2.26.1. Necessary, not sufficient — you also need
#                         an exposed FOIS serialized-LogEvent receiver.
#   --dns                 DYNAMIC, fully local: spin the lab receiver + a DNS sink
#                         and prove the result with a safe, gadget-free URLDNS probe.
#   --oob ID HOST PORT    DYNAMIC vs a receiver you OWN/are AUTHORIZED to test.
#                         Needs an OOB domain (interactsh / Burp / *.oast.pro).
#
# The dynamic checks send only a URLDNS chain: a DNS lookup, never code execution.
# =============================================================================
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
IMG=log4j4255
G=$'\e[32m'; R=$'\e[31m'; A=$'\e[33m'; D=$'\e[2m'; O=$'\e[0m'
die(){ echo "${R}[!] $*${O}"; exit 1; }

AFFECTED_LOW="2.8.0"; AFFECTED_HIGH="2.26.1"
in_range(){ local v="$1"
  [ "$(printf '%s\n%s\n' "$AFFECTED_LOW" "$v" | sort -V | head -1)" = "$AFFECTED_LOW" ] &&
  [ "$(printf '%s\n%s\n' "$v" "$AFFECTED_HIGH" | sort -V | head -1)" = "$v" ]
}

scan(){
  local dir="${1:-.}"
  command -v unzip >/dev/null || die "need 'unzip' for the static scan"
  echo "${A}[*] scanning $dir for log4j-core jars ...${O}"
  local found=0 vuln=0
  while IFS= read -r jar; do
    found=1
    local ver
    ver="$(unzip -p "$jar" 'META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties' 2>/dev/null \
           | sed -n 's/^version=//p' | head -1)"
    [ -z "$ver" ] && ver="$(basename "$jar" | sed -n 's/.*log4j-core-\([0-9][0-9.]*\)\.jar/\1/p')"
    [ -z "$ver" ] && ver="unknown"
    if [ "$ver" != "unknown" ] && in_range "$ver"; then
      vuln=1; echo "  ${R}AFFECTED${O}  $jar  (log4j-core $ver, in $AFFECTED_LOW–$AFFECTED_HIGH)"
    else
      echo "  ${G}ok${O}        $jar  (log4j-core $ver)"
    fi
  done < <(find "$dir" -name 'log4j-core*.jar' 2>/dev/null)
  [ "$found" = 0 ] && { echo "  ${D}no log4j-core jar found under $dir${O}"; return; }
  echo
  if [ "$vuln" = 1 ]; then
    echo "${A}[!] An affected log4j-core is present — necessary, not sufficient.${O}"
    echo "    Exploitable only if the app ALSO exposes a serialized-LogEvent receiver"
    echo "    (SocketServer / ObjectInputStreamLogEventBridge reading via FOIS)."
    echo "    Confirm with the DYNAMIC check (--dns / --oob)."
  else
    echo "${G}[+] No affected log4j-core jar found.${O}"
  fi
}

dns_sink(){ # start a local UDP:53 DNS logger container, echo its IP
  docker rm -f log4j4255-dnslog >/dev/null 2>&1 || true
  cat > /tmp/l4j_dnslog.py <<'PY'
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(("0.0.0.0",53)); print("dnssink up",flush=True)
while True:
    d,a=s.recvfrom(2048)
    try:
        i=12;L=[]
        while d[i]!=0: n=d[i];L.append(d[i+1:i+1+n].decode('latin1'));i+=n+1
        print("QUERY "+".".join(L),flush=True)
    except Exception as e: print("raw",e,flush=True)
PY
  docker run -d --rm --name log4j4255-dnslog -v /tmp/l4j_dnslog.py:/s.py:ro python:3-slim python3 /s.py >/dev/null
  sleep 2
  docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' log4j4255-dnslog
}

dyn_local(){
  docker image inspect "$IMG" >/dev/null 2>&1 || { echo "${A}[*] building lab image...${O}"; docker build -t "$IMG" "$HERE"; }
  echo "${A}[*] self-contained dynamic check (safe URLDNS, no code execution)${O}"
  local ip; ip="$(dns_sink)"; [ -n "$ip" ] || die "could not start DNS sink"
  echo "${D}[*] local DNS sink at $ip${O}"
  docker rm -f log4j4255-selfchk >/dev/null 2>&1 || true
  docker run -d --rm --name log4j4255-selfchk --dns "$ip" -e PORT=4598 "$IMG" >/dev/null
  local rip; rip="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' log4j4255-selfchk)"
  sleep 2
  local mark="selfcheck-$$-$(date +%s).oob.local"
  echo "${A}[*] sending gadget-free URLDNS probe -> $mark${O}"
  python3 "$HERE/payload.py" dns --oob "$mark" -t "$rip" -p 4598 >/dev/null 2>&1 || true
  sleep 3
  if docker logs log4j4255-dnslog 2>&1 | grep -q "$mark"; then
    echo "${R}[VULNERABLE] the receiver resolved our hostname — inner stream is UNFILTERED${O}"
    echo "${D}    $(docker logs log4j4255-dnslog 2>&1 | grep "$mark" | head -1)${O}"
  else
    echo "${G}[not vulnerable] no DNS callback — filter intact or class not reachable${O}"
  fi
  docker rm -f log4j4255-selfchk log4j4255-dnslog >/dev/null 2>&1 || true
}

dyn_oob(){
  local oob="$1" host="$2" port="$3"
  echo "${A}[*] AUTHORIZED remote check via OOB $oob (safe URLDNS, no code execution)${O}"
  echo "${A}[*] you MUST own or be authorized to test $host:$port${O}"
  python3 "$HERE/payload.py" dns --oob "$oob" -t "$host" -p "$port"
  echo "${D}[*] watch your OOB listener; a resolved hostname = VULNERABLE${O}"
}

case "${1:-}" in
  --scan)  scan "${2:-.}" ;;
  --dns)   dyn_local ;;
  --oob)   [ $# -ge 4 ] || die "usage: $0 --oob ID.oast.pro HOST PORT"; dyn_oob "$2" "$3" "$4" ;;
  *) sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//' ;;
esac
