#!/usr/bin/env bash
# =============================================================================
# selfcheck.sh — is a deployment exposed to log4j2 #4255?  (self-contained)
#
#   --scan DIR            STATIC: flag any jar containing FilteredObjectInputStream
#                         (log4j-core 2.8.2–2.10 or log4j-api 2.11.0+, incl. shaded)
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

# FOIS shipped 2.8.2–2.26.1 and is gone in 3.x, so the presence of the class is
# the real signal — not a jar name or a version guess. Detect the class in ANY
# jar. Its package moved with it: org.apache.logging.log4j.core.util.* in
# log4j-core (2.8.2–2.10), then org.apache.logging.log4j.util.* in log4j-api
# (2.11.0+) — so match the class file regardless of package or jar name (this
# also catches shaded/renamed fat jars that a log4j-core-*.jar glob would miss).
AFFECTED_RANGE="2.8.2–2.26.1"

scan(){
  local dir="${1:-.}"
  command -v unzip >/dev/null || die "need 'unzip' for the static scan"
  echo "${A}[*] scanning $dir for the FilteredObjectInputStream class ($AFFECTED_RANGE) ...${O}"
  local found=0 vuln=0
  while IFS= read -r jar; do
    # only jars that ACTUALLY contain FOIS — not by filename (a 161-byte stub
    # named log4j-core-2.20.0.jar must not be flagged; a shaded jar must be)
    unzip -l "$jar" 2>/dev/null | grep -q 'FilteredObjectInputStream\.class' || continue
    found=1; vuln=1
    local ver
    ver="$(unzip -p "$jar" 'META-INF/maven/org.apache.logging.log4j/log4j-api/pom.properties'  2>/dev/null | sed -n 's/^version=//p' | head -1)"
    [ -z "$ver" ] && ver="$(unzip -p "$jar" 'META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties' 2>/dev/null | sed -n 's/^version=//p' | head -1)"
    [ -z "$ver" ] && ver="version unknown"
    echo "  ${R}AFFECTED${O}  $jar  (FilteredObjectInputStream present, $ver)"
  done < <(find "$dir" -name '*.jar' 2>/dev/null)
  echo
  if [ "$vuln" = 1 ]; then
    echo "${A}[!] The FilteredObjectInputStream class is present — necessary, not sufficient.${O}"
    echo "    Exploitable only if the app ALSO exposes a serialized-LogEvent receiver"
    echo "    (SocketServer / ObjectInputStreamLogEventBridge reading via FOIS)."
    echo "    Confirm with the DYNAMIC check (--dns / --oob)."
    return 3   # non-zero so --scan can gate CI
  fi
  echo "${G}[+] No jar under $dir contains FilteredObjectInputStream.${O}"
  return 0
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
