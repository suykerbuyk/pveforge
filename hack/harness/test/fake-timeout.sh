#!/usr/bin/env bash
# Offline stand-in for timeout, used only by
# internal/sourceguard/harness_build_test.go for build.sh's TCP probes, which
# run `timeout 5 bash -c <connect> tcp <ip> <port>`. It records <ip>:<port>
# in tcp.log and answers from tcp/<ip>_<port>: the number of attempts that
# fail before the port opens, "never" for a port that never opens, and 1 when
# there is no file (the preflight finds every address free, then the poll
# finds it open). Each failed attempt is a timeout: it adds 5 s to the fake
# clock ($FAKE_PVEFORGE_DIR/clock, which the test's date and sleep share).
set -u
F=${FAKE_PVEFORGE_DIR:?}
ip=${*: -2:1}
port=${*: -1}
printf '%s:%s\n' "$ip" "$port" >>"$F/tcp.log"
mkdir -p "$F/tcpcount"
n=0
[ -f "$F/tcpcount/${ip}_$port" ] && n=$(cat "$F/tcpcount/${ip}_$port")
n=$((n + 1))
printf '%s' "$n" >"$F/tcpcount/${ip}_$port"
fails=1
[ -f "$F/tcp/${ip}_$port" ] && fails=$(cat "$F/tcp/${ip}_$port")
if [ "$fails" = never ] || [ "$n" -le "$fails" ]; then
	c=0
	[ -f "$F/clock" ] && c=$(cat "$F/clock")
	printf '%s' "$((c + 5))" >"$F/clock"
	exit 124
fi
exit 0
