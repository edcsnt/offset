#!/bin/sh
# nu.sh — Nubank TLS capture + API discovery
# Usage: nu.sh [-c N] [-e]
#   -c N    Capture N seconds, then decode + extract
#   -e      Extract from existing nu.pcap + sslkeys.log
#   (none)  Print uprobe offset only

swap() {
        _h=$1
        while case ${#_h} in 16) break ;; esac; do _h=0$_h; done
        _sw=
        while case $_h in ??*) ;; *) false ;; esac; do
                _b=${_h%"${_h#??}"}; _h=${_h#??}; _sw=$_b$_sw
        done
}

_trim() {
        while :; do
                case $_line in ' '*|'	'*) _line=${_line#?} ;;
                *) break ;; esac
        done
}


duration=60 capture= extract=
case $1 in
-c)     capture=1; duration=${2:-60} ;;
-e)     extract=1 ;;
esac

# === Phase 1: Offset Discovery ===

case $extract in 1) ;; *)

out=$(adb shell 'pm path com.nu.production && getprop ro.product.cpu.abi')
abi=${out##*
}
case $abi in *-*) nabi=${abi%-*}_${abi#*-} ;; *) nabi=$abi ;; esac
apk=${out%base.apk*}
apk=${apk##*package:}split_config.$nabi.apk
adb pull -q "$apk"
unzip -joq "${apk##*/}" "lib/$abi/libflutter.so"

for rev in $(strings -an 40 libflutter.so)
do
        case ${#rev} in 40) ;; *) continue ;; esac
        case $rev in *[!0-9a-f]*) continue ;; esac
        curl -fOs \
                "https://storage.googleapis.com/flutter_infra_release/flutter/$rev/android-$abi-release/symbols.zip" \
                && break
done
unzip -oq symbols.zip libflutter.so -d symbols/

vaddr=$(nm -P symbols/libflutter.so \
        | sed -n 's/.*tls13_set_traffic_key.* [tTwW] \([^ ]*\).*/0x\1/p')
case $vaddr in 0x?*) ;; *)
        printf 'tls13_set_traffic_key not found\n' >&2; exit 1
;; esac

seg=$(readelf -l libflutter.so | while IFS= read -r _l; do
        case $_l in *LOAD*)
                set -- $_l; _pp=$2; _pv=$3
                IFS= read -r _l
                case $_l in *R*E*)
                        printf '%s %s' "$_pp" "$_pv"; break ;; esac
        ;; esac
done)
p_off=${seg%% *}; p_vaddr=${seg##* }
foff=$(($(printf '%d' "$vaddr") - $(printf '%d' "$p_vaddr") \
        + $(printf '%d' "$p_off")))

h_off=$(unzip -Z -v "${apk##*/}" "lib/$abi/libflutter.so" \
        | while IFS= read -r _l; do
                case $_l in *"offset of local header"*)
                        printf '%s' "${_l##* }"; break ;; esac
        done)
set -- $(dd if="${apk##*/}" bs=1 skip=$((h_off + 26)) count=4 \
        2>/dev/null | od -An -tu1)
data_off=$((h_off + 30 + $1 + $2 * 256 + $3 + $4 * 256))
uprobe=$((data_off + foff))
printf 'uprobe offset: 0x%x\n' "$uprobe"

esac

# === Phase 2: Capture ===

case $capture in 1)

tfs=/sys/kernel/tracing
fa="level=%x1:u64 dir=%x2:u64 slen=%x5:u64"
fa="$fa cr0=+48(+48(%x0)):x64 cr1=+56(+48(%x0)):x64"
fa="$fa cr2=+64(+48(%x0)):x64 cr3=+72(+48(%x0)):x64"
fa="$fa s0=+0(%x4):x64 s1=+8(%x4):x64 s2=+16(%x4):x64"
fa="$fa s3=+24(%x4):x64 s4=+32(%x4):x64 s5=+40(%x4):x64"
uh=$(printf '0x%x' "$uprobe")
sys=/apex/com.android.conscrypt/lib64/libssl.so
sfa="label=+0(%x1):string slen=%x3:u64"
sfa="$sfa cr0=+48(+48(%x0)):x64 cr1=+56(+48(%x0)):x64"
sfa="$sfa cr2=+64(+48(%x0)):x64 cr3=+72(+48(%x0)):x64"
sfa="$sfa s0=+0(%x2):x64 s1=+8(%x2):x64 s2=+16(%x2):x64"
sfa="$sfa s3=+24(%x2):x64 s4=+32(%x2):x64 s5=+40(%x2):x64"

adb shell su -c sh <<EOF
rm -f /data/local/tmp/raw_keylog.txt /data/local/tmp/nu.pcap 2>/dev/null
echo 0 > $tfs/tracing_on
echo 0 > $tfs/events/enable
echo > $tfs/uprobe_events 2>/dev/null
echo > $tfs/trace
echo 4096 > $tfs/buffer_size_kb
echo "p:fkeylog $apk:$uh $fa" >> $tfs/uprobe_events
echo "p:skeylog $sys:0x54894 $sfa" >> $tfs/uprobe_events
echo 1 > $tfs/events/uprobes/fkeylog/enable
echo 1 > $tfs/events/uprobes/skeylog/enable
echo 1 > $tfs/tracing_on
am force-stop com.nu.production
pm clear --cache-only com.nu.production >/dev/null 2>&1 &
_if=\$(ip route show default); _if=\${_if##*dev }; _if=\${_if%% *}
: "\${_if:=wlan0}"
cat $tfs/trace_pipe > /data/local/tmp/raw_keylog.txt &
_tp=\$!
tcpdump -i \$_if -w /data/local/tmp/nu.pcap 2>/dev/null &
_dp=\$!
sleep $duration
kill \$_tp \$_dp 2>/dev/null; wait \$_tp \$_dp 2>/dev/null
echo 0 > $tfs/events/uprobes/fkeylog/enable
echo 0 > $tfs/events/uprobes/skeylog/enable
echo > $tfs/uprobe_events
echo 7 > $tfs/buffer_size_kb
echo 1 > $tfs/events/enable
EOF
adb pull /data/local/tmp/raw_keylog.txt .
adb pull /data/local/tmp/nu.pcap .

esac

# === Phase 3: Decode keylog ===

case $capture in 1)

seen=
while IFS= read -r line || case $line in ?*) ;; *) false ;; esac
do
        case $line in *keylog:*) ;; *) continue ;; esac
        slen=${line#*slen=}; slen=${slen%% *}
        nv=$((slen / 8))
        cr=
        for f in cr0 cr1 cr2 cr3; do
                v=${line#*"$f"=0x}; v=${v%% *}
                swap "$v"; cr=$cr$_sw
        done
        sec= i=0
        for f in s0 s1 s2 s3 s4 s5; do
                case $i in $nv) break ;; esac
                v=${line#*"$f"=0x}; v=${v%% *}
                swap "$v"; sec=$sec$_sw; i=$((i + 1))
        done
        case $line in
        *skeylog:*)
                lab=${line#*label=\"}; lab=${lab%%\"*} ;;
        *)      lev=${line#*level=}; lev=${lev%% *}
                dr=${line#*dir=}; dr=${dr%% *}
                case $lev in 2|3) ;; *) continue ;; esac
                case $lev in
                2) case $dr in
                   0) lab=SERVER_HANDSHAKE_TRAFFIC_SECRET ;;
                   *) lab=CLIENT_HANDSHAKE_TRAFFIC_SECRET ;;
                   esac ;;
                3) gk=${cr}_${dr}
                   eval "gn=\${gn_$gk:-0}"
                   case $dr in
                   0) lab=SERVER_TRAFFIC_SECRET_$gn ;;
                   *) lab=CLIENT_TRAFFIC_SECRET_$gn ;;
                   esac
                   eval "gn_$gk=$((gn + 1))" ;;
                esac ;;
        esac
        case $lab in *TRAFFIC*|*RANDOM*|*EXPORTER*) ;;
        *) continue ;; esac
        key=$lab:$cr
        case " $seen " in *" $key "*) continue ;; esac
        seen="$seen $key"
        printf '%s %s %s\n' "$lab" "$cr" "$sec"
done < raw_keylog.txt > sslkeys.log
printf '%d TLS keys decoded\n' "$(wc -l < sslkeys.log)"

esac

# === Phase 4: Extract ===

case $capture$extract in *1*)

pcap=nu.pcap keylog=sslkeys.log
kf=$(cd -- "$(dirname "$keylog")" && pwd)/${keylog##*/}
ts_opts="-o tls.keylog_file:$kf"
ts_opts="$ts_opts -o tcp.reassemble_out_of_order:TRUE"
tmp=/tmp/nu_$$ smap=/tmp/nu_smap_$$
trap 'rm -f "$tmp" "$smap"' EXIT INT TERM
mkdir -p extracted

tshark -r "$pcap" $ts_opts -Y "http2.headers.path" \
        -T fields -e tcp.stream -e http2.streamid \
        -e http2.headers.path 2>/dev/null > "$smap"
seen_p=
while IFS='	' read -r _ _ spath; do
        while case $spath in ?*) ;; *) false ;; esac; do
                case $spath in
                *,*) p=${spath%%,*}; spath=${spath#*,} ;;
                *)   p=$spath; spath= ;;
                esac
                case $p in /api*)
                        case " $seen_p " in *" $p "*) ;; *)
                                seen_p="$seen_p $p"
                                printf '%s\n' "$p"
                        ;; esac
                ;; esac
        done
done < "$smap" > extracted/paths.txt
printf '%d API paths discovered\n' "$(wc -l < extracted/paths.txt)"

for spec in \
        "feed/page=feed" \
        "feed/search=search" \
        "available-balance=balance" \
        "commitments-summary=commitments" \
        "investments-summary=investments" \
        "save-money=savings" \
        "/api/discovery=discovery" \
        "unread-push-count=notifications"
do
        pat=${spec%%=*}; label=${spec#*=}; n=0
        pairs= seen_s=
        while IFS='	' read -r stcp sid spath; do
                case $spath in *"$pat"*) ;; *) continue ;; esac
                oifs=$IFS; IFS=,; set -f; set -- $sid; set +f
                IFS=$oifs
                for s do
                        case $((s % 2)) in 1)
                                case " $seen_s " in *" $stcp,$s "*) ;; *)
                                        seen_s="$seen_s $stcp,$s"
                                        pairs="$pairs $stcp $s"
                                ;; esac
                        ;; esac
                done
        done < "$smap"
        set -- $pairs
        while case $# in 0) false ;; esac; do
                tcp=$1; h2=$2; shift 2
                case $label in
                feed|search) out=extracted/${label}_$((n + 1)).json ;;
                *) out=extracted/$label.json ;;
                esac
                tshark -r "$pcap" $ts_opts -q \
                        -z "follow,http2,raw,$tcp,$h2" \
                        2>/dev/null > "$tmp"
                case $pat in ?*)
                        p=
                        while IFS= read -r _line; do
                                case $_line in *3a6d*) _trim
                                        p=$(printf '%s' "$_line" \
                                                | xxd -r -p)
                                        break ;; esac
                        done < "$tmp"
                        case $p in *":path: "*"$pat"*) ;; *)
                                continue ;; esac
                ;; esac
                : > "$out"
                while IFS= read -r _line; do _trim
                        case $_line in 7b22*|7b0a*|5b7b*|5b22*)
                                printf '%s' "$_line" \
                                        | xxd -r -p > "$out"
                                break ;; esac
                done < "$tmp"
                case $(wc -c < "$out") in 0)
                        rm -f "$out"; continue ;; esac
                n=$((n + 1))
                printf '  %s\n' "${out##*/}"
                case $label in feed|search) ;; *) break ;; esac
        done
done
rm -f "$tmp" "$smap"
printf 'Output: extracted/\n'

esac
