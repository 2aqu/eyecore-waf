#!/bin/bash

#export IPTABLES_CMD=
default_ipt_cmd="/sbin/iptables"

if [ "$EUID" -ne 0 ]; then
    # Can be run as normal user, will just use "sudo"
    export su=sudo
fi

function usage() {
    echo ""
    echo " $0 - EYECORE SISTEMI - EYECORE.PRO"
    echo ""
    echo "Usage:"
    echo "------"
    echo " Script    : $0"
    echo " Parameters: [-vf]"
    echo ""
    echo "  -v : verbose"
    echo "  -f : Yeni kurallar oluşmadan önce kuralları düzenleyin"
    echo ""
}

##  --- Parse command line arguments ---
while getopts ":i:p:vf" option; do
    case $option in
        v)
            VERBOSE=yes
            ;;
        f)
            FLUSH=yes
            ;;
        ?|*)
            echo ""
            echo "[ERROR] Unknown parameter \"$OPTARG\""
            usage
            exit 2
    esac
done
shift $[ OPTIND - 1 ]

# Extra checking for iptables
if [ -z "$IPTABLES_CMD" ]; then
    echo "WARNING: Shell env variable IPTABLES_CMD is undefined"
    export IPTABLES_CMD=${default_ipt_cmd}
    echo "WARNING: Fallback to default IPTABLES_CMD=${default_ipt_cmd}"
fi

#
# A shell iptables function wrapper
#
iptables() {
    $su $IPTABLES_CMD "$@"
    local result=$?
    if [ ${result} -gt 0 ]; then
        echo "WARNING -- Error (${result}) when executing the iptables command:"
        echo " \"iptables $@\""
    else
        if [ -n "${VERBOSE}" ]; then
            echo "iptables $@"
        fi
    fi
}

# Cleanup before applying our rules
if [ -n "$FLUSH" ]; then
    iptables -t raw -F
    iptables -t raw -X
    iptables -F
    iptables -X
fi

iptables -A INPUT -i eth0 -m state --state ESTABLISHED,RELATED -j ACCEPT


iptables -A INPUT -s АДРЕС -i eth0 -p tcp -j ACCEPT




iptables -A INPUT -i eth0 -m conntrack --ctstate INVALID -j DROP


iptables -A INPUT -i eth0 -p tcp ! --syn -m conntrack --ctstate NEW -j DROP


iptables -A INPUT -i eth0 -p tcp -m conntrack --ctstate NEW -m tcpmss ! --mss 536:65535 -j DROP


iptables -A INPUT -i eth0 -p tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP
iptables -A INPUT -i eth0 -p tcp --tcp-flags FIN,SYN FIN,SYN -j DROP
iptables -A INPUT -i eth0 -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
iptables -A INPUT -i eth0 -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
iptables -A INPUT -i eth0 -p tcp --tcp-flags FIN,RST FIN,RST -j DROP
iptables -A INPUT -i eth0 -p tcp --tcp-flags FIN,ACK FIN -j DROP
iptables -A INPUT -i eth0 -p tcp --tcp-flags ACK,URG URG -j DROP
iptables -A INPUT -i eth0 -p tcp --tcp-flags ACK,FIN FIN -j DROP
iptables -A INPUT -i eth0 -p tcp --tcp-flags ACK,PSH PSH -j DROP
iptables -A INPUT -i eth0 -p tcp --tcp-flags ALL ALL -j DROP
iptables -A INPUT -i eth0 -p tcp --tcp-flags ALL NONE -j DROP
iptables -A INPUT -i eth0 -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP
iptables -A INPUT -i eth0 -p tcp --tcp-flags ALL SYN,FIN,PSH,URG -j DROP
iptables -A INPUT -i eth0 -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP


iptables -N port-scanning
iptables -A port-scanning -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s --limit-burst 2 -j RETURN
iptables -A port-scanning -j DROP


iptables -A INPUT -p tcp -m tcp --dport 25565 --tcp-flags FIN,SYN,RST,ACK SYN -m connlimit --connlimit-above 20 --connlimit-mask 32 --connlimit-saddr -j DROP
iptables -A INPUT -p tcp -m tcp --dport 25565 --tcp-flags FIN,SYN,RST,ACK SYN -m connlimit --connlimit-above 10 --connlimit-mask 32 --connlimit-saddr -j REJECT --reject-with icmp-port-unreachable

iptables -A INPUT -p udp -j DROP
#iptables -A PREROUTING -p icmp -j DROP




# More strict conntrack handling to get unknown ACKs (from 3WHS) to be
#  marked as INVALID state (else a conntrack is just created)
#
#$su /sbin/sysctl -w net/netfilter/nf_conntrack_tcp_loose=0

# Enable timestamping, because SYN cookies uses TCP options field
#$su /sbin/sysctl -w net/ipv4/tcp_timestamps=1

# Adjusting maximum number of connection tracking entries possible
#
# Conntrack element size 288 bytes found in /proc/slabinfo
#  "nf_conntrack" <objsize> = 288
#
# 288 * 2000000 / 10^6 = 576.0 MB
$su /sbin/sysctl -w net/netfilter/nf_conntrack_max=2000000

# IMPORTANT: Also adjust hash bucket size for conntracks
#   net/netfilter/nf_conntrack_buckets writeable
#   via /sys/module/nf_conntrack/parameters/hashsize
#
# Hash entry 8 bytes pointer (uses struct hlist_nulls_head)
#  8 * 2000000 / 10^6 = 16 MB
$su sh -c 'echo 2000000 > /sys/module/nf_conntrack/parameters/hashsize'

# Hint: Monitor nf_conntrack usage searched, found, new, etc.:
#  lnstat -c -1 -f nf_conntrack
