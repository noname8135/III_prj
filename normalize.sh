#!/bin/bash

if [ $# -lt 3 ]
then
    echo "Two few arguments. Should be at least 3."
    echo "format: normalize.sh logformat prog [\"args\"] files..."
    exit 1
fi
logformat=$1
prog=$2
shift
shift
if ! `echo $1 | grep -qF .`
then
    args=$1
    shift
fi

case $logformat in
CTTI | NBL)
# fields: timestamp, src_ip, src_port, dst_ip, dst_port, protocol
    awk -F, '{printf "%s,%s,%s,%s,%s,%s\n",$1,$8,$10,$11,$13,$7}' $*  \
	 | python $prog $args
    ;;
iii)
# fields: timestamp, src_ip, src_port, dst_ip, dst_port, protocol
    awk -F, '{printf "%s,%s,%s,%s,%s,%s\n",$1,$8,$10,$9,$11,$5}' $* \
	 | python $prog $args
    ;;
up_download)
# fields: timestamp, orig_ip, orig_port, resp_ip, resp_port, protocol, orig_bytes, resp_bytes
# orig_ip: the IP address which starts the connection
# resp_ip: the IP address which passively establishes the connection
# orig_bytes: the number of bytes from orig_ip to resp_ip
# resp_bytes: the number of bytes from resp_ip to orig_ip
	cat $* | /usr/local/bro/bin/bro-cut -d ts id.orig_h id.orig_p id.resp_h id.resp_p proto orig_bytes resp_bytes \
	| python $prog $args
	;;
crawler)
# fields: timestamp, orig_ip, resp_ip, URI
# orig_ip: the IP address which starts the connection
# resp_ip: the IP address which passively establishes the connection
	cat $* | /usr/local/bro/bin/bro-cut -D %Y-%m-%dT%H:%M:%S ts id.orig_h id.resp_h uri \
	| sort -k 1| python $prog $args
	;;

dns)
# fields: timestamp, orig_ip, resp_ip, resp_port, query, rcode_name
# orig_ip: the IP address which starts the connection
# resp_ip: the IP address which passively establishes the connection
# query: the DNS query
# rcode_name: the name of the DNS response code, e.g., NXDOMAIN

    awk -F"\t" '{printf "%s`%s`%s`%s`%s`%s\n",$1,$3,$5,$6,$9,$15}' $* \
    | python $prog $args
    ;;
*)
    echo "Format $logformat unrecognized"
    exit 1
esac
