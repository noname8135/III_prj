'''
HOWTO

./normalize.sh   dns   ./dns_overlen.py   all_dns_files_in_target_date

e.g.,: ./normalize.sh  dns  ./dns_overlen.py  {bro dns log folder}/{date}/dns.*

'''
import sys
import argparse
import datetime

if __name__=='__main__':
    parser=argparse.ArgumentParser(description='Find too long domain names')
    parser.add_argument('-l','--length',type=int,default=50,help='the length threshold')
    parser.add_argument('-f','--file',default='white_domain',help='the config file')
    args=parser.parse_args()
    length = args.length
    config_name = args.config
    try:
	conf = open(config_name, 'r')
    except IOError:
	print 'Cannot open ', config_name
    else:
	white_domain = []
	for line in conf:
	    if line[0] != '#':
		white_domain.append(line[:-1])   # Remove the newline
	conf.close()
    nodot_domain, onedot_domain, twodot_domain = [], [], []
    for domain in white_domain:
	dots = len(domain.split('.')) - 1
	if dots == 0:   # not dots
	   nodot_domain.append(domain)
	elif dots == 1: # one dot
	   onedot_domain.append(domain)
	else:
	   twodot_domain.append(domain)
    f = sys.stdin
    for line in f:
	if line[0]=='#':
	    continue
	line = line[:-1]
	dns_fields = line.split('`')
	now, src_ip, dst_ip, dst_port, query, rcode = \
	dns_fields[0], dns_fields[1], dns_fields[2], dns_fields[3], dns_fields[4], dns_fields[5]
	if len(query) > length:
	    now_format = datetime.datetime.fromtimestamp(float(now))
	    top1_domain, top2_domain, top3_domain = '', '', ''
	    last_dot = query.rfind('.')
	    if (last_dot != -1):       # the last one dot found
		top1_domain = query[(last_dot+1):]
		last2_dot = query.rfind('.',0,last_dot)
		if (last2_dot != -1):
		   top2_domain = query[(last2_dot+1):]
		   last3_dot = query.rfind('.',0,last2_dot)
		   if (last3_dot != -1):
			top3_domain = query[(last3_dot+1):]
		   else:
			top3_domain = query
		else:
		   top2_domain = query
	    else:
		top1_domain = query
	    if (top1_domain not in nodot_domain) and (top2_domain not in onedot_domain) \
		and (top3_domain not in twodot_domain):
		print now_format, src_ip, dst_ip, dst_port, query, rcode
