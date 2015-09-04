import sys
import math
import argparse
from datetime import datetime
from scipy import stats

def find_duration(duration):
    n = duration.find('-')
    try:
	if n > -1:
	   start = int(duration[:n])
	   end = int(duration[(n+1):])+1
	else:
	   start = int(duration)
	   end = start+1
    except ValueError:
	start, end = 0, 24 
# specified duration out of range. Abort range specifiation
    if start < 0 or start > 23 or end < 0 or end > 23:
	start, end = 0, 24 
    return start,end

def update_table(ip_src_table, ip_pair_table, src_ip, dst_ip, interval):
    if ip_src_table and src_ip in ip_src_table:
	if interval in ip_src_table[src_ip]:
           ip_src_table[src_ip][interval] += 1
	else:
	   ip_src_table[src_ip][interval] = 1
    else:
	ip_src_table[src_ip] = {}
	ip_src_table[src_ip][interval] = 1
    if ip_pair_table and (src_ip, dst_ip) in ip_pair_table:
	if interval in ip_pair_table[src_ip, dst_ip]:
           ip_pair_table[src_ip, dst_ip][interval] += 1
	else:
	   ip_pair_table[src_ip, dst_ip][interval] = 1
    else:
	ip_pair_table[src_ip, dst_ip] = {}
	ip_pair_table[src_ip, dst_ip][interval] = 1

def chi_sqtest(ip_src_table, ip_pair_table, interval, intvl_type):
    if interval < 5:
	print "Too few intervals for an effective test by", intvl_type
	return
    if intvl_type=='hour':
	effective_intvl = 0
	for i in range(interval+1):
	    if (i+start_time.hour)%24 in range(start_hour, end_hour):
		effective_intvl += 1
	if effective_intvl < 5:
	    print "Too few effective intervals for an effective test by", intvl_type
	    return
    for src_ip in ip_src_table:
	freq=[]
	cnt=0
	for i in range(interval+1):
# If i not in ip_src_table[src_ip], there are two possibilities
# 1: the hour interval not in the range of start_hour and end_hour
# 2: no connection in that interval
# We distiguish the two cases in the following code.
	    if intvl_type=='hour' and \
	       (i+start_time.hour)%24 not in range(start_hour, end_hour):
	        continue
	    if i in ip_src_table[src_ip]:
		freq.append(ip_src_table[src_ip][i])
	    else:
		freq.append(0)
		cnt += 1
	if cnt/effective_intvl > 0.5:
	    continue
	chisq, p = stats.chisquare(freq)
	if math.isnan(p) or p > 0.95:    # isnan should be rare
	   print src_ip, "has regular activities by", intvl_type
	   print freq
    for src_ip,dst_ip in ip_pair_table:
	freq=[]
	cnt=0
	effective_intvl = 0
	for i in range(interval+1):
	    if intvl_type=='hour' and \
	       (i+start_time.hour)%24 not in range(start_hour, end_hour):
	        continue
	    effective_intvl += 1
	    if i in ip_pair_table[src_ip,dst_ip]:
		freq.append(ip_pair_table[src_ip,dst_ip][i])
	    else:
		freq.append(0)
		cnt += 1
	if cnt/effective_intvl > 0.5:
	    continue
	chisq, p = stats.chisquare(freq)
	if math.isnan(p) or p > 0.95:    # isnan should be rare
	   print src_ip, dst_ip, "has regular activities by", intvl_type
	   print freq

#def chi_sq_test(h_ip_src, h_ip_pair, d_ip_src, d_ip_pair,\
#w_ip_src, w_ip_pair, hour, day, week):
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--daily", help="to analyze daily regularity", action="store_true")
    parser.add_argument("-w", "--weekly", help="to analyze weekly regularity", action="store_true")
    parser.add_argument("-D", "--duration", help="to limit the duration in hours")
    parser.add_argument('-f','--white_list',type=str,default=None, \
    help='customize the source IP white list')
    args = parser.parse_args()
    if args.white_list:
	try:
	    white_fd = open(args.white_list, 'r')
	    for line in white_fd:
		if line[0]!='#':
		   white_list.append(str(line)[:-1]) #remove \n
	    white_fd.close()
	except IOError:
	    print "Cannot open "+args.white_list
    else:
	white_list = None
    if args.duration:
	start_hour, end_hour = find_duration(args.duration)
    else:
	start_hour, end_hour = 0, 24
    hip_src, hip_pair = {}, {}
    if args.daily:
	dip_src, dip_pair = {}, {}
    if args.weekly:
	wip_src, wip_pair = {}, {}
    sys.stdin.readline()         # Skip the first line
    first_line = True
    for line in sys.stdin:
	fields = line.split(',')
	if first_line:
	    if fields[0].find('"') > -1:    # timestamp embedded in double quotes
	       start_time = datetime.strptime(fields[0][1:-1],"%Y-%m-%d %H:%M:%S")
	       time_with_dblquote = True
	    else:
	       start_time = datetime.strptime(fields[0],"%Y-%m-%d %H:%M:%S")
	       time_with_dblquote = False
	    first_line = False
	try:
	    if time_with_dblquote:
	       current_time = datetime.strptime(fields[0][1:-1],"%Y-%m-%d %H:%M:%S")
	    else:
	       current_time = datetime.strptime(fields[0],"%Y-%m-%d %H:%M:%S")
	except ValueError:
	    continue
	src_ip, dst_ip = fields[1], fields[3]
	if white_list and src_ip in white_list:
	    continue
	if current_time.hour in range(start_hour, end_hour):
	    time_diff = current_time - start_time
	    update_table(hip_src, hip_pair, src_ip, dst_ip, time_diff.seconds//3600)
	    if args.daily:
	       update_table(dip_src, dip_pair, src_ip, dst_ip, time_diff.days)
	    if args.weekly:
	       update_table(wip_src, wip_pair, src_ip, dst_ip, time_diff.days//7)
    chi_sqtest(hip_src, hip_pair, time_diff.seconds//3600, 'hour')
    if args.daily:
       chi_sqtest(dip_src, dip_pair, time_diff.days, 'day')
    if args.weekly:
       chi_sqtest(wip_src, wip_pair, time_diff.days//7, 'week')
