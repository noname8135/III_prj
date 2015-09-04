import sys
import os
import argparse

from numpy import *
#input format: bro connection log after normalized
#ts id.orig_h id.orig_p id.resp_h id.resp_p proto orig_bytes resp_bytes
threshold = 10
def output_con(con_info,upload_tot,download_tot):
	#upload standard deviation and mean, threshold = mean+n*std_dev
	std_dev = int(std([con_info[i]['upload'] for i in con_info]))
	mean = upload_tot/len(con_info)
	counter = 0
	#print std_dev,mean
	print "excessive upload:"
	for i in con_info:
		if con_info[i]['upload'] > mean + std_dev*threshold:
			print con_info[i]['time'],i,con_info[i]['upload']#,con_info[i]['dst_ip_port']
			
	std_dev = int(std([con_info[i]['download'] for i in con_info]))
	mean = download_tot/len(con_info)
	#print std_dev,mean
	print "excessive download:"
	for i in con_info:
		if con_info[i]['download'] > mean + std_dev*threshold:
			print con_info[i]['time'],i,con_info[i]['download']#,con_info[i][dst_ip_port]


if __name__ == '__main__':
	parser = argparse.ArgumentParser()
	parser.add_argument("-t", "--threshold",type=int, help="customize the threshold (mean + t*standard deviation )")
	args = vars(parser.parse_args())
	if args['threshold']:
		threshold = args['threshold']
	con_info = {}
	upload_tot = 0
	download_tot = 0
	for line in sys.stdin:
		columns=line.replace("\n","").split("\t")
		if 'time' in columns[0] or columns[0][0]=='#' or (columns[6]=='-' and columns[7]=='-') or (columns[6]=='0' and columns[7]=='0'): #get rid of column names row and 0/0 upload/download
			continue
		time_str, src_ip, dst_ip_port,upload_byte,download_byte =columns[0], columns[1],columns[3]+":"+columns[5]+columns[4],int(columns[6]),int(columns[7])
		upload_tot+=upload_byte
		download_tot+=download_byte
		
		if con_info.has_key(src_ip):
			con_info[src_ip]['dst_ip_port'].add(dst_ip_port)
			con_info[src_ip]['upload'] += upload_byte
			con_info[src_ip]['download'] += download_byte
		else:
			con_info[src_ip]={}
			con_info[src_ip]['dst_ip_port'] = set([dst_ip_port])
			con_info[src_ip]['upload'] = upload_byte
			con_info[src_ip]['download'] = download_byte
			con_info[src_ip]['time'] = time_str
		
	output_con(con_info,upload_tot,download_tot)
	
