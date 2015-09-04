'''
HOWTO

./normalize.sh Input_Type ./port_scan.py Target_Folder/*

ex: ./normalize.sh  CTTI  ./port_scan.py  {Firewall log folder}/ctti_firewall*

'''
import sys
from datetime import datetime
#import psycopg2
import argparse

def cal_data(detail_data,date,scan_threshold,sweep_threshold,whitelist,subnet) :
	scan_list={}
	sweep_list={} 
	#some port that attackers usually scan
	scan_confirm=["21","22","25","53","80","110","135","443","465","993"]

	for content in detail_data :
		remain_byte=4-(subnet/8)
	#####port scan#####
		ip_str=content['src_ip']+","+content['dst_ip']
		port=content['dst_port']
		if scan_list.has_key(ip_str)==False : #first time appeared in  scan_list , create set
			scan_list[ip_str]={}
			scan_list[ip_str][port]=0
		elif port not in scan_list[ip_str]: #this port first time appeared in this ip_str , add in set
			scan_list[ip_str][port]=0
		#else : this situation means that this port in ip_str has been scan , not port scan
	#####port sweep#####
		origin_dst=content['dst_ip']
		dst_cut=len(origin_dst)
		while remain_byte>0:
			dst_cut=content['dst_ip'][:dst_cut-1].rfind('.')
			remain_byte-=1
		#the subnet range ,ex: 8.8.8.16 -> 8.8.8.0/24 , find the subnet/24
		remain_byte=4-(subnet/8)
		dst_subnet=content['dst_ip'][:dst_cut]
		while remain_byte>0:
			dst_subnet=dst_subnet+".0"
			remain_byte-=1
		dst_subnet=dst_subnet+"/"+str(subnet)
		dst_sub_ip=content['dst_ip'][dst_cut+1:]          # ex: 8.8.8.16 -> 16 , find the address in this subnet
		sweep_str=content['src_ip'],dst_subnet,content['dst_port']
		if sweep_str not in sweep_list : #first time appeared in sweep_list ,create set
			sweep_list[sweep_str]=set()
			sweep_list[sweep_str].add(dst_sub_ip)
		elif dst_sub_ip not in sweep_list[sweep_str] : #this destination first time appeared in sweep_str , add in set
			sweep_list[sweep_str].add(dst_sub_ip)
		#else : this situation means that this destination in sweep_str has been scan , not port sweep

	#####output#####
	for content in scan_list.iteritems():
		if len(content[1]) > scan_threshold:
			tag_src_ip=content[0][content[0].find('\'')+1:]
			tag_src_ip=tag_src_ip[:tag_src_ip.find('\'')]
			#source ip in whitelist , ignore
			if whitelist!=None and tag_src_ip in whitelist:
				continue
				
			scan_count=0
			for tar_port in scan_confirm:
				if tar_port in content[1]:
					scan_count+=1
			print "At :"+str(date)
			if scan_count>=2:
				print "likely Port scan alert :"
			else:
				print "Perhaps Port scan alert :"
			#stdout
			out=''
			for scanned_port in content[1].iteritems():
				out+=str(scanned_port[0])+","
			print str(content[0])+" : "+str(len(content[1]))+" ports scanned , "+out[:-1]
	for content in sweep_list.iteritems():
		if len(content[1]) > sweep_threshold:
			tag_src_ip=str(content[0])[str(content[0]).find('\'')+1:]
			tag_src_ip=tag_src_ip[:tag_src_ip.find('\'')]
			#source ip in whitelist , ignore
			if whitelist!=None and tag_src_ip in whitelist:
				continue
			#stdout
			print "At :"+str(date)
			print "Port sweep alert :"
			print str(content[0])+" : "+str(len(content[1]))+" host scanned , "+str(content[1])[5:-2]




if __name__ == '__main__':
		parser=argparse.ArgumentParser()
		parser.add_argument('-sct','--scan_threshold',type=int,default=100,help='customize the port scan threshold')
		parser.add_argument('-swt','--sweep_threshold',type=int,default=50,help='customize the port sweep threshold')
		parser.add_argument('-time','--interval',type=int,default=10,help='customize the time interval')
		parser.add_argument('-f','--source_IP_whitelist',type=str,default=None,help='customize the source IP white list')
		parser.add_argument('-sub','--subnet',type=int,default=24,help='customize the subnet range , only support 8,16,24')
		args=vars(parser.parse_args())
		#set threshold
		scan_threshold=args['scan_threshold']
		sweep_threshold=args['sweep_threshold']
		interval=args['interval']  # minute
		whitelist_filename=args['source_IP_whitelist']
		subnet=args['subnet']

		if whitelist_filename!=None:
			try:
				whitelist_fd=open(whitelist_filename,'r')
			except IOError:
				print "Cannot open "+whitelist_filename
			whitelist=[]
			for line in whitelist_fd:
				if line[0]!='#':
					whitelist.append(str(line)[:-1]) #remove \n
			whitelist_fd.close()
		else:
			whitelist=None

		f=sys.stdin
		line = f.readline()	#get rid of first line(column names)
		begin_line = f.readline() #initial the begin_time
		detail_data=[]
		#initial the begin_time
		line=f.readline()
		while(line[0]=='s' or line[0]=='t'):
			line=f.readline()
		col=line.split(",")
		if col[0][0]=='\"' :
			begin_time=col[0][1:-1]
		else:
			begin_time=col[0]
		begin_time=datetime.strptime(begin_time,"%Y-%m-%d %H:%M:%S")
		detail_data.append({"src_ip":col[1],"dst_ip":col[3],"dst_port":col[4]}) 

		for line in f:
			if line[0]=='s' or line[0]=='t' :
				continue
			col=line.split(",")
			if col[0][0]=='\"' :
				timestr = col[0][1:-1]
			else:
				timestr = col[0]

			timestr=datetime.strptime(timestr,"%Y-%m-%d %H:%M:%S")
			time_diff=(timestr.day*1440+timestr.hour*60+timestr.minute)-(begin_time.day*1440+begin_time.hour*60+begin_time.minute)
			if  time_diff>=interval:
				cal_data(detail_data,begin_time,scan_threshold,sweep_threshold,whitelist,subnet)
				detail_data=[]
				begin_time=timestr
			
			detail_data.append({"src_ip":col[1],"dst_ip":col[3],"dst_port":col[4]}) 

