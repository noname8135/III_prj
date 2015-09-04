'''
HOWTO

./normalize.sh Input_Type ./port_report.py Target_Folder/*

ex: ./normalize.sh  CTTI  ./port_report.py  {Firewall log folder}/ctti_firewall*

'''
import sys
import os
from datetime import datetime

scan_threshold = 100
sweep_threshold= 50

scan_result={}
sweep_result={}

def cal_data(detail_data,date) :
	scan_list={}
	sweep_list={} 
	scan_incident=False
	sweep_incident=False
	for content in detail_data :
	#####port scan#####
		ip_str=content['src_ip'],content['dst_ip']
		port=content['dst_port']
		if scan_list.has_key(ip_str)==False : #first time appeared in  scan_list , create set
			scan_list[ip_str]=set(port)
		elif port not in scan_list[ip_str]: #this port first time appeared in this ip_str , add in set
			scan_list[ip_str].add(port)
			if len(scan_list[ip_str]) > scan_threshold :
				scan_incident=True
		#else : this situation means that this port in ip_str has been scan , not port scan

	#####port sweep#####
		dst_cut=content['dst_ip'].rfind('.')                                                                                                                                   
		dst_subnet=content['dst_ip'][:dst_cut]+".0/24"    # ex: 8.8.8.16 -> 8.8.8.0/24 , find the subnet/24                            
		dst_sub_ip=content['dst_ip'][dst_cut+1:]          # ex: 8.8.8.16 -> 16 , find the address in this subnet                                      
		sweep_str=content['src_ip'],dst_subnet,content['dst_port']                                                                                  
		if sweep_str not in sweep_list : #first time appeared in sweep_list ,create set                                                                  
			sweep_list[sweep_str]=set()                                                                                                               
			sweep_list[sweep_str].add(dst_sub_ip)                                                                                       
		elif dst_sub_ip not in sweep_list[sweep_str] : #this destination first time appeared in sweep_str , add in set                                  
			sweep_list[sweep_str].add(dst_sub_ip)                                                                                                
		#else : this situation means that this destination in sweep_str has been scan , not port sweep                                                  
		if len(sweep_list[sweep_str]) > sweep_threshold :                                                        
			sweep_incident=True                            
	#####output#####
	if scan_incident :
		for content in scan_list.iteritems():
			if len(content[1]) > scan_threshold :
				if scan_result.has_key(content[0])==True :
					scan_result[content[0]]+=1
				else:
					scan_result[content[0]]=1
	if sweep_incident:
		for content in sweep_list.iteritems():
			if len(content[1]) > sweep_threshold :
				if sweep_result.has_key(content[0])==True :
					sweep_result[content[0]]+=1
				else:
					sweep_result[content[0]]=1


if __name__ == '__main__':


		f=sys.stdin
		line = f.readline()	#get rid of first line(column names)
		detail_data=[]
		#initial the begin_minute
		line=f.readline()
		while (line[0]=='s' or line[0]=='t'):
			line=f.readline()
		col=line.split(",")
		if col[0][0]=='\"':
			begin_minute = col[0][1:-1]
		else:
			begin_minute=col[0]
		begin_minute=datetime.strptime(begin_minute,"%Y-%m-%d %H:%M:%S")
		detail_data.append({"src_ip":col[1],"dst_ip":col[3],"dst_port":col[4]}) 

		for line in f:
			if line[0]=='s' or line[0]=='t' :
				continue
			col=line.split(",")
			if col[0][0]=='\"':
				timestr = col[0][1:-1]
			else:
				timestr=col[0]
			timestr=datetime.strptime(timestr,"%Y-%m-%d %H:%M:%S")
			time_diff=timestr.minute-begin_minute.minute

			if  time_diff==10 or time_diff==-50 :
				cal_data(detail_data,begin_minute)
				detail_data=[]
				begin_minute=timestr
			
			detail_data.append({"src_ip":col[1],"dst_ip":col[3],"dst_port":col[4]}) 
		
		print "port scan report :"
		for key , value in sorted(scan_result.iteritems() , key= lambda(v,k):(k,v)):
			print str(key)+"  : "+str(value)+" time"
		print "\n\nsweep scan report : "
		for key , value in sorted(sweep_result.iteritems() , key= lambda(v,k):(k,v)):
			print str(key)+"  : "+str(value)+" time"

