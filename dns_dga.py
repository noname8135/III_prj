'''
HOWTO

./normalize.sh   dns   ./dns_dga.py   all_dns_files_in_target_date

ex: ./normalize.sh  dns  ./dns_dga.py  {bro dns log folder}/{date}/dns.*

'''
import sys
import time
import argparse
from netaddr import *

if __name__=='__main__':
	parser=argparse.ArgumentParser()
	parser.add_argument('-dgat','--dga_threshold',type=int,default=300,help='customize the dga threshold')
	parser.add_argument('-qt','--query_threshold',type=int,default=3,help='customize the query threshold')
	parser.add_argument('-nt','--nxdomain_threshold',type=int,default=300,help='customize the nxdomain threshold')
	parser.add_argument('-np','--nxdomain_percentage',type=float,default=50,help='customize the nxdomain percentage threshold ,should be an integer')
	parser.add_argument('-d','--output_detail',type=int,default=1,help='output the detail information ,default means yes ,0 means no')
	parser.add_argument('-f','--whitelist_filename',type=str,default="white_domain",help='customize the white list of url and source IP ,please put the white list file in the same folder and just type the filename ,don\'t type any \'.\' in argument')
	args=vars(parser.parse_args())
	#set threshold
	dga_threshold=args['dga_threshold']
	query_threshold=args['query_threshold']
	nxdomain_threshold=args['nxdomain_threshold']
	nxdomain_percentage=float(args['nxdomain_percentage'])/100
	output_detail=args['output_detail']
	##white list for DGA
	try:
		conf=open(args['whitelist_filename'],'r')
	except IOError:
		print "Cannot open "+conf
	url_white_list=[]
	src_white_list={}
	for line in conf:
		if line[0]!='#':
			content=str(line)[:-1] #remove the new line , \n
			try :
				IPNetwork(content) #it is an IP address
				src_white_list[content]=True
			except: #it is an url
				url_white_list.append(content) 
	conf.close()

	date=None
	count=0
	f=sys.stdin
	query_list={}
	src_list={}
	for line in f:
		if line[0]=='#':
			continue
		line=line[:-1] #remove the \n
		dns_list=line.split('`')
		now,src_ip,dst_ip,dst_port,query,rcode_name=float(dns_list[0]),dns_list[1],dns_list[2],int(dns_list[3]),dns_list[4],dns_list[5]
		if date==None:
			if count<2000:
				count+=1
			else:
				date=time.strftime("%Y-%m-%d",time.localtime(now))
		judge=True

		if dst_port==53:
			##initial the src ip
			if src_ip not in src_list:
				src_list[src_ip]={}
				src_list[src_ip]['seldom_count']=0
				src_list[src_ip]['out_list']=[]
				src_list[src_ip]['total_connection']=0
				src_list[src_ip]['nxdomain_count']=0
				src_list[src_ip]['nxdomain_list']={}
			src_list[src_ip]['total_connection']+=1

			#if query is in white list , ignore
			for content in url_white_list:
				if content in query:
					judge=False
					break
			#if query is not in white list , record in dict
			if judge==True:
				if query not in query_list :
					query_list[query]=0
				query_list[query]+=1
				if query not in src_list[src_ip] and rcode_name!='NXDOMAIN': #normal dns connection
					src_list[src_ip][query]=0
				if rcode_name=='NXDOMAIN' :  # no such domain query , counld be dga
					src_list[src_ip]['nxdomain_count']+=1
					if query not in src_list[src_ip]['nxdomain_list']:
						src_list[src_ip]['nxdomain_list'][query]=0
					
			
	##counting the src ip's seldom connection
	for content in src_list.iteritems():
		for detail in content[1]:
			if detail in query_list and query_list[detail]<query_threshold:
				content[1]['seldom_count']+=1
				content[1]['out_list'].append(detail)
	
	sort_list=sorted(src_list.iteritems(),key=lambda k:k[1]['seldom_count'],reverse=False)

	##stdout
	for content in sort_list:
		if content[1]['nxdomain_count']==0:
			percent=0
		else:
			percent=float(len(content[1]['nxdomain_list']))/content[1]['nxdomain_count']

		if  content[0] not in src_white_list  and content[1]['seldom_count'] > dga_threshold \
		and content[1]['nxdomain_count']> nxdomain_threshold and percent >= nxdomain_percentage:
			print date
			print content[0]+" , total dns query="+str(content[1]['total_connection'])+" times"	
			##detail normal url
			print "normal url query , seldom query = "+str(content[1]['seldom_count'])+" times"
			if output_detail==1:
				for url in content[1]['out_list']:
					print "\t"+url
			##detail NXDOMAIN url
			print "NXDOMAIN url query , NXDOMAIN query = "+str(len(content[1]['nxdomain_list']))+\
			" kinds , NXDOMAIN total query number = "+str(content[1]['nxdomain_count'])+" times"
			if output_detail==1:
				for url in content[1]['nxdomain_list']:
					print "\t"+url
			print "\n"
	
