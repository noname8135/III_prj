'''
HOWTO

./normalize.sh   dns   ./dns_abnormal.py   all_dns_files_in_target_date

ex: ./normalize.sh  dns  ./dns_abnormal.py  {bro dns log folder}/{date}/dns.*

'''
import sys
import time
import argparse

if __name__=='__main__':
	parser=argparse.ArgumentParser()
	parser.add_argument('-nt','--nxdomain_threshold',type=int,default=100,help='customize the NXDOMAIN threshold')
	parser.add_argument('-st','--servfail_threshold',type=int,default=100,help='customize the SERVFAIL threshold')
	parser.add_argument('-f','--white_list',type=str,default=None,help='customize the source IP white list')
	args=vars(parser.parse_args())
	#set threshold
	nxdomain_threshold=args['nxdomain_threshold']
	servfail_threshold=args['servfail_threshold']
	
	white_list={}
	if args['white_list']!=None:
		try:
			conf=open(args['white_list'],"r")
		except IOError:
			print "Cannot open "+args['white_list']
		for line in conf:
			if line[0]!='#':
				white_list[line[:-1]]=True
		conf.close()
	
	f=sys.stdin
	nxdomain_src={}
	nxdomain_dst={}
	servfail_src={}
	servfail_dst={}
	date=None
	count=0

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
		#in white list or not
		if src_ip in white_list:
			continue  

		##NXDOMAIN record
		if rcode_name=='NXDOMAIN':
			if src_ip not in nxdomain_src:
				nxdomain_src[src_ip]=0
			if dst_ip not in nxdomain_dst:
				nxdomain_dst[dst_ip]=0
			nxdomain_src[src_ip]+=1
			nxdomain_dst[dst_ip]+=1
		##SERVFAIL record
		elif rcode_name=='SERVFAIL':
			if src_ip not in servfail_src:
				servfail_src[src_ip]=0
			if dst_ip not in servfail_dst:
				servfail_dst[dst_ip]=0
			servfail_src[src_ip]+=1
			servfail_dst[dst_ip]+=1


	##output
	print date
	print "NXDOMAIN abnormal src ip connection :"
	for content in sorted(nxdomain_src.iteritems(),key=lambda k:k[1],reverse=True):
		if content[1] > nxdomain_threshold:
			print content[0]+"\t,\t"+str(content[1])+"  times"

	print "\nNXDOMAIN abnormal dst ip connection :"
	for content in sorted(nxdomain_dst.iteritems(),key=lambda k:k[1],reverse=True):
		if content[1] > nxdomain_threshold:
			print content[0]+"\t,\t"+str(content[1])+"  times"


	print "\nSERVFAIL abnormal src ip connection :"
	for content in sorted(servfail_src.iteritems(),key=lambda k:k[1],reverse=True):
		if content[1] > servfail_threshold:
			print content[0]+"\t,\t"+str(content[1])+"  times"

	print "\nSERVFAIL abnormal dst ip connection :"
	for content in sorted(servfail_dst.iteritems(),key=lambda k:k[1],reverse=True):
		if content[1] > servfail_threshold:
			print content[0]+"\t,\t"+str(content[1])+"  times"





