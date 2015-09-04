import sys
import os
import argparse
#import psycopg2
"""
expected input:
bro http log
#  0     1          2         3     
# ts id.orig_h id.resp_h i   uri
# ts 
"""
threshold = 30
def next_5min(start,now):
	start = int(start.split("T")[1].split(':')[1])
	now = int(now.split("T")[1].split(':')[1])
	return now-start>=5 or now-start < -50
	
def output_con(start_time,con_info):
	for i in con_info:
		#print len(con_info[i])
		if len(con_info[i]['uri'])>threshold:
			src,dst = i.split("!!!")[0], i.split("!!!")[1]
			print start_time+"\t"+src+"\t"+dst+"\t"+str(len(con_info[i]['uri'])),
			if 'HTTP::URI_SQLI' in con_info[i]['tag']:
				print '\tSQLI attempt' 
			else:
				print '\tcrawling'
			#print con_info[i]
			
	"""
	if time_flag:
		print "-----------At "+ timestr +"----------\n"
	"""
	"""
			try:
				con = psycopg2.connect(database='iii_prj', user='iii_prj',password='ilovesgc',port='1234',host='140.123.103.160') 
				cur = con.cursor()			#holder of returned result     
				query = "INSERT INTO ddos(id,start_time,con_num,atker_ip,victim_ip,from_org) "
				query += "VALUES(DEFAULT,%s,%s,%s,%s,%s)"
				value = (timestr,con_info[i]['tot_con_count'],attacker,victim,org)
				cur.execute(query,value) 
				con.commit()
			except psycopg2.DatabaseError, e:
				print 'Error %s' % e    
				sys.exit(1)
			"""

if __name__ == '__main__':
	parser = argparse.ArgumentParser()
	parser.add_argument("-t", "--threshold",type=int, help="customize the threshold (connections per hour)")
	parser.add_argument('-f','--white_list',type=str,default=None,help='customize the source IP white list')
	args = vars(parser.parse_args())
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

	if args['threshold']:
		threshold = args['threshold']
	target_list = ['.php','.pdf','.html','.htm','.aspx']
	start_time = ''
	last_one = ''
	start_flag =True
	con_info = {}		#dict {'scr_ip!!!dst_ip':'uri'}
	for line in sys.stdin:
		columns=line.split("\t")
		timestr,src_ip,dst_ip,tag = columns[0],columns[1],columns[2],columns[4]
		if white_list.get(src_ip,None):
			continue
		'''status_code = columns[4].replace("\n","")
		if status_code == '304' or status_code=='-':
			continue
		'''
		uri = columns[3].split('?')[0].replace("\n","")
		
		
		if 'time' in columns[0] or uri=='-':	
			continue
		uri_last_sec = uri.split('/')[-1]	#get last section of url
		skip_flag = True
		for i in target_list:
			if uri_last_sec.endswith(i):
				skip_flag = False
				break
		if skip_flag or last_one == src_ip+dst_ip+uri:	#for acceleration, if it's exactly the same as last line of record,
			continue
		if not start_time:
			if int(timestr.split("T")[1].split(':')[1]) > 0:
				continue
			start_time = timestr
		last_one = src_ip+dst_ip+uri
		#print timestr, src_ip, dst_ip, uri
		if_output = next_5min(start_time,timestr)
		if if_output:
			output_con(start_time,con_info)
			con_info.clear()
			con_info = {}
			start_time = timestr	  #timestr for this time_sec_5min
		else:
			key = src_ip + '!!!' + dst_ip
			if not con_info.has_key(key):
				con_info[key]={}
				con_info[key]['uri'] = set()
				con_info[key]['tag'] = set()
			con_info[key]['uri'].add(uri)
			if 'empty' not in tag:
				con_info[key]['tag'].add(tag[:-1])
	output_con(start_time,con_info)	#for 23th(the last) time_sec_5min
	
