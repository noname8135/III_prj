import sys
import os
import argparse
#import psycopg2

def output_con(con_info):
	timestr = con_info['time']
	time_flag = False
	for i in con_info:
		attacker = ''
		victim = i
		if i == 'time' or i == 'tot_con_count':
			continue
		elif con_info[i]['tot_con_count'] > threshold:	#if a dst_ip's connection
			time_flag = True
                        print "Total source ip: %d" % (len(con_info[i]) - 1)
			print "possible victim: %s, connected %d times" % (i,con_info[i]['tot_con_count'])
#                        print "victim: %s" % i
			total = con_info[i]['tot_con_count']
			con_info[i]['tot_con_count']
			for j in con_info[i]:
				if j == 'tot_con_count':
					continue
				elif con_info[i][j] > total / 5:	#if a src takes more than 20% of a ddos incident, list it as suspect
					print "  suspect:" + j
					attacker += ','+j+"_"+str(con_info[i][j])
			print ''
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
	
	if time_flag:
		print "-----------At "+ timestr + "----------\n"

if __name__ == '__main__':
	threshold = 80000	#default threshold to identify ddos connection per hour
	parser = argparse.ArgumentParser()
	parser.add_argument("-t", "--threshold",type=int, help="customize the threshold")
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
	hour = '' 
	con_info = {}
	con_info['tot_con_count'] = 0
        line_counter = 0
	for line in sys.stdin:
		columns=line.split(",")
		if 'time' in columns[0] or columns[0][0]=='#':
			continue
                if columns[0][0]=='"':
                    timestr = columns[0][1:-1]
                else:
		    timestr = columns[0]
		src_ip,dst_ip = columns[1],columns[3]
		if white_list.get(src_ip,None):
			continue
		this_hour = timestr.split(" ")[1].split(":")[0] #this_hour = hour of this line
		if this_hour != hour:
			if hour:
				output_con(con_info)	#output the collected info if connection count pass the threshold
			hour = this_hour  
			con_info.clear()
			con_info['time'] = timestr	  #timestr for this hour
			con_info['tot_con_count'] = 0   #total connection count
		else:
			con_info['tot_con_count'] += 1
			if con_info.has_key(dst_ip):
				con_info[dst_ip]['tot_con_count'] += 1
				if con_info[dst_ip].has_key(src_ip):
					con_info[dst_ip][src_ip] += 1
				else:
					con_info[dst_ip][src_ip] = 1
			else:
				con_info[dst_ip] = {}
				con_info[dst_ip][src_ip] = 1
				con_info[dst_ip]['tot_con_count'] = 1 	
	output_con(con_info)	#for 23th(the last) hour
	
