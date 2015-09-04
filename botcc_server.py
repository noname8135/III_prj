import requests
import sys
import re 
import argparse
#import psycopg2
import datetime

def parse_and_collect():	#get and parse data from web, and return a list of (ip,port) tuple
	s = requests.Session()
	data = s.get("https://rules.emergingthreats.net/open/snort-2.9.0/rules/emerging-botcc.rules")
	if data.status_code != 200:
		print "The botcc server list site isn't available "
		sys.exit()
	data2 = s.get("https://rules.emergingthreats.net/open/snort-2.9.0/rules/emerging-botcc.portgrouped.rules")
	if data2.status_code != 200:
		print "The botcc server list site isn't available "
		sys.exit()

	ip_set = set()
	for line in data.iter_lines():
		if line.startswith("#") or len(line) < 10:
			continue
		result = re.search('any -> (.*) any', line)
		
		ip_list = result.group(1).split(',')
		for ip in ip_list:
			if ip.startswith('['):
				ip_set.add(ip[1:])
			elif ip.endswith(']'):
				ip_set.add(ip[:-1])
			else:
				ip_set.add(ip)

	for line in data2.iter_lines():
		if line.startswith("#") or len(line) < 10:
			continue
		result = re.search('any -> (.*) (\d+) \(msg', line)
		ip_list = result.group(1).split(',')
		for ip in ip_list:
			if ip.startswith('['):
				ip_set.add(ip[1:])
			elif ip.endswith(']'):
				ip_set.add(ip[:-1])
			else:
				ip_set.add(ip)
	update_to_db(ip_set)
	return ip_set
	
def update_to_db(ip_set):
	today = "%s-%s-%s" % (datetime.datetime.now().year, datetime.datetime.now().month, datetime.datetime.now().day)	#get date of today 
	con = psycopg2.connect(database='iii_prj', user='iii_prj',password='ilovesgc',port='1234',host='140.123.103.160') 
	cur = con.cursor()			#holder of returned result
	for i in ip_set:	#iterate through ip in blacklist
		query = "INSERT INTO blacklist(id,ip,rec_date) VALUES (DEFAULT,%s,%s)"
		try:
			value = i,"%s" % (today)
			cur.execute(query,value)
			con.commit()
			print "%s INSERTED" % i
		except:
			con.rollback()
			query = "UPDATE blacklist SET rec_date='%s' WHERE ip='%s'" % (today,i)	
			cur.execute(query)
			con.commit()
			
			print "%s, %s UPDATED" % (today,i)
		

if __name__ == '__main__':
#	parse_and_collect() #get C&C ip list and update to db
    parser = argparse.ArgumentParser()
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

	ip_exist = {}	#if ip is in blacklist, ip_exist[$ip] = True
        """
        for i in ip_set:
		ip_exist[i] = True
	"""
        f=open("blacklist.csv","r")
        for line in f:
            if not line:
                continue
            ip = line.replace('"','').replace('/','-').replace("\n",'').split(' ')[1]
            ip_exist['.'.join(re.findall('[\d]+',ip))] = True
        print "format: time src_ip src_port dst_ip dst_port"
        for line in sys.stdin:
		columns=line.split(",")
        	if 'time' in columns[0]:
		    continue
		timestr = columns[0][1:]
		src_ip,src_port,dst_ip,dst_port = columns[1],columns[2],columns[3],columns[4]
		if white_list.get(src_ip,None):
					continue
                if not src_ip or not dst_ip:
                    continue
                if ip_exist.get(src_ip,False):
                    print "src detected: "+timestr+" "+src_ip+' '+src_port+" "+ dst_ip+" "+dst_port
		elif ip_exist.get(dst_ip,False):
                    print "dst detected: "+timestr+" "+src_ip+' '+src_port+" "+ dst_ip+" "+dst_port
