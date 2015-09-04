import Crypto
#import pdb
import sys, argparse
import re
import time
import socket
from Crypto.Hash import SHA
from Crypto.Cipher import ARC4
from Crypto import Random
import base64
from netaddr import *
from IPy import IP
import pprint
#base64 -> [\w\+\/]

def get_pattern(type):
	if (type == 'email'):
		return '([\w_+-]+@[\w]+(\.[\w]+)+)'
	elif (type == 'ipv4'):
		return '(!!!)?(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])(\.(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])){3}(!!!)?'
	elif (type == 'dn'): #domain name
		return '([a-zA-Z]+(\.\w+)+(\/\w+)*(\w\/)*)'
	elif (type == 'ipv6'):
		return '([0-9a-fA-F]{0,4}:)(:?[0-9a-fA-F]{0,4}:?){1,6}(:[0-9a-fA-F]{0,4}:?:?)((\.(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])){3})?'
	elif (type=='decrypt'):
		return "!!![\w\.\/@\-\+\=:]+!!!"
	else:
		print "Invalid type! \n"
		sys.exit()

if __name__ == '__main__':
	parser = argparse.ArgumentParser()
	group = parser.add_mutually_exclusive_group()
	parser.add_argument("-o", "--outfile", help="the output file (stdout by default if missing)")
	parser.add_argument("infile", help="input file")	
	##################################
	args = parser.parse_args()
	if args.outfile:
		out_log = open(args.outfile,'w')
	else:
		out_log = sys.stdout
	f = file(args.infile,'r')
	pattern = get_pattern('ipv4')+'|'+get_pattern('email')+'|'+get_pattern('dn')+'|'+get_pattern('ipv6')
	for line in f:
		enc_line = ""
		walker = 0
		result = re.finditer(pattern, line)		
		for m in result:
			target_str = line[m.start():m.end()]	
			if (m.groups()[13]): #ipv6
				try:
					socket.pton(socket.AF_INET6,target_str) #it is real ipv6 or not
					print "an ipv6 fail"
				except: #ipv6 regex fail
					continue
			if (m.groups()[1]): #ipv4 , groups[0] is !!! , we make sure it's an ipv4 first
				try:
					if (IP(target_str).iptype()=='PRIVATE' ): #it is private ipv4 or not
						continue
				except:
					if (target_str[0]=='!'): #it is an encrypted ipv4
						continue
					enc_line+=target_str+"\n"
					walker=m.end()
					print "an ipv4 fail"
					continue
			#email and domain name situation , could be base64 code
			#if it is base64 code , you can ignore this
			#if not , it is email or domain fail
			enc_line +=  target_str +"\n"
			walker = m.end()
		out_log.write(enc_line)



