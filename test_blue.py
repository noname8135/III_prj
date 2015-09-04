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
"""
usage: Blur ip, email, domain name in log
"""
key='test_key'


def ip_encrypt(str_to_be_enc,key,subnet):
	if subnet==32 :
		return str_to_be_enc
	hashed_key=SHA.new(key).digest()
	cipher=ARC4.new(hashed_key)
	ip_addr = []
	enc_ip_addr=''
	i=0
	digits = re.compile('\d+')
	iterator = digits.finditer(str_to_be_enc)
	for match in iterator:
		if i<subnet:
			enc_ip_addr+=match.group()+"."
		else:
			ip_addr.append(int(match.group()))
		i+=8
	ip_bytes = "".join(map(chr, ip_addr))
	enc_ip_bytes = cipher.encrypt(ip_bytes)
	for letter in enc_ip_bytes :
		enc_ip_addr+=str(ord(letter))+'.'
	return enc_ip_addr[:-1]

def ip_decrypt(str_to_be_dec, key, subnet):
	hashed_key=SHA.new(key).digest()
	cipher=ARC4.new(hashed_key)
	ip_addr = []
	dec_ip_addr=''
	i=0
	digits = re.compile('\d+')
	iterator = digits.finditer(str_to_be_dec)
	for match in iterator:
		if i<subnet:
			dec_ip_addr+=match.group()+"."
		else:
			ip_addr.append(int(match.group()))	
		i+=8
	ip_bytes = "".join(map(chr, ip_addr))
	dec_ip_bytes = cipher.decrypt(ip_bytes)
	for letter in dec_ip_bytes:
		dec_ip_addr+=str(ord(letter))+'.'
	return dec_ip_addr[:-1]

def ip_judge(text, blur_ip_list, key, kind_of_action) : #ipv4 encrypt/decrypt or not
	if (kind_of_action=='enc'):
		if (blur_ip_list==[]):  # If IP block list is empty , encrypting all ip
			return ip_encrypt(text,key,0)
		ip=IPNetwork(text)
		for ip_list in blur_ip_list:
			if ip in ip_list:
				return ip_encrypt(str(ip.ip),key,ip_list.prefixlen) #encrypt subnet part
		return text  # don't encrypt
	else:
		if (blur_ip_list==[]):  # If IP block list is empty , encrypting all ip
			return ip_decrypt(text,key,0)
		ip=IPNetwork(text)
		for ip_list in blur_ip_list:
			if ip in ip_list:
				return ip_decrypt(str(ip.ip),key,ip_list.prefixlen)
		return text  # don't decrypt

def my_encrypt(text, key):	#return encrypted text string
	hashed_key=SHA.new(key).digest()
	cipher=ARC4.new(hashed_key)
	return base64.b64encode(cipher.encrypt(text))

def my_decrypt(enc,key):
	enc=base64.b64decode(enc)
	hashed_key=SHA.new(key).digest()
	cipher=ARC4.new(hashed_key)
	return cipher.decrypt(enc)
	
#base64 -> [\w\+\/]
def enc_all_word(text, key, group, blur_ip_list):	#encrypt whole target string
	"""
		encrypt only alphanumeric chars, 
		and keep non-alphanumeric chars plaintext.
	"""	
	encrypted_str=''
	"""
	if (group[11]): #for ipv6
		try:
			socket.inet_pton(socket.AF_INET6,text) #test ipv6 or not
			substring_list=re.split(':',text)
			embedded_ipv4=''
			if (text.find('.')!=-1): #ipv4 inside
				embedded_ipv4+=substring_list[-1]
				substring_list.pop()  #remove ipv4 part
				embedded_ipv4=":"+ip_encrypt(embedded_ipv4,key,0)
			for substring in substring_list:
				encrypted_str+=my_encrypt(substring,key)+":"
			return "!!!"+encrypted_str[:-1]+embedded_ipv4+"!!!"
		except:  #ipv6 regex fail
			return text
	"""
	'''
	for i in range(0,6):
		print i, group[i]
	print text, "\n"
	'''
	if group[0]:	#for ip
		return ip_judge(text,blur_ip_list,key,'enc')
	elif group[2]: #for email
		substring_list=re.split('@',text)
		encrypted_str+=my_encrypt(substring_list[0],key)+'@'
		substring_list.remove(substring_list[0])
		substring_list=re.split('\.',substring_list[0])
		for substring in substring_list:
			encrypted_str+=my_encrypt(substring,key)+'.'
		return "!!!"+encrypted_str[:-1]+"!!!"
	elif group[4] : #for dn
		substring_list=re.split('\.',text)
		for substring in substring_list:
			encrypted_str+=my_encrypt(substring,key)+'.'
		return "!!!"+encrypted_str[:-1]+"!!!"
	else: 
		return text

def dec_all_word(cipher, key, blur_ip_list):
	if cipher[0]=='!':
		cipher=cipher[3:-3]
	if (cipher.find(':')==-1 and re.match(get_pattern('ipv4'),cipher)): #avoid ipv6 embedded ipv4
		return ip_judge(cipher,blur_ip_list,key,'dec')
	else:
		substring_list = re.split("\.|@|:", cipher)
		decrypted_str = ''
		if (cipher.find(':')==-1): #domain name and email
			if (cipher.find('@')!=-1): #email
				decrypted_str+=my_decrypt(substring_list[0],key)+'@'
				substring_list.remove([0])
			for substring in substring_list:
				decrypted_str+=my_decrypt(substring,key)+'.'
			return decrypted_str[:-1] #-1 for taking off the last pattern
		"""
		else: #ipv6
			dec_embedded_ipv4=''
			if (cipher.find('.')!=-1): #ipv4 inside
				dec_embedded_ipv4+=substring_list[-4]+"."+substring_list[-3]+"."+substring_list[-2]+"."+substring_list[-1]
				for i in range(4):
					substring_list.pop() #remove ipv4 part
				dec_embedded_ipv4=":"+ip_decrypt(dec_embedded_ipv4,key)
			for substring in substring_list:
				decrypted_str+=my_decrypt(substring,key)+":"
			return decrypted_str[:-1]+dec_embedded_ipv4
		"""
def read_config(config_file,blur_ip_list,trigger) :
	for line in config_file :
		if line[0]=='#':
			continue
		opt_list=re.split('\s',line)
		if (opt_list[0]=='email' and opt_list[1]=='off') :
			trigger[0]=False
		elif (opt_list[0]=='dn' and opt_list[1]=='off') :
			trigger[1]=False
		elif (re.match(get_pattern('ipv4')+"/\d\d?",opt_list[0])) :
			blur_ip_list.append(IPNetwork(opt_list[0]))	

def get_pattern(type):
	if (type == 'ipv4'):
		return '(\d{1,3}(\.\d{1,3}){3})'
	elif (type == 'email'):
		return '([\w_+-]+@[\w]+(\.[\w]+)+)'
	elif (type == 'dn'): #domain name
		return '(\w+(\.\w+)+(\/\w+)*(\w\/)*)'
	#elif (type == 'ipv6'):
	#	return '([0-9a-fA-F]{0,4}:)(:?[0-9a-fA-F]{0,4}:?){1,6}(:[0-9a-fA-F]{0,4}:?:?)((\.(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])){3})?'
	elif (type=='decrypt'):
		return "!!![\w\.\/@\-\+\=:]+!!!|(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])(\.(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])){3}"
	else:
		print "Invalid type! \n"
		sys.exit()

def testfunc(match_obj): 
	#print "IIIIIIIIIIIIIIIIIIIIIIIIIIIII", aaa.group(0) , aaa.group(1) , aaa.group(2), aaa.group(3), aaa.group(4), aaa.group(5)
	#return 'shut'
	encrypted_str = ''
	if match_obj.group(1):	#for ip
		return ip_judge(match_obj.group(1),blur_ip_list,key,'enc')
	elif match_obj.group(3): #for email
		substring_list=re.split('@',match_obj.group(3))
		encrypted_str+=my_encrypt(substring_list[0],key)+'@'
		substring_list.remove(substring_list[0])
		substring_list=re.split('\.',substring_list[0])
		for substring in substring_list:
			encrypted_str+=my_encrypt(substring,key)+'.'
		return "!!!"+encrypted_str[:-1]+"!!!"
	elif match_obj.group(5) : #for dn
		substring_list=re.split('\.',match_obj.group(5))
		for substring in substring_list:
			encrypted_str+=my_encrypt(substring,key)+'.'
		return "!!!"+encrypted_str[:-1]+"!!!"
	else: 
		return match_obj.group(0)


if __name__ == '__main__':
	parser = argparse.ArgumentParser()
	group = parser.add_mutually_exclusive_group()
	group.add_argument("-e", "--encrypt", action="store_true", help="encrypt the input file")
	group.add_argument("-d", "--decrypt", action="store_true", help="decrypt the input file")
	parser.add_argument("-o", "--outfile", help="the output file (stdout by default if missing)")
	parser.add_argument("-k", "--key", help="the key value", required=True)
	parser.add_argument("-c", "--conf", help="the config file")
	parser.add_argument("infile", help="input file")	
	args = parser.parse_args()
	key = args.key
	#start_time=time.time()
	if args.outfile:
		out_log = open(args.outfile,'w')
	else:
		out_log = sys.stdout
	blur_ip_list=[]
	trigger=[True,True]# 0 = email_trigger , 1 = dn_trigger

	
	if args.conf:
		conf_file = open(args.conf, "r")
		read_config(conf_file,blur_ip_list,trigger)
	if args.encrypt:
		pattern = get_pattern('ipv4')
		if trigger[0]:
			pattern += '|'+get_pattern('email')
		if trigger[1]:
			pattern += '|'+get_pattern('dn')
	else:
		pattern = get_pattern('decrypt')

	f = file(args.infile,'r')
	
	for line in f:
		if len(line) < 3:
			continue
		enc_line = ''
		walker = 0
		result = re.finditer(pattern, line)		#process one line at a time
		
		if (args.encrypt):
			enc_line += re.sub(pattern,testfunc,line)
			out_log.write(enc_line)
		else:
			for m in result:
				target_str = line[m.start():m.end()]
				enc_line += line[walker:m.start()] + dec_all_word(target_str,args.key,blur_ip_list)
				walker=m.end()
		
		

	#stop_time=time.time()
	#print (stop-start)

