#!/usr/bin/python3
from urllib.request import urlopen
#https://pypi.org/project/termcolor/
from termcolor import colored
import hashlib
import optparse
import sys,os

#encryption
def encryption(word,type):
	if type == 'md5':
		hash1=hashlib.md5(bytes(word,'utf-8')).hexdigest()
		print (colored("\n[+] Encrypted Hash : "+str(hash1),'green'))
		exit(0)
	if type == 'sha1':
		hash2 = hashlib.sha1(bytes(word,'utf-8')).hexdigest()
		print (colored("\n[+] Encrypted Hash : "+str(hash2),'green'))
		exit(0)
	if type == 'sha256':
		hash3 = hashlib.sha256(bytes(word,'utf-8')).hexdigest()
		print (colored("\n[+] Encrypted Hash : " +str(hash3),'green'))
		exit(0)
	if type == 'sha384':
		hash4 = hashlib.sha384(bytes(word,'utf-8')).hexdigest()
		print (colored("\n[+] Encrypted Hash : " +str(hash4),'green'))
		exit(0)
	if type == 'sha512':
		hash5 = hashlib.sha512(bytes(word,'utf-8')).hexdigest()
		print (colored("\n[+] Encrypted Hash : " +str(hash5),'green'))
		exit(0)

#Decryption
def decryption(hash,lenth,wordlist):
	try:
		path = os.path.exists(wordlist)
		if path == True:
			password = open(wordlist,'r')
			if lenth == '32':
				for passwd in password:
					line = passwd.strip()
					hashobj1 = hashlib.md5(bytes(line,'utf-8')).hexdigest()
					key = hashobj1
					if key == hash:
						print (colored("\n[+] Cracked Key is : "+str(line),'green'))
						exit(0)
				print (colored("\n[-] Password Not Found ",'red'))
				exit(0)
			if lenth == '40':
				for passwd in password:
					line = passwd.strip()
					hashobj1 = hashlib.sha1(bytes(line,'utf-8')).hexdigest()
					key = hashobj1
					if key == hash:
						print (colored("\n[+] Cracked Key is : "+str(line),'green'))
						exit(0)
				print (colored("\n[-] Password Not Found ",'red'))
				exit(0)
			if lenth == '64':
				for passwd in password:
					line = passwd.strip()
					hashobj1 = hashlib.sha256(bytes(line,'utf-8')).hexdigest()
					key = hashobj1
					if key == hash:
						print (colored("\n[+] Cracked Key is : "+str(line),'green'))
						exit(0)
				print (colored("\n[-] Password Not Found ",'red'))
				exit(0)
			if lenth == '96':
				for passwd in password:
					line = passwd.strip()
					hashobj1 = hashlib.sha384(bytes(line,'utf-8')).hexdigest()
					key = hashobj1
					if key == hash:
						print (colored("\n[+] Cracked Key is : "+str(line),'green'))
						exit(0)
				print (colored("\n[-] Password Not Found ",'red'))
				exit(0)
			if lenth == '128':
				for passwd in password:
					line = passwd.strip()
					hashobj1 = hashlib.sha512(bytes(line,'utf-8')).hexdigest()
					key = hashobj1
					if key == hash:
						print (colored("\n[+]Cracked Key is : "+str(line),'green'))
						exit(0)
				print (colored("\n[-] Password Not Found",'red'))
				exit(0)
		else:
			print (colored("[!!] File Does not exists",'red'))
	except:
		pass


#Online Passwd to crack a hash
def online_dir(hash,lenth):
	wordlist = str(urlopen('https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-10000.txt').read(),'utf8')
	if lenth == '32':
		for word in wordlist.split('\n'):
			crack = hashlib.md5(bytes(word,'utf8')).hexdigest()
			if crack == hash:
				print (colored("\n[+] Cracked key Is: "+str(word),'green'))
				exit(0)

		print (colored("\n[-] Password Not Found..!",'red'))
		exit(0)
	if lenth == '40':
		for word in wordlist.split('\n'):
                        crack = hashlib.sha1(bytes(word,'utf8')).hexdigest()
                        if crack == hash:
                                print (colored("\n[+] Cracked key Is: "+str(word),'green'))
                                exit(0)
		print (colored("\n[-] Password Not Found..!",'red'))
		exit(0)
#no problem
	if lenth == '64':
		for word in wordlist.split('\n'):
			crack = hashlib.sha256(bytes(word,'utf8')).hexdigest()
			if crack == hash:
				print (colored("\n[+] Cracked key Is: "+str(word),'green'))
				exit(0)
		print (colored("\n[-] Password Not Found..!",'red'))
		exit(0)
	if lenth == '96':
		for word in wordlist.split('\n'):
			crack = hashlib.sha384(bytes(word,'utf8')).hexdigest()
			if crack == hash:
				print (colored("\n[+] Cracked key Is: "+str(word),'green'))
				exit(0)
		print (colored("\n[-] Password Not Found..!",'red'))
		exit(0)
	if lenth == '128':
		for word in wordlist.split('\n'):
			crack = hashlib.sha512(bytes(word,'utf8')).hexdigest()
			if crack == hash:
				print (colored("\n[+] Cracked key Is: "+str(word),'green'))
				exit(0)
		print (colored("\n[-] Password Not Found..!",'red'))
		exit(0)



def banner():
	print(colored(""" 


██╗░░██╗░█████╗░░██████╗██╗░░██╗  ░█████╗░██████╗░░█████╗░░█████╗░██╗░░██╗███████╗██████╗░
██║░░██║██╔══██╗██╔════╝██║░░██║  ██╔══██╗██╔══██╗██╔══██╗██╔══██╗██║░██╔╝██╔════╝██╔══██╗
███████║███████║╚█████╗░███████║  ██║░░╚═╝██████╔╝███████║██║░░╚═╝█████═╝░█████╗░░██████╔╝
██╔══██║██╔══██║░╚═══██╗██╔══██║  ██║░░██╗██╔══██╗██╔══██║██║░░██╗██╔═██╗░██╔══╝░░██╔══██╗
██║░░██║██║░░██║██████╔╝██║░░██║  ╚█████╔╝██║░░██║██║░░██║╚█████╔╝██║░╚██╗███████╗██║░░██║
╚═╝░░╚═╝╚═╝░░╚═╝╚═════╝░╚═╝░░╚═╝  ░╚════╝░╚═╝░░╚═╝╚═╝░░╚═╝░╚════╝░╚═╝░░╚═╝╚══════╝╚═╝░░╚═╝
								        @𝕾𝖆𝖗𝖆𝖛𝖆𝖓𝖆 𝕾𝖊𝖊𝖐𝖊𝖗
""",'red'))
	print (colored("""Support Only
-md5	-sha256    -sha512

-sha1	-sha384

 """,'magenta'))






#main()

def main():
	parser = optparse.OptionParser("Usage of Program:" + " -e <Encryption mode>" + " -t <type of hash>" +" -s <String to hash>" +" -d <Decryption mode>" + " -H <define the Hash>"  + " -w <wordlist for bruteforce>" + " -n <without wordlist>")
	parser.add_option('-e','--encrypt',dest='encrypt',action='store_true',help='encryption mode')
	parser.add_option('-s','--string',dest='word',help='Enter the String to hash')
	parser.add_option('-d','--decrypt',dest='decrypt',action='store_true',help='decryption mode')
	parser.add_option('-H','--hash',dest='hash',help='paste the hash')
	parser.add_option('-t','--type',dest='type',help='type of hash')
	parser.add_option('-w','--wordlist',dest='wordlist',help='Entrer the path of the wordlist to bruteforce')
	parser.add_option('-n','--without',dest='online',action='store_true',help='without wordlist using online file')
	(options,args) = parser.parse_args()
	encrypt = options.encrypt
	word = options.word
	decrypt = options.decrypt
	hash = options.hash
	type = options.type
	wordlist = options.wordlist
	online = options.online
	#if (encrypt == None):
		#print (colored(parser.usage,'yellow'))
		#exit(0)
	banner()
	if len(sys.argv)< 3:
		print (colored(parser.usage,'yellow'))
	if (encrypt == True) :
		encryption(word,type)
	if (decrypt == True):
		lenth = str(len(hash))
		decryption(hash,lenth,wordlist)
	if (online == True):
		print (colored("Cracking....!",'yellow'))
		online_dir(hash,lenth)



if __name__ == '__main__':
	main()
