"""

	[H]ttp [OP]tions Checker in [PY]thon

	hoppy - a (dirty) python script to test webserver methods: 
	 		it gets options then tests all known methods not just those returned by options
	 		basic parsing is emplloyed to see if the server told us anything of interest
	 			 		
	hopclass.py is the class file for this project	
	
	Copyright (C) 14/03/2007 - deanx <RID[at]portcullis-secuirty.com>
	
	Version 1.6.4
	
	* This program is free software; you can redistribute it and/or modify
	* it under the terms of the GNU General Public License as published by
 	* the Free Software Foundation; either version 2 of the License, or
	* (at your option) any later version.
	*
 	* This program is distributed in the hope that it will be useful,
 	* but WITHOUT ANY WARRANTY; without even the implied warranty of
 	* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 	* GNU General Public License for more details.
 	*
 	* You should have received a copy of the GNU General Public License
 	* along with this program; if not, write to the Free Software
 	* Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.	

"""


import socket, re, base64, os, sys


def higlightip(message):
	messageip = regex.ip2.search(message).group()
	message = message.replace(messageip, '\033[31m' + messageip + '\033[0;0m')
	return message

def highlightpath(message):
	if regex.pathl.search(message):
		path = regex.pathl
	else:
		path = regex.pathw
	messagepath = path.search(message).group()
	message = message.replace(messagepath, '\033[31m' + messagepath + '\033[0;0m')
	return message

class connection: 
	"Server Object"
	def __init__(self):
		self.port = ''
		self.ssl = 0
		self.file = 'dummy.txt'
		self.location = '/images'
		self.timeout = 10
		self.errors = 0
		self.proxyon = 0
		self.noproxy = 0
		self.b64auth = ''
		self.connection = ''
		self.host = ''
		self.hostname = ''
		self.nossl = 0
		self.errors = 0
		self.tests = []
		self.leak = []
		self.pathleak = []
		self.ipleak = []
		self.auth = []
		self.authmethods = []
		self.extract = []
		
	def __finished(self, data, got, length): # check to see if we should wait for anymore data, return 0 on finish else length
		if data.lower().find('transfer-encoding: chunked') >= 0: # Dirty!
			if data.splitlines()[-2] == '0': # Dirtier but speeds things up !
				return 0
   			return length
		elif length < 0 and data and data.splitlines()[0].lower().find('http') == 0: # Get Content Length
			for content in data.splitlines():
				if content.lower().find('content-length') == 0:
					hhh = content.split(':')
					length = int(hhh[1])
					#print 'found length ' + str(length) + ' got so far ' + str(got) 
					break
		if (length > 0 and got < length):
			return length
		if not data or len(data.splitlines()[-1]) == 0 or (length > 0 and got > length):
			return 0
		return length


				
	def exportSummary(self, file, fof):
		file.write('\n\n[+] Summary of Findings\n')
		types = []
		ignorecodes = [404, 100, 000, 301, 400]		

		for check in self.tests:
			for rescode in check.resline:
				if (check.name + ',' + rescode[1]) not in types:
					if not (ignorecodes.count(rescode[0]) or check.name == "Info") or fof:
						sys.stdout.flush()
						types.append(check.name + ',' + rescode[1])
		if len(types) > 0:
			types.sort()
			file.write('\n\t[+] Method Responses:\n')
			for data in types:
				name, got = data.split(',', 1)
				file.write('\n\t\t%-25s -\t %s' % (name, got))
		if len(self.leak) > 0: 
			file.write('\n\n\t[+] Information Leakage:\n')	
			for data in self.leak:
				file.write('\n\t\t' + data[:115])
		if len(self.ipleak) > 0: 
			file.write('\n\n\t[+] IP Leakage:\n')	
			for data in self.ipleak:
				iph = higlightip(regex.ips.search(data).group())
				file.write('\n\t\t' + iph)
		if len(self.pathleak) > 0: 
			file.write('\n\n\t[+] PATH Leakage:\n')	
			for data in self.pathleak:
				pathh = highlightpath(data)
				file.write('\n\t\t' + pathh[:115])
		if len(self.authmethods) > 0:
			file.write('\n\n\t[+] Avaliable Auth Methods:\n\n\t\t' + str(self.authmethods))
		if len(self.auth) > 0:
			file.write('\n\n\t[+] AUTH Leakage:\n')	
			for data in self.auth:
				file.write('\n\t\tBase64 Decode: ' + data)
		if len(self.extract) > 0:
			file.write('\n\n\t[+] Extracted Data:\n')	
			for data in self.extract:
				file.write('\n\t\t' + data)
		file.write('\n\n')
				
	def summary(self):
		for job in self.tests:
			for resp in job.summary:
				resp = resp.strip()								# Find all matching headers and print once
				if resp not in self.auth and resp.lower().find('www-authenticate') == 0 or resp.lower().find('proxy-authenticate') == 0: # bas64decode the NTLM header
					if resp.split()[1] not in self.authmethods:
						if resp.split()[1] == 'Negotiate' and 'NTLM' not in self.authmethods:
							self.authmethods.append('NTLM')
						elif resp.split()[1] != 'Negotiate':	
							self.authmethods.append(resp.split()[1])
					try:
						all = resp.split()[2]
						machine = base64.b64decode(all)[56:]
						if machine not in self.auth and all.find('TlRMT') == 0:
							self.auth.append(machine)			 # Append leak text
					except TypeError:
						pass
					except IndexError:
						pass
				#auth.append(resp)
				if resp.find('{extract}') == 0:
					resp = resp.replace('{extract}', '')
					if resp not in self.extract:
						self.extract.append(resp)
					continue
				if resp not in self.pathleak and (regex.pathl.search(resp) or regex.pathw.search(resp)):
					self.pathleak.append(resp)
				if resp not in self.ipleak and regex.matchip(resp):
					self.ipleak.append(resp)
				if resp[:115] not in self.leak and resp not in self.ipleak and resp not in self.pathleak and resp not in self.extract and resp not in self.auth:
					self.leak.append(resp[:115])
		self.leak.sort()	
	
	def addAuth(self, auth):
		print '\n\t[+] Adding Basic Auth of "' + auth + '"'
		self.b64auth = base64.encodestring(auth)
	
	def removessl(self):
		self.nossl = 1
	def removeproxy(self):
		self.noproxy = 1
		
	def checkConfig(self):
		
		h = regex.host.match(self.host)
		protocol = h.group(1)
		auth = h.group(3)
		host = h.group(4)
		port = h.group(6)
		location = h.group(8)
		file = h.group(9)
		if auth:
			self.addAuth(auth)	
		if protocol and protocol.lower() == 'https://':
			if not self.nossl:
				self.ssl = 1
			if not self.port:
				self.port = '443'	
		if port:
			self.port = port
		if location:
			self.location = location
		if file:
			self.file = file	
		self.host = host
				
		if self.port == str(443) and not self.nossl:
			self.ssl = 1
		if not self.hostname:
			self.hostname = self.host
		if not self.port:
			if self.ssl:
				self.port = '443'
			else:	
				self.port = '80'	
			
		
	def send(self, test):
		timedout = 0
		returnbuff = []
		text = test.method
		connecthead = 'CONNECT ' + self.host + ':' + self.port + ' HTTP/1.1\r\nHost: ' + self.hostname + ':' + self.port + '\r\n\r\n'
		#connecthead = 'CONNECT ' + test.name + ' HTTP/1.1\r\nHost: ' + test.name + '\r\n\r\n'
		text = text.replace('(host)',self.hostname)
		text = text.replace('(realhost)',self.host)
		text = text.replace('(port)',self.port)
		if self.b64auth:
			text = text.replace('(auth)','Authorization: Basic ' + self.b64auth)
		else:
			text = text.replace('(auth)\\n','')
		text = text.replace('(location)',self.location)
		text = text.replace('(file)',self.file)
		text = text.replace('\\n','\r\n')
		split = text.split('(wait)')
		test.sent = split
		data = ''
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		length = 0
		try:
			#s.connect((host, int(port)))
			s.connect(self.connection)
			if self.ssl: # do it over ssl
				if self.proxyon:
					s.send(connecthead)
					data = s.recv(8192)
				ssl_sock = socket.ssl(s)
				for line in split:
					ssl_sock.write(line)
					s.settimeout(self.timeout)
					total_data = []
					length = -1
					while True:
						try:
							data = ssl_sock.read()
						except socket.error:
							#print 'timeout'
							break
						total_data.append(data)
						length = self.__finished(data, len(''.join(total_data)), length)
						#print length
						if not length:
							break
					returnbuff.append(''.join(total_data))
				del ssl_sock
			else: # do it over plain http
				for line in split:
					s.send(line)
					total_data = []
					s.settimeout(self.timeout)
					length = -1
					while True:
						try:
							data = s.recv(8192)
						except socket.error,e:
							timedout = 1
							break
						total_data.append(data)					
						length = self.__finished(data, len(''.join(total_data)), length)
						#print length
						if not data or not length:
							break
					returnbuff.append(''.join(total_data))
			if timedout:
				test.result = '!'
			else:
				test.result = '.'
					
		except socket.error, e:
			(num, name) = e
			#print '\n\t[!] Host Lookup Failure - ' + name + ' - Check hostname (-h)'
			test.result = name
		s.close()
	 	test.recieved = returnbuff
		
	#sys.exit(2)

class test:

	def __init__(self, name, method):
		self.name = name
		self.method	= method
		self.recieved = ''
		self.sent = ''
		self.result = ''
		self.resline = []
		self.summary = []
	
	
	def summarise(self, keywords):
		if self.recieved:
			for line in self.recieved:
				allow = line.splitlines()
				if (allow):
					match = regex.p.search(allow[0])							# match a server code 
					if match:			# Append Server Response
						code = int(match.group())
					else:
						code = 888
					self.resline.append([code, allow[0]])
					for x in allow:			# print intersting lines from server response and saves to a list
						x = x.lstrip().rstrip()
						if regex.matchip(x) or regex.pathw.search(x) or regex.pathl.search(x) and x not in self.summary:	# match an ip address and add
							self.summary.append(x)
						else: 
							for y in keywords:	# try matching keywords from file 
								name, method = y.split(',', 1)
								if ((x.find(name) >= 0 and int(method)) or x.find(name) == 0) and x not in self.summary:
									if (int(method) == 2):
										self.summary.append('{extract}' + self.name + ':\t\t ' + x)
									else:
										self.summary.append(x)
				else:
					self.resline.append([000,'HTTP/1.1 000 This Test Falied!'])
					return 1
		return 0
		

	def export(self, file, verbose):
		
		i = 0
		if verbose >= 2: # print the sent and recievned if we are in verbose mdoe.
			for line in self.sent:
				if verbose > 2:
					file.write('\n\nWe Sent:\n\n' + line + '\n')
					if len(self.recieved) > i:
						file.write('\nServer Responded:\n\n' + self.recieved[i]  + '\n')
					i = i + 1
		if verbose:
			file.write('\n\t[+] Parsed Response:' + '\n')
			for res in self.resline:
				file.write('\n\t\t' + self.name + ': ' + res[1] + '\n')
			for sum in self.summary:
				file.write('\n\t\t\t' + sum + '\n')
		elif len(self.result) == 1:
			file.write(self.result)
		else:
			file.write('\n\t[!] ' + self.result)
		file.flush()


class Callable:
    def __init__(self, anycallable):
    	self.__call__ = anycallable	

class regex:

	p = re.compile(' \d\d\d ')											# regex for matching server responce code
	ip = re.compile('(\d{1,}\.){3}\d{1,}')				# regex to match ip addresses
	ip2 = re.compile('(\d{1,3}\.){3}\d{1,3}')							# regex to match ip addresses
	ips = re.compile('.{0,60}(\d{1,3}\.){3}\d{1,3}.{0,60}') 			# regex to isoloate IP address
	pathw = re.compile('[A-z]:\\\\([^\\\\]*\\\\){0,10}')				# regex to match windows filename
	pathl = re.compile('/([^/]*/){0,10}w[we][wb]root/([^/]*/){0,10}')	# regex to match linux filename		
	host = re.compile('^(https?://)?((\S*:\S*)@)?([A-z0-9.]*)(:(\d+))?((/\S*)?/(\S*.\S*)?)?', re.I)

	def matchip(IP):
		
		if (regex.ip.search(IP)):
			octets = regex.ip.search(IP).group().split('.')
			if (int(octets[0]) == 0) or (int(octets[3]) == 0):
				return 0
			for i in octets:
				if (int(i) > 255):
					return 0
			return 1
		return 0
	
	matchip = Callable(matchip) 		

	
		

		
		
		
		
