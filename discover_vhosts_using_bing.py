#!/usr/bin/python
# -*- coding: utf-8 -*-
# By Galkan 


try:
  import socket
  import struct
  import sys
  import re
  import urllib2
  import tempfile
except ImportError,e:
  import sys
  sys.stdout.write("%s" %e)
  sys.exit(1)


class InvalidIPAddress(ValueError):
    "The ip address given to ipaddr is improperly formatted"



class IpRange():
	"""
		Derived from http://www.randomwalking.com/snippets/iprange.text
	"""

	def ipaddr_to_binary(self,ipaddr):
    		q = ipaddr.split('.')
    		return reduce(lambda a,b: long(a)*256 + long(b), q)
   


	def binary_to_ipaddr(self,ipbinary):
    		return socket.inet_ntoa(struct.pack('!I', ipbinary))
    


	def iprange(self, ipaddr):
    		span_re = re.compile(r'''(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})   # The beginning IP Address
                             \s*-\s*
                             (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})   # The end IP Address
                          ''', re.VERBOSE)

    		res = span_re.match(ipaddr)
    		if res:
        		beginning = res.group(1)
        		end = res.group(2)
        		return span_iprange(beginning, end)
                                 
    		cidr_re = re.compile(r'''(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})   # The IP Address
                             /(\d{1,2})                             # The mask
                          ''', re.VERBOSE)

    		res = cidr_re.match(ipaddr)
    		if res:
        		addr = res.group(1)
        		cidrmask = res.group(2)
        		return self.cidr_iprange(addr, cidrmask)

    		wild_re = re.compile(r'''(\d{1,3}|\*)\.
                             (\d{1,3}|\*)\.
                             (\d{1,3}|\*)\.
                             (\d{1,3}|\*)   # The IP Address
                          ''', re.VERBOSE)

    		res = wild_re.match(ipaddr)
    		if res:
        		return wildcard_iprange(ipaddr)
   
    		raise InvalidIPAddress 


	def span_iprange(self, beginning, end):
    		b = self.ipaddr_to_binary(beginning) 
    		e = ipaddr_to_binary(end) 

    		while (b <= e):
        		yield binary_to_ipaddr(b)
        		b = b + 1

    

	def cidr_iprange(self, ipaddr, cidrmask):
    		mask = (long(2)**long(32-long(cidrmask))) - 1

    		b = self.ipaddr_to_binary(ipaddr) 
    		e = self.ipaddr_to_binary(ipaddr) 
    		b = long(b & ~mask)
    		e = long(e | mask)

    		while (b <= e):
        		yield self.binary_to_ipaddr(b)
        		b = b + 1



	def wildcard_iprange(ipaddr):

		beginning = [] 
    		end = [] 
    
    		tmp = ipaddr.split('.')
    		for i in tmp:
        		if i == '*':
            			beginning.append("0")
            			end.append("255") 
        		else:
            			beginning.append(i)
            			end.append(i) 

    		b = beginning[:]
    		e = end[:]
    
    		while int(b[0]) <= int(e[0]):
        		while int(b[1]) <= int(e[1]):
            			while int(b[2]) <= int(e[2]):
                			while int(b[3]) <= int(e[3]):
                    				yield b[0] + '.' + b[1] + '.' + b[2] + '.' + b[3]
                    				b[3] = "%d" % (int(b[3]) + 1)

                			b[2] = "%d" % (int(b[2]) + 1)
                			b[3] = beginning[3]

            			b[1] = "%d" % (int(b[1]) + 1)
            			b[2] = beginning[2]

        		b[0] = "%d" % (int(b[0]) + 1)
        		b[1] = beginning[1]



class Bing():

	def __init__(self):
		"""
			Define regex 
		"""

		self.regex_url = re.compile("<h3><a href=\"http(s)?://([^/]+)")
		self.regex_count = re.compile("<span class=\"sb_count\" id=\"count\">([0-9]+)")


	def get_webpage(self, url, ip, count_or_data, timeout):
		"""
			Fetch web page and return url extracted
		"""
		# count_or_data = 1 means that return count

		result_list = []
		page_count = 30

		output_file = tempfile.TemporaryFile(mode='w+t')
		web_page_url_1 = urllib2.Request("%s"% (url))

		try:
	                web_page_url_2 = urllib2.urlopen(web_page_url_1, timeout = int(timeout))
                except Exception,e:
			web_page_url_2.close()
			output_file.close()

        	        return None

		try:
			page_result = str(web_page_url_2.read())
		except Exception,e:
			output_file.close()
			web_page_url_2.close()

                        return None


		output_file.writelines(page_result)
		web_page_url_2.close()


		output_file.seek(0)
                for line in output_file:
			if count_or_data == 1:
				if ( re.search(self.regex_count, line) ):
					page_count = re.search(self.regex_count, line).group(1)
					

			result = re.findall(self.regex_url, line)
			if result:
				for res in result:
					if not res[1] in result_list:
						result_list.append(res[1])	

		output_file.close()

		if count_or_data == 1:
			return page_count, result_list
		else:
			return result_list			 



	def get_result(self, ip, timeout):
		"""
			Main function 
		"""

		result = []
		init_result = []
		main_result = []

		ip_regex = re.compile("^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$")

		init_url = "http://www.bing.com/search?q=ip%3a" + ip + "&go=&qs=n&first=00&FORM=PERE"

		try:
			page_count, init_result = self.get_webpage(init_url,ip, 1, timeout)

			if page_count and init_result:
				for tmp in init_result:
					if not tmp in main_result:
						main_result.append(tmp)	
	
				if  int(page_count) % 10 == 0:
					for page in range(10, page_count + 1, 10):
						url = "http://www.bing.com/search?q=ip%3a" + ip + "&go=&qs=n&first=" + str(page) + "&FORM=PERE"
						result = self.get_webpage(url, ip, 0, timeout)
					
						if result:
							for tmp_res in result:
								if not tmp_res in main_result:
									main_result.append(tmp_res)

				else:
					total_page_count = (int(page_count) + ( 10 - (int(page_count) % 10)))
	
					for page in range(10, total_page_count + 1, 10):
						url = "http://www.bing.com/search?q=ip%3a" + ip + "&go=&qs=n&first=" + str(page) + "&FORM=PERE"
						result = self.get_webpage(url, ip, 0, timeout)
					
						if result:
							for tmp_res in result:
								if not tmp_res in main_result:
									main_result.append(tmp_res)

				if main_result:
					for ip_domain in main_result:
						if not re.search(ip_regex,ip_domain):
                                                        print "%s : %s"% (ip,ip_domain)
						
			else:
				return None
		except:
			pass


if __name__ == '__main__':


	if not  len(sys.argv) == 3:
		print "Usage: %s <ip_adres/subnet> <timeout>"% (sys.argv[0])
		sys.exit(1)	
	else:	
		cidr_ip = sys.argv[1]
		timeout = sys.argv[2]
	
		cidr_reg = re.compile("^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/([1-9]|[1-2]\d|3[0-2])$")

                if not ( re.search(cidr_reg,cidr_ip) ):
                        print "Ip Adresi Belirtimi Yanlis. <ip_adresi/subnetmask>"
                        sys.exit(2)

		ip_range = IpRange()
		bing = Bing()

    		for ip in ip_range.iprange(cidr_ip):
    			bing.get_result(ip, timeout)    	
