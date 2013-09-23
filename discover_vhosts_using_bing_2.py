#!/usr/bin/python
# -*- coding: utf-8 -*-
# By Galkan 

__VERSION__ = '0.1'
__AUTHOR__ = 'Galkan'
__DATE__ = '23.09.2013'


try:
  	import socket
  	import struct
  	import sys
  	import re
  	import urllib2
  	import tempfile
  	import os	
  	import subprocess
	from xgoogle.search import GoogleSearch
except ImportError,e:
  	import sys
  	sys.stdout.write("%s" %e)
  	sys.exit(1)


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
			page_count, init_result = self.get_webpage(init_url, ip, 1, timeout)

			if page_count and init_result:
				for tmp_res in init_result:
					if not tmp_res in main_result:
						if not re.search(ip_regex, tmp_res):
							main_result.append(tmp_res)	


				if  int(page_count) % 10 == 0:
					for page in range(10, page_count + 1, 10):
						url = "http://www.bing.com/search?q=ip%3a" + ip + "&go=&qs=n&first=" + str(page) + "&FORM=PERE"
						result = self.get_webpage(url, ip, 0, timeout)
					
						if result:
							for tmp_res in result:
								if not tmp_res in main_result:
									if not re.search(ip_regex, tmp_res):	
										main_result.append(tmp_res)

				else:
					total_page_count = (int(page_count) + ( 10 - (int(page_count) % 10)))
	
					for page in range(10, total_page_count + 1, 10):
						url = "http://www.bing.com/search?q=ip%3a" + ip + "&go=&qs=n&first=" + str(page) + "&FORM=PERE"
						result = self.get_webpage(url, ip, 0, timeout)
					
						if result:
							for tmp_res in result:
								if not tmp_res in main_result:
									if not re.search(ip_regex, tmp_res):	
										main_result.append(tmp_res)
				url_list = []
				if main_result:
					for ip_domain in main_result:
						url_list.append(ip_domain)

					return ip,url_list

			else:
				return None

		except:
			pass



class Nmap():

	def __init__(self, nmap_path):
		self.nmap = nmap_path
		self.port_is_open_reg = re.compile("Host:\s([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\s\(\)\s+Ports:\s(80|443)/open/tcp//http")

	def port_scan(self, ip_list):
		result = []

		nmap_result_file = tempfile.NamedTemporaryFile(mode='w+t')
                nmap_result_file_name = nmap_result_file.name

		nmap_scan_option = "-n -PN -sS -T4 --open -p 80,443 --host-timeout=10m --max-rtt-timeout=600ms --initial-rtt-timeout=300ms --min-rtt-timeout=300ms --max-retries=2 --min-rate=150 %s -oG %s"% (ip_list, nmap_result_file_name)
		run_nmap = "%s %s"% (self.nmap, nmap_scan_option)

		proc = subprocess.Popen([run_nmap], 
			shell=True,
                        stdout=subprocess.PIPE,
                        )
		
		stdout_value = str(proc.communicate())

		nmap_result_file.seek(0)
		for line in nmap_result_file:
			if re.search(self.port_is_open_reg, line):
				host = re.search(self.port_is_open_reg, line).group(1)
				result.append(host)		


		nmap_result_file.close()
		if result:
			return result
		else:
			return None	



	def google_search(self, keyword):
		
		search_keyword = keyword
		gs = GoogleSearch(keyword)
		gs.results_per_page = 10000
		results = gs.get_results()

		return results

		

	def google(self, ip_url, file_type_list):
		
		print "Ip Address:			Host_Name:		Google_Output:"
		print "-----------			----------		--------------"

		result_list = []
		result_str = ""	
		for ip in ip_url.keys():
			for _f_type in file_type_list:
				f_type = _f_type.split("\n")[0]
				keyword = "filetype:%s site:%s"% (f_type,ip_url[ip][0])

				try:
					results = self.google_search(keyword)
					for _res in results:
						res =  _res.url.encode('utf8')
						hostname_reg = re.compile("https?://(.*%s)"% (f_type))
						
						if re.search(hostname_reg, res):
							res = re.search(hostname_reg, res).groups(1)[0]
							if not res in result_list:
								result_list.append(res)

				except Exception,e:
					print e.message
					pass

				
				for host in result_list:
					if not result_str:
						result_str = host 
					else:
						result_str = result_str + ", " + host

				if result_str:
					print "%s\t\t\t%s\t\t%s"% (ip, ip_url[ip][0],result_str)
				else:
					result_str = "---"
					print "%s\t\t\t%s\t\t%s"% (ip, ip_url[ip][0],result_str)
					result_str = ""
	
##	
### Main ...
##

if __name__ == '__main__':

	if not  len(sys.argv) == 4:
		print  >> sys.stderr, "Usage: %s <ip_adres/subnet> <timeout> <filetype_file>"% (sys.argv[0])
		sys.exit(1)
	
	else:
		cidr_reg = re.compile("^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/([1-9]|[1-2]\d|3[0-2])$")
		nmap_path = "/usr/bin/nmap"

		cidr_ip = sys.argv[1]
		timeout = sys.argv[2]
		filetype_file = sys.argv[3]	

		for bin in nmap_path,filetype_file:
			if not os.path.exists(bin):
				print >> sys.stderr, '%s: File Doesn\'t Exist On The System !!!'% (bin)
				sys.exit(2)

                if not ( re.search(cidr_reg,cidr_ip) ):
                        print >> stderr, "Wrong Ip Usage <ip_adress/subnetmask>"
                        sys.exit(3)


		nmap = Nmap(nmap_path)
                nmap_result = nmap.port_scan(cidr_ip)

		bing = Bing()

		if nmap_result:
			ip_url = {}
    			for ip in nmap_result:
    				result = bing.get_result(ip, timeout)    	
				if result:
					ip_addr = result[0]
					url = result[1]
					ip_url[ip_addr] = url			

			file_type_list = []	
			for f_type in open(filetype_file, "r"):
				if not f_type in file_type_list:
					file_type_list.append(f_type)

			nmap.google(ip_url, file_type_list)

		else:
			print >> sys.stderr, "Nmap Scan is not completed succesfully !!!"
			sys.exit(4)
