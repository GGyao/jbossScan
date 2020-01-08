#coding=utf-8
#by GGyao

import sys
import requests

requests.packages.urllib3.disable_warnings()

headers = {
	"User-Agent":"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:67.0) Gecko/20100101 Firefox/67.0"
}

vuls=['/jmx-console','/web-console','/invoker/JMXInvokerServlet','/admin-console','/jbossmq-httpil/HTTPServerILServlet','/invoker/readonly']

def main():
	for target in open("target.txt"):
		target=target.strip()
		print ("========== " + target + " ==========")
		for listt in vuls:
			listt = listt.strip()
			url = target + listt
			try:
				r = requests.get(url, headers=headers, timeout=3, verify=False)

				#jmx-console
				#web-console
				if r.status_code == 401:
					if "jmx" in url:											
						print ("[+]jmx-console vulnerability may exist!")
					elif "web" in url:
						print ("[+]web-console vulnerability may exist!")
					else:
						pass
				else:
					pass

				#admin-console
				#JBoss JMXInvokerServlet(CVE-2015-7501)
				#JBOSSMQ JMS(CVE-2017-7504)
				if r.status_code == 200:
					if "admin" in url:
						print ("[+]admin-console vulnerability may exist!")
					elif "JMXInvokerServlet" in url:
						print ("[+]JBoss JMXInvokerServlet(CVE-2015-7501) vulnerability may exist!")
					elif "jbossmq" in url:
						print ("[+]JBOSSMQ JMS(CVE-2017-7504) vulnerability may exist!")
					else:
						pass
				else:
					pass

				#(CVE-2017-12149)
				if r.status_code == 500:
					if "readonly" in url:
						print ("[+]CVE-2017-12149 vulnerability may exist!")
					else:
						pass
				else:
					pass

			except Exception as e:
				pass

if __name__=="__main__":
	main()

