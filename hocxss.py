import datetime
from time import sleep
import sys
import os
from multiprocessing import Process
try:
    print ('Dependencies installing now...')
    os.system('sudo apt-get install tor && sudo apt-get install python3-pip && sudo apt-get install python3-socks')
except ImportError:
    print ('check network connection....')
    sys.exit(1)
try:
    import requests, json
except ImportError:
    os.system('pip3 install requests')
try:
    from urllib.parse import urljoin
except ImportError:
     from urlparse import urljoin
try:
    from bs4 import BeautifulSoup as bs
except ImportError:
    print ('BeautifulSoup isn\'t installed, installing now.')
    os.system('pip3 install beautifulsoup4 --upgrade')
try:
    os.system('sudo service tor start')
except ImportError:
    print ('sudo service tor start is not working')

#----------------------------------Pre-define TXT Output------------------------------	
def intro():
	intro1 = G + '''
    ----------------------------------------------------------
        #    #   ####    #####  #     #	  #####	 #####
        #    #  #    #  #	 #   #	 #	#
        #    #  #    #  #	  # # 	 # 	#
        ######  #    #  #	  ###	  ####	 ####
        #    #  #    #  #	  # #	      #	     #
        #    #  #    #  #	 #   #	      #	     #
	#    #   ####    #####	#     #  #####	#####            

        Version : 1.0
        Team Hackersonlineclub
        Website : https://hackersonlineclub.com
    ----------------------------------------------------------
  HOCXSS tool must be used for Knowledge & Research Purpose Only.
  Usage of HOC XSS for attacking targets without prior mutual consent 
  is illegal. It is the end user's responsibility to obey all applicable
  local, state and federal laws. Developers assume no liability and are 
  not responsible for any misuse or damage caused by this program.
    ''' + '\n' + '\n' +N
	for c in intro1:
		print(c,end='')
		sys.stdout.flush()
		sleep(0.00095)

#----------------------------------Pre-define TXT Output------------------------------
N = '\033[0m'
B = '\033[1;34m' 
R = '\033[1;31m' 
G = '\033[1;32m' 
Y = '\033[1;33m' 
plin= "--" * 50
depth = 10
time = str(datetime.datetime.now())
keybordexcpt = ' Keyboard Interruption! Exiting... \n'
exit = ' Press CTRL + C  or CTRL + Z for EXIT'
retrypls =' Failed to establish a new connection Name or service not known'
presskey=' Press a key to continue '
wrongkey = ' Wrong Key Enter Retry... Press enter'
ntf = ' file not found....'
user_agent = {'User-Agent': 'MMozilla/5.0 (Windows; U; Windows NT 5.1; it; rv:1.8.1.11)Gecko/20071127 Firefox/2.0.0.11'} 
visited=[]
#----------------------------------Pre-define TXT Output------------------------------
class PL:
	@classmethod
	def inforI(self,text):
 		print(B +" [#] " + text + N) 
	@classmethod
	def inforG(self,text):
		print(G+time + G + " [#] " +text + N)
	@classmethod
	def inforY(self,text):
 		print(G+time + Y + " [!] " +text + N)
	@classmethod
	def inforR(self,text):
 		print(G+time + R + " [!] " +text + N)
#----------------------------------------------------------------------------------
def get_all_forms(url):
    soup = bs(requests.get(url).content, "html.parser")
    return soup.find_all("form",method=True)
#----------------------------------------------------------------------------------
def get_form_details(form):
    details = {}
    action = form.attrs.get("action").lower()
    method = form.attrs.get("method", "get").lower()
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        inputs.append({"type": input_type, "name": input_name})
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details

#------------------------------Submit form------------------------------------
def submit_form(form_details, url, value,TOR):
    session = get_session(TOR)
    target_url = urljoin(url, form_details["action"])
    inputs = form_details["inputs"]
    data = {}
    for input in inputs:
        if input["type"] == "text" or input["type"] == "search":
            input["value"] = value
        input_name = input.get("name")
        input_value = input.get("value")
        if input_name and input_value:
            data[input_name] = input_value

    if form_details["method"] == "post":
        PL.inforG(' Method  :- POST')
        x = session.post(target_url, data=data)
        y = str(x.status_code)
        if(int(y)>=400):
               print(' WAF Detected status code  :-'+y)
        else:
               print(' No WAF Detected status code  :-'+y)
        return session.post(target_url, data=data)
    else:
        PL.inforG(' Method  :- GET')
        x = session.get(target_url, params=data)
        y = str(x.status_code)
        if(int(y)>=400):
               PL.inforR(' WAF Detected status code  :-'+y)
        else:
               PL.inforG(' No WAF Detected status code  :-'+y)
        return session.get(target_url, params=data)

#----------------------------------Scan XSS -------------------------------------
def scan_xss(url,script,TOR):
	forms = get_all_forms(url)
	print(plin)
	PL.inforY(' Testing URL :- '+ str(url))
	if(str(len(forms))==0):
		PL.inforG(" No Forms are detected")
	else:
		PL.inforG(' '+ str(len(forms)) + ' forms detected')
	for js_script in script:
		for form in forms:
			PL.inforR(' Input Box Details:-')
			form_details = get_form_details(form)
			print(form_details)
			content = submit_form(form_details, url, js_script,TOR).content.decode()
			if js_script in content:
				PL.inforR(' FOUND Working Payload:' + str(js_script))
				#print(form_details)
			else:
				PL.inforG(' NOT Working Payload:' + str(js_script))
				#print(form_details)


#----------------------------------------------------------------------------------

def links_to_page(base,TOR):
	session = get_session(TOR)
	lt=[]
	text=session.get(base).text
	visit=bs(text,"html.parser")
	for objects in visit.find_all("a",href=True):
		url=objects["href"]
		if url.startswith("http://") or url.startswith("https://"):
			continue
		elif url.startswith("mailto:") or url.startswith("javascript:"):
			continue
		elif urljoin(base,url) in visited:
			continue
		else:
			lt.append(urljoin(base,url))
			visited.append(urljoin(base,url))
	return lt

#---- Crawl Website ----------------------------------
def crawl(url,depth,TOR,payload):
	urls=links_to_page(url,TOR)
	for url in urls:
		p=Process(target=scan_xss, args=(url,payload,TOR)) 	#scan_xss(url,payload,TOR)
		p.start()
		p.join()
		if depth != 0:
			crawl(url,depth-1,TOR,payload)
		else:
			break	

#--------------------------------- TOR SESSION --------------------------------------
def get_session(TOR):
	session = requests.session()
	if(TOR == True):
		session.proxies = {}
		session.proxies['http']='socks5h://127.0.0.1:9050'
		session.proxies['https']='socks5h://127.0.0.1:9050'
	else:
		proxies = None
		session.proxies = proxies
	session.headers=user_agent
	return session

#---------------------------------- Inputs payloads -----------------------------------
def payloads(file):
	try:
		with open(file, "r") as f:
        		payloads = f.read().splitlines()
	except ImportError:
		PL.inforR(ntf)
		sys.exit(1)
	except:
		PL.inforR(ntf)
		sys.exit(1)
	sleep(0.1)
	return payloads  # Return the list of payloads.


#----------------------------------- Inputs enter -------------------------------------

def XSSENTRURLPAYLOAD(TOR, OPTION):
	ses = get_session(TOR)
	weburl = input("Enter the url :- ")
	try:
		if ("https://" not in weburl and "http://" not in weburl):
			weburl = "http://{}".format(weburl)
	except Exception as e:
		print(str(e))
		sys.exit(1)
	try:	
		PL.inforI(" Please wait getting response from website....")
		r=ses.get(weburl)
		#body=r.text
		PL.inforI(" Establish a new connection status code:- "+ str(r.status_code))
		ya = str(r.status_code)
		if(int(ya)>=400):
			if(ya==404):
				sys.exit(1)
			elif(ya==500):
				sys.exit(1)
			else:
				PL.inforI(" WAF DETECTED :- " + str(r.status_code))
				waf= input(" Want to continue Y/N :-  ")
				if(waf == 'y' or waf == 'Y'):
					pass
				else:
					sys.exit(1)
	except Exception as e:
		PL.inforI(retrypls)
		print(str(e))
		sys.exit(1)
	P = input(" Want to use own payload Y/N :-  ")
	if(P == 'y' or P =='y'):
		PL.inforI(' Example :- /root/payloads.txt')
		PayloadFile = input("Payload file location :- ")
	else:
		os.system('wget https://raw.githubusercontent.com/hackersonlineclub/HOC_PAYLOAD/master/payloads.txt -O /tmp/payloads')
		sleep(1)
		PayloadFile = '/tmp/payloads'
	PL.inforI("Please wait loading payloads....")
	payload = payloads(PayloadFile)
	PL.inforI(" Sucessfull Loaded.....")
	if (TOR == True):
		try:
			s = get_session(TOR)
			PL.inforG( " New IP :-  {}".format(s.get("http://httpbin.org/ip").json()["origin"]))
		except:
			PL.inforR('Please check the network connection')
			sys.exit(1)
	
	if (TOR == False):
		try:
			s = get_session(TOR)
			PL.inforG( " Current IP :-  {}".format(s.get("http://httpbin.org/ip").json()["origin"]))
		except:
			PL.inforR('Please check the network connection')
			sys.exit(1)
	if(OPTION == 1):
		scan_xss(weburl,payload,TOR)
	else:
		scan_xss(weburl,payload,TOR)
		crawl(weburl,depth,TOR,payload)
#----------------------------------- XSS01 function -----------------------------------
def XSS01():
	TOR = False
	os. system('clear')
	intro()
	PL.inforI(' 1. Quick Scan {Scan only given url}')
	PL.inforI(' 2. Intensive Scan {Scan all links in the page}')
	PL.inforI(' 0. FOR GO BACK')
	PL.inforI(exit)	
	print('\n')
	XSS01_VAR = input('Enter your choice: >')	
	if(XSS01_VAR=="1"):
		OPTION = 1
		XSSENTRURLPAYLOAD(TOR, OPTION)
		sys.exit(1)
	if(XSS01_VAR=="2"):
		OPTION = 2
		XSSENTRURLPAYLOAD(TOR, OPTION) 
		sys.exit(1)
	if(XSS01_VAR=="0"):
		XSSMENU() #BACK TO MENU
	if(XSS01_VAR !="1" and XSS01_VAR !="2" and XSS01_VAR !="0"):
		PL.inforR(wrongkey)
		input()
		XSS01()
#----------------------------------- XSS02 function -----------------------------------
def XSS02():
	TOR = True
	os. system('clear')
	intro()
	PL.inforI(' 1. Quick Scan {Scan only given url}')
	PL.inforI(' 2. Intensive Scan {Scan all links in the page}')
	PL.inforI(' 0. FOR GO BACK')
	PL.inforI(exit)
	print('\n')
	XSS02_VAR = input('Enter your choice: >')
	if(XSS02_VAR=="1"):
		OPTION = 1
		XSSENTRURLPAYLOAD(TOR , OPTION)
		sys.exit(1)
	if(XSS02_VAR=="2"):
		OPTION = 2
		XSSENTRURLPAYLOAD(TOR, OPTION) 
		sys.exit(1)
	if(XSS02_VAR=="0"):
		XSSMENU() #BACK TO MENU
	if(XSS02_VAR !="1" and XSS02_VAR !="2" and XSS02_VAR !="0"):
		PL.inforR(wrongkey)
		input()
		XSS02()

#----------------------------------- XSS MENU ---------------------------------------
def XSSMENU():
	os. system('clear')
	intro()
	PL.inforI(' 1. USE HOCXSS WITHOUT TOR')
	PL.inforI(' 2. USE HOCXSS WITH TOR')
	PL.inforI(exit)	
	print('\n')
	XSSMENU_VAR = input('Enter your choice: >')
	if(XSSMENU_VAR=="1"):
		XSS01() #USE TOR WITH OUT HOCXSS
	if(XSSMENU_VAR=="2"):
		XSS02() #USE HOCXSS WITH TOR
	if(XSSMENU_VAR !="1" and XSSMENU_VAR !="2"):
		PL.inforR(wrongkey)
		input()
		XSSMENU()

if __name__ == "__main__":	
	try:
		XSSMENU()      
	except KeyboardInterrupt:
		print(keybordexcpt + '\n')
		sys.exit(1)
	except Exception as inst:
		print('Exception in __name__ == __main__ function')
		print(' [!] ',str(inst))
		sys.exit(1)
