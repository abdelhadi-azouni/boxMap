#!usr/bin/env python

import socket
import threading
import select
import time
import string
#from scapy import *


try:
    from scapy.all import *
except ImportError:
    from scapy import *

import threading, time
from struct import pack
from struct import unpack
import socket
import urllib
import sys
import os
from scapy.error import Scapy_Exception


sys.path.append("/home/uwaterloo_boxMap/")

FIN = 0x01
SYNf = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80

def compare_pkts(pkt1, pkt2):


    """
    compare two tcp/ip packets and returns a dict containing the differences

    pkt1 is always complete
    pkt2 can be incomplete (icmp quote)


    NOTE: only finds modifications, not addition and suppression
          for a complete tracebox see http://www.tracebox.org
    """
    print '\n\n'
    print "pkt1==\n"
    print pkt1[0][IP].src
    print '\n'
    print "pkt2==\n"
    print pkt2[0][IP]

    print '\n\n'
    diff={}
    sent=dict(pkt1.__dict__["fields"].items()+dict(pkt1.payload.options).items())
    print 'sent ===========+>'+str(sent)
    quoted=dict(pkt2.payload.payload.__dict__["fields"].items() + dict(pkt2.payload.payload.payload.options).items())

    for name1,data1 in sent.iteritems():
        if name1 in quoted:
            if data1 != quoted[name1]:
                diff[name1]=data1
    return diff


#TODO : move it inside Server
def send_feedback(a):
    time.sleep(5)
    conf.L3socket = L3RawSocket #to make it work on planetlab
    print 'a=='+repr(a)
    #print '\n'+str(a[TCP].dport)  #just double checking because of the known bug in scapy sniff
    if a[TCP].dport == 33444:
        client_ip=a[IP].src
        ip=IP(dst=client_ip)
        ACK=TCP(dport=44555, flags='S', seq=3000)
        #ACK=TCP(sport=80, dport=80, flags='S', ack=31)
        send(ip/ACK/repr(a))


def get_external_ip():
    #first method TODO: not sufficient !
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    f= s.getsockname()[0]
    s.close()
    return f

    # other methods

    f=os.popen('/sbin/ifconfig eth0 | grep "inet\ addr" | cut -d: -f2 | cut -d" " -f1')
    return f

    data = json.loads(urllib.urlopen("http://ip.jsontest.com/").read())
    return data["ip"]


class Server(threading.Thread):

    def __init__(self):
        threading.Thread.__init__(self)
        self.running = 1
        self.conn = None
        self.addr = None

    def run(self):
        # Wait for the SYN of the client
        # self.sniff()
        sniff_thread = threading.Thread(target=self.sniff())
        sniff_thread.start()

    def open_socket(self):
        HOST = ''   # Symbolic name, meaning all available interfaces
        PORT = 33444 # Arbitrary non-privileged port

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print 'Socket created'

        #Bind socket to local host and port
        try:
            s.bind((HOST, PORT))
        except socket.error:
            #print 'Bind failed. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
            sys.exit()

        print 'Socket bind complete'

        #Start listening on socket
        s.listen(10)
        print 'Socket now listening'

    def sniff(self):

        """
        these two calls didnt work and I have no idea why

        """
        """
        before sniffing we make sure there is a socket listening. Opening a socket aloows the administrative
        domain on lanetlab to correctly forward packets to our slice

        socket_thread = threading.Thread(target=self.open_socket())
        socket_thread.start()

        """
        """
        self.open_socket()
        """

        HOST = ''   # Symbolic name, meaning all available interfaces
        PORT = 33444 # Arbitrary non-privileged port

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print 'Socket created'

        #Bind socket to local host and port
        try:
            s.bind((HOST, PORT))
        except socket.error :
            #print 'Bind failed. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
            sys.exit()

        print 'Socket bind complete'

        #Start listening on socket
        s.listen(10)
        print 'Socket now listening'
        try:
            print 'listening'
            local_ip =  get_external_ip()
            print local_ip

            #filter = "dst host "+local_ip+" and tcp dst port 33444 and tcp-syn != 0"
            build_lfilter = lambda (r): TCP in r and r[TCP].dport == PORT and (r[TCP].flags & SYNf)

            sniff(lfilter=build_lfilter, prn=send_feedback)
        except Exception, e:
            print e.message
            #print "problem"

    def kill(self):
        self.running = 0

def scapystr_to_dictionary(scapystr):
    scapystr=scapystr.replace(", ", ",")    #skipping the issue in Options=['MSS', 5000]

    #print repr(a).split('<')
    dico=dict()
    for e in str(scapystr).split('<'):
        if e.__len__()==0:
            continue

        e=e.translate(string.maketrans('',''), "<|>\'")
        print e

        layer=e.split('  ')[0]
        fields=e.split('  ')[1]
        #print fields
        fields=dict(f.split('=') for f in fields.strip().split(' '))
        #print 'layerrr==='+layer
        #print fields

        dico[layer]=fields
    #print 'dicoo==\n'
    #print dico
    return dico


def dict_diff(first, second):
    KEYNOTFOUND='key not found'
    diff = {}
    # Check all keys in first dict
    for key in first.keys():
        if (not second.has_key(key)):
            diff[key] = (first[key], KEYNOTFOUND)
        elif (first[key] != second[key]):
            diff[key] = (first[key], second[key])
    # Check all keys in second dict to find missing
    for key in second.keys():
        if (not first.has_key(key)):
            diff[key] = (KEYNOTFOUND, second[key])
    return diff


def dict_packet_diff(dict_pkt1, dict_pkt2):
    diff = {}
    print 'layer diff === \n'
    print dict_diff(dict_pkt1, dict_pkt2)

    for key in dict_pkt1.keys():
        if (not dict_pkt2.has_key(key)):
            diff[key] = (dict_pkt1[key], KEYNOTFOUND)
        if (dict_pkt2.has_key(key) and (dict_pkt1[key] != dict_pkt2[key])):
            #print key+' details === \n'
            diff[key]= dict_diff(dict_pkt1[key], dict_pkt2[key])
    for key in dict_pkt2.keys():
        if (not dict_pkt1.has_key(key)):
            diff[key] = (KEYNOTFOUND, dict_pkt2[key])
    return  diff


# for performance ?
def dict_packet_diff_once(dict_pkt1, dict_pkt2):
    KEYNOTFOUND='key not found'
    diff = {}
    # Check all keys in first dict
    for key in first.keys():
        if (not second.has_key(key)):
            diff[key] = (first[key], KEYNOTFOUND)
        elif (first[key] != second[key]):
            for intern_key in first[key].keys():
                if (not second[key].has_key(intern_key)):
                    diff[intern_key] = (first[key][intern_key], KEYNOTFOUND)
                elif (first[key] != second[key]):
                    diff[intern_key] = (first[key][intern_key], second[key][intern_key])

            #diff[key] = (first[key], second[key])
    # Check all keys in second dict to find missing
    for key in second.keys():
        if (not first.has_key(key)):
            diff[key] = (KEYNOTFOUND, second[key])
    return diff



def hops(dest):

    proc = subprocess.Popen(["traceroute "+dest, " "], stdout=subprocess.PIPE, shell=True)
    (out, err) = proc.communicate()
    print "program output:", out

    # Built-up data structures as string. Should look effectively
    # identical to the above input string.
    ip_hops=[]

    for line in out.splitlines():
        if 'traceroute' in line:
            continue
        line=line[3:]
        if line.replace('*','').replace(' ','').__len__()==0: #if line has only * and spaces
            ip_hops.append(str(line))
        else:
	        ip_hops.append(line.rsplit(' ')[2].replace("(", "").replace(")", ""))

    return ip_hops

class Client(threading.Thread):

    def __init__(self, server_ip):
        threading.Thread.__init__(self)
        self.host = None
        self.sock = None
        self.running = 1
        self.server_ip=server_ip
        #self.server_port=server_port
        print server_ip


    def feedback_to_tracker(self, packet_diff):

        traceroute_hops=hops(self.server_ip)
        message=get_external_ip()+" || "+str(self.server_ip)+" || "+str(traceroute_hops)+" || "+str(packet_diff)
        #HOST=''
        #PORT=44999
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #sock.bind((HOST, PORT  ))
        # Connect the socket to the port where the server is listening
        server_address = ('129.97.74.12', 33777)

        print >>sys.stderr, 'connecting to %s port %s' % server_address
        sock.connect(server_address)

        try:

            print >>sys.stderr, 'sending "%s"' % message
            sock.sendall(message)


            """
            # Look for the response
            amount_received = 0
            amount_expected = len(message)

            while amount_received < amount_expected:
                data = sock.recv(16)
                amount_received += len(data)
                print >>sys.stderr, 'received "%s"' % data
            """

        finally:
           print >>sys.stderr, 'closing socket'
           sock.close()

    def analyse_feedback(self,a, b):

        """"  tests "
        a=Ether(str(a))

        print '\nsent\n'
        sent=dict(a.__dict__["fields"].items()+dict(a.payload.options).items())
        print sent

        print 'quoted\n'

        quoted=dict(b.payload.payload.__dict__["fields"].items() + dict(b.payload.payload.payload.options).items())
        """""



        if b[TCP].dport==44555:  #just double checking because of the known bug in scapy sniff
            print 'b=='+repr(b)

            load = b.load


            #feedback_pkt = Packet().__class__(str(load))
            #feedback_pkt=Ether(load)
            #feedback_pkt=feedback_pkt.__class__(str(feedback_pkt))
            a = a.__class__(str(a))  #to set kernel stage fields

            #print'cooommm===\n'
            #print feedback_pkt.command()


            #feedback_pkt= str(feedback_pkt)
            a=repr(a)
            feedback_pkt=load

            """
            print '\n'
            print 'loooooad==========='+load
            print '\n'
            print "seeeent ============ \n"
            print str(a)
            print '\n'
            print "feeeeedback ============ \n"
            print feedback_pkt
            print '\n'
            """

            print 'sent packet\n'
            sent_pkt=scapystr_to_dictionary(a)
            print sent_pkt
            print '\n'
            feedback_pkt=scapystr_to_dictionary(feedback_pkt)

            if 'Ether' in feedback_pkt:
                del feedback_pkt['Ether']
            if 'Padding' in feedback_pkt:
                del feedback_pkt['Padding']
            if 'Untagged' in feedback_pkt:
                del feedback_pkt['Untagged']

            print 'feedback_pkt\n'

            print feedback_pkt
            print '\n'

            """
            unmatched_item=dict_diff(sent_pkt, feedback_pkt)
            print 'diff===\n'
            print unmatched_item
            """

            packet_diff=dict_packet_diff(sent_pkt, feedback_pkt)
            print "\n"
            print packet_diff
            self.feedback_to_tracker(packet_diff)


            #print 'the difference=='+str(compare_pkts(a, feedback_pkt))

    def run(self):
        conf.L3socket = L3RawSocket #to make it work on planetlab
        #conf.L2socket = L2RawSocket
        ip=IP(dst=self.server_ip)
        SYN=TCP(sport=22333, dport=33444, flags='S', seq=1000, options=[('Timestamp', (342940201L, 0L))])
        #SYN=TCP(sport=22333, dport=33444, flags='S', seq=1000, options=[('Timestamp', (342940201L, 0L)), ('MSS', 1460)])
        #SYN=TCP(sport=22333, dport=33444, flags='S', seq=1000)
        #SYN=TCP(sport=80, dport=80, flags='S', seq=1000)
        syn_prb = ip/SYN
        #syn_prb = Ether(repr(syn_prb))   # this is a work around since I didnt find a method in scapy to represent a packet
                                                    # in a comparable form ..

        """
        before sniffing we make sure there is a socket listening. Opening a socket allows the administrative
        domain on planetlab to correctly forward packets to our slice
        """

        HOST = ''   # Symbolic name, meaning all available interfaces
        PORT = 44555 # Arbitrary non-privileged port

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print 'Socket created'

        #Bind socket to local host and port
        try:
            s.bind((HOST, PORT))
        except socket.error:
            #print 'Bind failed. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
            sys.exit()

        print 'Socket bind complete'

        #Start listening on socket
        s.listen(10)
        print 'Socket now listening'

        b =PacketList()
        F=0
        while b.__len__()==0 or b[0].haslayer(TCP)==False or b[0][TCP].dport!=PORT or not (F & SYNf):  #to make sure we receive a feedback but also we stop sniffing at the first one received
                                                #the second part is to make sure we dont get traped by buggy sniff
            send(syn_prb)
            #b=sniff(count=1,filter="tcp and host 127.0.0.1 and port 3344", timeout=3)
            print "sniffing for feedback b"
            # b=sniff(filter="src host "+ str(self.server_ip)+" and tcp dst port 44555 and tcp.flags.syn==0", timeout=3) # does not work => exception
            build_lfilter = lambda (r): TCP in r and r[TCP].dport == PORT and (r[IP].src!=r[IP].dst) and (r[TCP].flags & SYNf)
            b=sniff(lfilter=build_lfilter, count=1, timeout=20)
            #b=sniff(filter="src host "+ str(self.server_ip)+" and tcp dst port 44555 and tcp-syn != 0", timeout=3)
            F = b[0][TCP].flags
            time.sleep(2)

        self.analyse_feedback(syn_prb, b[0])
        s.close()

    def kill(self):
        self.running = 0

def main(argv):
    #conf.L3socket = L3RawSocket

    # Prompt, object instantiation, and threads start here.

    #ip_addr = raw_input('What IP (or type listen)?: ')


    if argv[1] == '0':
        server = Server()
        try:
            server.daemon=True
            server.start()
            while True: time.sleep(100)
        except (KeyboardInterrupt, SystemExit):
            print '\n! Received keyboard interrupt, quitting threads.\n'

    else:
        client = Client(argv[1])
        try:
            client.daemon=True
            client.start()
            client.join()
        except (KeyboardInterrupt, SystemExit):
            print '\n! Received keyboard interrupt, quitting threads.\n'


if __name__ == "__main__":
    main(sys.argv)
