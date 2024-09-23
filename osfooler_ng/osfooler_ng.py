#!/opt/osfooler-ng/bin/python3
# -*- coding: utf-8 -*-

# ver:2024-03-14__py3

from random import randint
import hashlib
import logging
#import module_p0f
import socket
import fcntl
import struct
import optparse
import sys
import time
import os
import netfilterqueue as nfqueue
#import ConfigParser
import ast
l = logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
#from dpkt import *
import dpkt
from socket import AF_INET, AF_INET6, inet_ntoa
import urllib
import multiprocessing
from multiprocessing import Process

from scapy.layers.inet import IP,TCP
import scapy_p0f
from scapy_p0f import p0f, p0f_impersonate

#from pyp0f.net.layers.tcp import TCPFlag
#from pyp0f.impersonate import impersonate_mtu, impersonate_tcp
import yaml
import codecs



# Some configuration
#sys.tracebacklimit = 3
conf.verbose = 0
conf.L3socket = L3RawSocket
sys.path.append('python')
sys.path.append('build/python')
sys.path.append('dpkt-1.6')

SIGNATURES='/etc/p0f/p0f.yaml'
# Initialize statistic variables
icmp_packet = 0
IPID = 0

# Started NFQueues
q_num1 = -1

# TCP packet information
# Control flags
TH_FIN = 0x01          # end of data
TH_SYN = 0x02          # synchronize sequence numbers
TH_RST = 0x04          # reset connection
TH_PUSH = 0x08          # push
TH_ACK = 0x10          # acknowledgment number set
TH_URG = 0x20          # urgent pointer set
TH_ECE = 0x40          # ECN echo, RFC 3168
TH_CWR = 0x80          # congestion window reduced
# Options (opt_type) - http://www.iana.org/assignments/tcp-parameters
TCP_OPT_EOL = 0     # end of option list
TCP_OPT_NOP = 1     # no operation
TCP_OPT_MSS = 2     # maximum segment size
TCP_OPT_WSCALE = 3     # window scale factor, RFC 1072
TCP_OPT_SACKOK = 4     # SACK permitted, RFC 2018
TCP_OPT_SACK = 5     # SACK, RFC 2018
TCP_OPT_ECHO = 6     # echo (obsolete), RFC 1072
TCP_OPT_ECHOREPLY = 7     # echo reply (obsolete), RFC 1072
TCP_OPT_TIMESTAMP = 8     # timestamp, RFC 1323
TCP_OPT_POCONN = 9     # partial order conn, RFC 1693
TCP_OPT_POSVC = 10    # partial order service, RFC 1693
TCP_OPT_CC = 11    # connection count, RFC 1644
TCP_OPT_CCNEW = 12    # CC.NEW, RFC 1644
TCP_OPT_CCECHO = 13    # CC.ECHO, RFC 1644
TCP_OPT_ALTSUM = 14    # alt checksum request, RFC 1146
TCP_OPT_ALTSUMDATA = 15    # alt checksum data, RFC 1146
TCP_OPT_SKEETER = 16    # Skeeter
TCP_OPT_BUBBA = 17    # Bubba
TCP_OPT_TRAILSUM = 18    # trailer checksum
TCP_OPT_MD5 = 19    # MD5 signature, RFC 2385
TCP_OPT_SCPS = 20    # SCPS capabilities
TCP_OPT_SNACK = 21    # selective negative acks
TCP_OPT_REC = 22    # record boundaries
TCP_OPT_CORRUPT = 23    # corruption experienced
TCP_OPT_SNAP = 24    # SNAP
TCP_OPT_TCPCOMP = 26    # TCP compression filter
TCP_OPT_MAX = 27

# Some knowledge about nmap packets
# Options
T1_opt1 = "03030a01020405b4080affffffff000000000402"
T1_opt2 = "020405780303000402080affffffff0000000000"
T1_opt3 = "080affffffff0000000001010303050102040280"
T1_opt4 = "0402080affffffff0000000003030a00"
T1_opt5 = "020402180402080affffffff0000000003030a00"
T1_opt6 = "020401090402080affffffff00000000"
T2_T6_opt = "03030a0102040109080affffffff000000000402"
T7_opt = "03030f0102040109080affffffff000000000402"
ECN_opt = "03030a01020405b404020101"
# Window Size
T1_1w = "1"
T1_2w = "63"
T1_3w = "4"
T1_4w = "4"
T1_5w = "16"
T1_6w = "512"
T2w = "128"
T3w = "256"
T4w = "1024"
T5w = "31337"
T6w = "32768"
T7w = "65535"
ECEw = "3"
# Payloads
udp_payload = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"

# Parse fields in nmap-db
def parse_nmap_field(field):
  raise Exception("Function dropped")

# Get default interface address without external packages
def get_ip_address(ifname):
  raise Exception("Function dropped")
  s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  return socket.inet_ntoa(fcntl.ioctl(
    s.fileno(),
    0x8915,  # SIOCGIFADDR
    struct.pack('256s', ifname[:15])
    )[20:24])

def show_banner():
	print ("""
		
                 -o:      
                .o+`      
                :o-.-.` ``
          `-::::+o/-:++/o/	          _____             __                                        
        `/+//+/--ss///:-.    ____  ______/ ________   ____ |  |   ___________            ____   ____ 
        /o:` .:/:ss         /  _ \\/  ___\\   __/  _ \\ /  _ \\|  | _/ __ \\_  __ \\  ______  /    \\ / ___\\
        oo`.-` .+s+        (  <_> \\___ \\ |  |(  <_> (  <_> |  |_\\  ___/|  | \\/ /_____/ |   |  / /_/  >
  .-::::oo--/+/+o/`         \\____/____  >|__| \\____/ \\____/|____/\\___  |__|            |___|  \\___  /
 /+/++:-/s+///:-`                     \\/                             \\/                     \\/_____/
 `  `-///s:                           
      `-os.                           v1.0b (https://github.com/segofensiva/osfooler-ng)
       /s:                            v1.0d (https://github.com/ezbik/osfooler-ng)
""")

# Which packet is?
def check_even(number):
  if number % 2 == 0:
    return 1
  else:
    return 0

# Display TCP flags in human format
def tcp_flags(flags):
  ret = ''
  if flags & TH_FIN:
    ret = ret + 'F'
  if flags & TH_SYN:
    ret = ret + 'S'
  if flags & TH_RST:
    ret = ret + 'R'
  if flags & TH_PUSH:
    ret = ret + 'P'
  if flags & TH_ACK:
    ret = ret + 'A'
  if flags & TH_URG:
    ret = ret + 'U'
  if flags & TH_ECE:
    ret = ret + 'E'
  if flags & TH_CWR:
    ret = ret + 'C'
  return ret

# Parse TCP options to human format
def opts_human(options):
  opts = []
  for o, v in options:
    if o == TCP_OPT_WSCALE:
      opts.append("WS%d" % ord(v))
    elif o == TCP_OPT_MSS:
      opts.append("MSS%d" % struct.unpack('>H', v)[0])
    elif o == TCP_OPT_TIMESTAMP:
      opts.append("TS(%d,%d)" % struct.unpack('>II', v))
    elif o == TCP_OPT_NOP:
      opts.append("NOP")
    elif o == TCP_OPT_SACKOK:
      opts.append("SACK")
  return opts

# GET IP ID ICMP
def get_icmp_ipid():
  raise Exception("Function dropped")

#
def get_ipid_new(test):
  raise Exception("Function dropped")

# Send ICMP response
def send_icmp_response(pl, probe):
  raise Exception("Function dropped")

# Send UDP response
def send_udp_response(pl, probe): 
  raise Exception("Function dropped")

# Send probe response
def send_probe_response(pl, probe):
  raise Exception("Function dropped")

# ECN
# Send probe response
def send_ECN_response(pl, probe):
  raise Exception("Function dropped")

def send_probe_response_T1(pl, probe, packet):
  raise Exception("Function dropped")

def get_nmap_os_db_path():
  raise Exception("Function dropped")

# Parse nmap-os-db
def get_base():
    raise Exception("Function dropped")

def get_names(search):
    raise Exception("Function dropped")

def list_os():
    raise Exception("Function dropped")

def get_random_os():
    raise Exception("Function dropped")

def search_os(search_string):
    raise Exception("Function dropped")

def options_to_scapy(x):
    options = []
    for indice_opt in range(0, len(x)):
        if x[indice_opt] == "W":
            w_opt = ""
            for index in range(indice_opt + 1, len(x)):
                if ((x[index] != "N") and (x[index] != "W") and (x[index] != "M") and (x[index] != "S") and (x[index] != "T") and (x[index] != "L")):
                    w_opt += x[index]
                else:
                    break
            options.append(('WScale', int(w_opt, 16)))
        if x[indice_opt] == "N":
            options.append(('NOP', None))
        if x[indice_opt] == "M":
            m_opt = ""
            for index in range(indice_opt + 1, len(x)):
                if ((x[index] != "N") and (x[index] != "W") and (x[index] != "M") and (x[index] != "S") and (x[index] != "T") and (x[index] != "L")):
                    m_opt += x[index]
                else:
                    break
            options.append(('MSS', int(m_opt, 16)))
        if x[indice_opt] == "S":
            options.append(('SAckOK', ""))
        if x[indice_opt] == "T":
            if (x[indice_opt + 1] == "0"):
                T_0 = 0
            else:
                T_0 = 1  # Random
            if (x[indice_opt + 2] == "0"):
                T_1 = 0
            else:
                T_1 = 1  # Random
            # PENDING
            options.append(('Timestamp', (T_0, T_1)))
        if x[indice_opt] == "L":
            options.append(('EOL', None))
    return options

def print_tcp_packet(pl, destination): 
    pkt = dpkt.ip.IP(pl.get_payload())
    option_list = dpkt.tcp.parse_opts(pkt.tcp.opts)
    
    if opts.verbose:
        print(" [+] Packet '%s' (total length %s)" % (destination, pl.get_payload_len()))
        print("      [+] IP:  source %s destination %s tos %s id %s" % (inet_ntoa(pkt.src), inet_ntoa(pkt.dst), pkt.tos, pkt.id))
        print("      [+] TCP: sport %s dport %s flags %s seq %s ack %s win %s" % (pkt.tcp.sport, pkt.tcp.dport, tcp_flags(pkt.tcp.flags),  pkt.tcp.seq, pkt.tcp.ack, pkt.tcp.win))
        print("               options %s" % (opts_human(option_list)))

def print_icmp_packet(pl): 
    pkt = dpkt.ip.IP(pl.get_payload())
    if opts.verbose:
        print(" [+] Modifying packet in real time (total length %s)" % pl.get_payload_len())
        print("      [+] IP:   source %s destination %s tos %s id %s" % (inet_ntoa(pkt.src), inet_ntoa(pkt.dst), pkt.tos, pkt.id))
        print("      [+] ICMP: code %s type %s len %s id %s seq %s" % (pkt.icmp.code, pkt.icmp.type, len(pkt.icmp.data.data), pkt.icmp.data.id, pkt.icmp.data.seq))

def print_udp_packet(pl): 
    pkt = dpkt.ip.IP(pl.get_payload())

    if opts.verbose:
        print( " [+] Modifying packet in real time (total length %s)" % pl.get_payload_len())
        print( "      [+] IP:   source %s destination %s tos %s id %s" % (inet_ntoa(pkt.src), inet_ntoa(pkt.dst), pkt.tos, pkt.id))
        print( "      [+] UDP:  sport %s dport %s len %s" % (pkt.udp.sport, pkt.udp.dport, len(pkt.udp.data)))
        print( "                data %s" % (pkt.udp.data[0:49]))
        print( "                     %s" % (pkt.udp.data[50:99]))
        print( "                     %s" % (pkt.udp.data[100:149]))
        print( "                     %s" % (pkt.udp.data[150:199]))
        print( "                     %s" % (pkt.udp.data[200:249]))
        print( "                     %s" % (pkt.udp.data[250:299]))

# Process p0f packets
def cb_p0f( pl ): 

    pkt = dpkt.ip.IP(pl.get_payload())
    
    scapy_packet = IP(bytes(pkt))
    #flags = TCPFlag(int(scapy_packet[TCP].flags))

    # Not a SYN packet, re-inject unmodified packet into the network stack
    #if flags != TCPFlag.SYN: print('not SYN')

    #print ( 'flags', flags )

    # that condition is too complex, I had to drop SourceIP check, so it will work with PolicyBasedRouting.
    #
    # During PolicyBasedRouting, when we afterwards route the packets via
    # .. another interface, its SRC_IP remains always of main interface, as TCP stack sees it.

    #if opts.verbose:
        #print " [+] got packet", "flags", tcp_flags(pkt.tcp.flags) , inet_ntoa(pkt.src), ">", inet_ntoa(pkt.dst), "pkt.id", pkt.id

    #if (inet_ntoa(pkt.src) == home_ip) and (pkt.p == dpkt.ip.IP_PROTO_TCP) and (tcp_flags(pkt.tcp.flags) == "S"):
    tcp_flag_my=tcp_flags(pkt.tcp.flags)
    if (pkt.p == dpkt.ip.IP_PROTO_TCP) and ( (tcp_flag_my  == "S") ):

        if opts.verbose:
            print(" [+] original packet:")
            print_tcp_packet(pl, "p0f")
            scapy_verbose=True
        else:
            scapy_verbose=False
        #options = pkt.tcp.opts.encode('hex_codec') # Python 2.7 !!
        options = codecs.encode( pkt.tcp.opts ,  'hex_codec').decode()
        #print(options)
        op = options.find("080a")
        if (op != -1):
            op = op + 7
            timestamp = options[op:][:5]
            i = int(timestamp, 16)
        if opts.osgenre and opts.details_p0f:
            try:
                if (tcp_flag_my  == "S"):
                    option_list = dpkt.tcp.parse_opts(pkt.tcp.opts)
                    # when we set: sysctl -w net.ipv4.tcp_timestamps=0
                    ts1=0
                    ts2=0

                    # we can retrieve TS only for SYN packets??
                    for o, v in option_list:
                     if o == TCP_OPT_TIMESTAMP:
                      tss=struct.unpack('>II', v)
                      ts1=tss[0]
                      ts2=tss[1]
                     elif o == TCP_OPT_MSS:
                      orig_mss= struct.unpack('>H', v)[0]

                      #print("orig ts1", tss[0])
                      #print("orig ts2", tss[1])
                      #print("orig mss", orig_mss)

                    TCP_OPTS=[ ('MSS', orig_mss), ('Timestamp',(ts1,ts2)), ('NOP',0), ('NOP',0), ('NOP',0)  ]
                    
                    #p0f3:
                    #sig = ver:ittl:olen:mss:wsize,scale:olayout:quirks:pclass <- Template
                    #                                                                 incolumi    valdik  brows/lea  whoer 
                    #                                                               ----------------------------------------
                    #sig='*:64:0:*:mss*44,1:mss,sok,ts,nop,ws:df,id+:0'               # Lin         Andr   Andr       Andr
                    #sig='*:64:0:*:mss*44,3:mss,sok,ts,nop,ws:df,id+:0'               # Lin         Andr   Andr       Andr
                    #sig='*:64:0:*:65535,8:mss,sok,ts,nop,ws:df,id+:0'                # A         L       L           ?
                    #sig='*:64:0:*:65535,4:mss,nop,ws,nop,nop,ts,sok,eol+1:df,id+:0'  #mac os WORK
                    #sig='*:64:0:*:65535,3:mss,nop,ws,nop,nop,ts2,sok,eol+1:df,id+:0' #macos

                    if opts.verbose: print(" [+] dest sig",sig)

                    try:
                        METHOD='old'
                        if METHOD=='old':
                            pkt_send = scapy_p0f.p0f_impersonate(
                                IP(dst=inet_ntoa(pkt.dst), src=inet_ntoa(pkt.src), id=pkt.id, tos=pkt.tos)/TCP( sport=pkt.tcp.sport, dport=pkt.tcp.dport, flags=tcp_flag_my , seq=pkt.tcp.seq, ack=0 , options=TCP_OPTS ), 
                                signature=sig, 
                                verbose=scapy_verbose )
    #                    if METHOD=='new':
    #                        pkt_send = impersonate_tcp(
    #                            packet = scapy_packet,
    #                            raw_label="g:unix:Linux:2.2.x-3.x (barebone)",
    #                            raw_signature="*:64:0:*:*,0:mss:df,id+:0",
    #                            )
                    except Exception as e: 
                        print(e)

                pkt = IP(dst=inet_ntoa(pkt.dst), src=inet_ntoa(pkt.src), id=pkt.id, tos=pkt.tos) 
                pl.set_payload(bytes(pkt_send))
                pl.accept()  
            except Exception as e:
                print( " [+] Unable to modify packet with p0f personality...")
                print( " [+] Aborting because:", e)
                sys.exit()
        else:
            pl.accept()
    else:
        pl.accept()
        if opts.verbose:
            print( " [+] Ignored packet: source %s destination %s tos %s id %s tcp flag %s" % (inet_ntoa(pkt.src), inet_ntoa(pkt.dst), pkt.tos, pkt.id, tcp_flag_my))
      #  return 0

# Process nmap packets
def cb_nmap( pl): 
    raise Exception("Function dropped")

def init(queue):
  q = nfqueue.NetfilterQueue()
  if (opts.details_p0f and opts.osgenre):
    q.bind(queue, cb_p0f)
    print( "      [->] %s: p0f packet processor" % multiprocessing.current_process().name)
  try: 
    q.run()
  except KeyboardInterrupt as err:
    pass

# Upload database
def update_nmap_db():
    raise Exception("Function dropped")

def md5(fname):
  hash_md5 = hashlib.md5()
  with open(fname, "rb") as f:
    for chunk in iter(lambda: f.read(4096), b""):
      hash_md5.update(chunk)
  return hash_md5.hexdigest()

def user_is_root():
  if not os.geteuid() == 0:
      sys.exit(' [+] OSfooler must be run as root')
  else:
      return

def get_default_iface_name_linux():
    route = "/proc/net/route"
    with open(route) as f:
        for line in f.readlines():
            try:
                iface, dest, _, flags, _, _, _, _, _, _, _, =  line.strip().split()
                if dest != '00000000' or not int(flags, 16) & 2:
                    continue
                return iface
            except:
                continue

def main():
  # Main program begins here
  show_banner()
  parser = optparse.OptionParser()
  parser.add_option('-M', '--marked', action='store', dest='marked', 
                    help="process only packets with FWMARK, can be 1000 (dec) or (hex) 0x3e8 or value/mask")
  parser.add_option('--cgroup_classid', action='store', dest='cgroup_classid', 
                    help="process only packets coming from this Cgroup classid. Example: 1000 (dec) or 0x3e8 (hex). Make sure this Cgroup already exists!")
  parser.add_option('--cgroup_path', action='store', dest='cgroup_path', 
                    help="process only packets coming from this Cgroup paths (comma separated). Example: kek.slice/my.service,kek.slice/my2.service . Make sure these Cgroup paths already exist! ")
  parser.add_option('-q', '--qnum', action='store',
                    dest='qnum', help="NFQUEUE id to use")
  parser.add_option('-p', '--p0f', action='store_true',
                    dest='p0f', help="list available p0f signatures")
  parser.add_option('-o', '--os_p0f', action='store',
                    dest='osgenre', help="use p0f OS Genre")
  parser.add_option('-d', '--details_p0f',
                    action='store', dest='details_p0f', help="choose p0f Details")
  #parser.add_option('-i', '--interface', action='store',
                    #dest='interface', help="choose network interface (eth0)")
  parser.add_option('-v', '--verbose', action='store_true',
                    dest='verbose', help="be verbose")
  parser.add_option('-V', '--version', action='store_true',
                    dest='version', help="display the version of OSfooler and exit")
  global opts
  (opts, args) = parser.parse_args()

  #print(opts)

  if opts.version:
    exit(0)

  if opts.p0f:
    print( " [+] Supported list of p0f OS to emulate, from ",SIGNATURES,"file; use any in '-o XXX', '-d YYY' flags")
    print()
    signatures=load_signatures()
    for osgenre in signatures:
      for osdetails in signatures[osgenre]:
        s=signatures[osgenre][osdetails]
        print(f'{osgenre:>20}\t{osdetails:<10} {s}')
    exit(0)

  if (opts.details_p0f and not opts.osgenre):
    print( " [ERROR] Please, choose p0f OS system to emulate, not only OS details")
    print( " [+] Use %s -p to list possible candidates" % sys.argv[0])
    print()
    sys.exit(' [+] Aborting...')

  # Check if user is root before continue
  user_is_root()

#  if opts.interface:
#    interface = opts.interface 
#  else:
  interface = get_default_iface_name_linux()

  print(" [+] detected interface: %s" % interface)

  if opts.qnum:
    q_num1  = int(opts.qnum)
  else:
      try:
            # for spoofing p0f:
            q_num1 = sorted(os.listdir("/sys/class/net/")).index(interface) * 2 + 1
      except ValueError as err:
            q_num1 = -1

  # Global -> get values from and cb_p0f
  global base

  if opts.osgenre and opts.details_p0f:
    print( " [+] Mutating to p0f:")
    global sig
    sig=load_signature(opts.osgenre, opts.details_p0f)
    if sig: 
      print( " [+] OS: %s:%s, with signature %s"  % (opts.osgenre , opts.details_p0f, sig))
    else:
      print( "      [->] Could not found that combination in p0f database...")
      sys.exit(' [+] Aborting...')
  else:
    print( " [i] Select both p0f OS genre and OS details.")
    sys.exit(' [+] Aborting...')
  
  # Start activity
  print( " [+] Activating queues")
  procs = []
  
  p0f_iptables_rules_added=False

  # p0f mode:

  iptables_conditions=[]
  rule1="-p TCP  -m multiport --dports 443,446,80 --syn -m comment --comment Osfooler-ng "

  if opts.marked:
    print( (" [+] will process only packets marked as %s" % opts.marked))
    iptables_conditions.append( rule1+ "-m mark --mark  %s" % opts.marked )
  elif opts.cgroup_path:
    print( (" [+] will process only packets from Cgroup Path  %s" % opts.cgroup_path))
    for i in opts.cgroup_path.split(","):
        iptables_conditions.append( rule1+"-m cgroup --path %s" % i )
  elif opts.cgroup_classid:
    print( (" [+] will process only packets from Cgroup classid  %s" % opts.cgroup_classid))
    iptables_conditions.append( rule1+"-m cgroup --classid %s" % opts.cgroup_classid)
  else:
    print( (" [+] will process all system packets"))
    iptables_conditions.append(rule1)

  if (opts.osgenre):
    #global home_ip
    #home_ip = get_ip_address(interface)  
    #print( (" [+] detected home_ip %s" % home_ip))
    print( (" [+] detected Queue %s" % q_num1))
    add_iptables_rules_p0f(iptables_conditions, q_num1)
    p0f_iptables_rules_added=True
    proc = Process(target=init,args=(q_num1,))
    procs.append(proc)
    proc.start() 
  # Detect mode

  try:
      for proc in procs:
        proc.join()
      print()
      # Flush all iptabels rules
      if (q_num1 >= 1):
        del_iptables_rules_p0f(iptables_conditions, q_num1)
      print( " [+] Active queues removed")
      print( " [+] Exiting OSfooler..." )
  except KeyboardInterrupt:
      print()
      # Flush all iptabels rules
      if (q_num1 >= 1) and p0f_iptables_rules_added==True:
        del_iptables_rules_p0f(iptables_conditions, q_num1)
      print( " [+] Active queues removed [kbd except]")
      print( " [+] Exiting OSfooler... [kbd except]")
      #for p in multiprocessing.active_children():
      #  p.terminate()

def add_iptables_rules_p0f(iptables_conditions, q_num1 ):
    for iptables_condition in iptables_conditions:
        iptables_line="iptables -A OUTPUT %s -j NFQUEUE --queue-num %s" % ( iptables_condition , q_num1  )
        print( " [+] Queue %s, add iptables rule: \n   %s" % (q_num1, iptables_line ))
        ret=os.system( iptables_line )
        if ret != 0:
            print( " [+] could not add Iptables rule")
            del_iptables_rules_p0f(iptables_conditions, q_num1 )
            sys.exit(' [+] Aborting...')
        
def del_iptables_rules_p0f(iptables_conditions, q_num1 ):
    for iptables_condition in iptables_conditions:
        iptables_line="iptables -D OUTPUT %s -j NFQUEUE --queue-num %s" % ( iptables_condition , q_num1  )
        print( (" [+] Queue %s, del iptables rule: %s" % ( q_num1, iptables_line ) ))
        os.system( iptables_line )

def load_signatures( ):
    with open(SIGNATURES, 'r') as stream:
        try:
            parsed_yaml=yaml.load(stream, Loader=yaml.BaseLoader )
        except yaml.YAMLError as exc:
            print(exc)
    return parsed_yaml

def load_signature( osgenre, details_p0f ):
    parsed_yaml=load_signatures()
    #print "signatures loaded", parsed_yaml
    #print "trying to load sig by", osgenre, details_p0f
    ret=parsed_yaml[osgenre][details_p0f]
    if ret:
        return ret
    


if __name__ == "__main__":
  main()



### https://github.com/Nisitay/pyp0f/blob/master/pyp0f/impersonate/tcp.py
