#!/usr/bin/python
from optparse import OptionParser
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
#
from scapy import all
from scapy.all import *
import time
import sys
import Tkinter as tk
import webbrowser, os
from dominate import document
from dominate.tags import *
from Tkinter import *
from tkFileDialog import askopenfilename
filename = ""

#parses the ip addresses supplied, breaks ranges into individual values
# so that 127.0.0.1-3 becomes 3 ip addresses in the list.
def parseIps(ips):
  newIps = []
  for ip in ips.split(','):
#converts ranges into individual IP addresses and adds them to the list
    if '-' in ip:
      parts = ip.split('.')
      base = '.'.join(parts[0:3])
      ipRange = parts[3]
      startEnd = ipRange.split('-')
      start, end = startEnd
      for address in range(int(start),int(end)+1):
        newIps.append(base + "." + str(address))
#if it's not a range, adds it to the list
    else:
      newIps.append(ip)
  return newIps

#parses the ports in a similar manner to parseIps
def parsePorts(ports):
  newPorts = []
  for port in ports.split(','):
    if '-' in port:
      start, end = port.split('-')
      for port in range(int(start),int(end)+1):
        newPorts.append(port)
    else:
      newPorts.append(port)
  return newPorts

#scan takes in options supplied by the GUI or the command line and
#outputs the results in an html file.
def scan(options):
    ips = options.destination
    if options.file:
      f = open(options.file,"r")
      ips = f.readline()
    ips = parseIps(ips)
    list_of_ports = parsePorts(options.ports)
    tcp = options.tcp
    udp = options.udp
    icmp = options.icmp
    tcp_ports = []
    udp_ports = []
    icmp_addresses = []
    tcp_address_port_dict = {}
    udp_address_port_dict = {}
    icmp_address_port_dict = {}

#loops through all IP addresses supplied
    for ip in ips:
#sends a ping if ICMP was selected,
#adds it to the list of ICMP addresses if it gets a response
      if icmp:
        ansi = sr1(IP(dst=ip)/ICMP())
        if ansi == None:
          pass
        else:
          icmp_addresses.append(ip)
#iterates through all ports supplied
      if list_of_ports:
        for port in list_of_ports:
#if TCP is enabled, sends a SYN signal. If it receives a SYN/ACK then the port is
#added to the list of TCP ports
          if tcp:
            anst = sr1(IP(dst=ip)/TCP(dport=int(port)),timeout=1,verbose =0)
            if anst == None:
                pass
            else:
                if int(anst[TCP].flags) == 18:
                    tcp_ports.append(port)
                else:
                    pass
#if UDP is enabled, sends a UDP packet to the port. If there is a response then
#the port is closed, otherwise it addes it to the list of possible UDP ports
          if udp:
            ans = sr1(IP(dst=ip)/UDP(dport=int(port)),timeout=5,verbose =0)
            time.sleep(1)
            if ans == None:
              udp_ports.append(port)
            else:
              pass
#adds an entry to the dictionary with the IP address and the list of open ports
        if tcp:
          tcp_address_port_dict[ip]=tcp_ports
          tcp_ports=[]
        if udp:
          udp_address_port_dict[ip]=udp_ports
          udp_ports=[]      
#creates an html report. It prints all the IP addresses and their associated open ports.
    with document(title="Scan Report") as doc:
      for ip in ips:
        h1(ip)
        if tcp:
          if ip in tcp_address_port_dict:
            h3("Open TCP Ports")
            for port in tcp_address_port_dict[ip]:
              h5(str(port))
        if udp:
          if ip in udp_address_port_dict:
            h3("Possibly open UDP Ports")
          for port in udp_address_port_dict[ip]:
            h5(str(port))
        if icmp:
          if ip in icmp_addresses:
            h5("Open to ICMP")

    with open('report.html','w') as f:
      f.write(doc.render())
    webbrowser.open('file://'+os.path.realpath('report.html'))

#Sets up command line argument parser and help information
parser = OptionParser()
parser.add_option('-t','--tcp',action="store_true",help='Specify to use tcp')
parser.add_option('-d', '--destination', help='Target-IP (comma separated if multiple, no spaces)')
parser.add_option('-f', '--file', help='name of file with target-IP (comma separated if multiple on one line, no spaces)')
parser.add_option('-p','--ports',help="Port to scan (comma separated if multiple, no spaces)")
parser.add_option('-g','--gui',action="store_true", help="If supplied, will launch GUI")
parser.add_option('-i','--icmp',action='store_true',help="Specify to use icmp")
parser.add_option('-u','--udp',action='store_true',help="Specify to use udp")

options, args = parser.parse_args()
#sets the filename to be opened
def getFileName():
  global filename
  filename=askopenfilename()


#if gui has been enabled, creates the GUI inputs and displays it
if options.gui:
  options = type('',(),{})()
  top = tk.Tk()
  frame1 = Frame(top)
  frame1.pack()

  frame2 = Frame(top)
  frame2.pack()

  frame3 = Frame(top)
  frame3.pack()

  frame4 = Frame(top)
  frame4.pack()

  frameBottom = Frame(top)
  frameBottom.pack(side=BOTTOM)

  dl = Label(frame1, text="Target-IP (comma separated if multiple, no spaces)")
  dl.pack(side=LEFT)
  d = Entry(frame1)
  d.pack(side=RIGHT)

  fl = Label(frame2, text="File with target-IP's")
  fl.pack(side=LEFT)
  f = Button(frame2,text="Choose file",command=getFileName)
  f.pack()

  pl = Label(frame3,text="Ports to scan (comma separated if multiple on one line, no spaces)")
  pl.pack(side=LEFT)
  p = Entry(frame3)
  p.pack(side=RIGHT)

  varTCP = IntVar()
  varUDP = IntVar()
  varICMP = IntVar()
  tr = Checkbutton(frame4,text="UDP",variable = varUDP)
  tr.pack()
  ur = Checkbutton(frame4,text="TCP",variable = varTCP)
  ur.pack()
  ir = Checkbutton(frame4,text="ICMP",variable = varICMP)
  ir.pack()
# processes the GUI inputs into the options object which is identical to
# the options that could be supplied from the command line
  def processInput():
    options.file = None
    options.ports = None
    options.ports = None
    options.destination = None

    options.ports = p.get()
    options.destination = d.get()
    options.tcp = varTCP.get()
    options.udp = varUDP.get()
    options.icmp = varICMP.get()
    if filename:
      options.file = filename
    scan(options)

  r = Button(frameBottom,text="Scan",command=processInput)
  r.pack()

  top.mainloop()
#if gui was not specified then this checks to make sure all the necessary parameters
#were supplied in the command line
else:
  errors =[]
  error_msg = "No %s specified. Use option %s"
  if not options.destination and not options.file:
    errors.append(error_msg % ('Target-IP or File', '-d or -f'))
  if not options.ports:
    errors.append(error_msg % ('Ports', '-p'))
  if not options.udp and not options.tcp and not options.icmp:
    errors.append(error_msg % ('Scan type','-u or -t or -i'))

  if errors:
    errors.append("Can use GUI using option -g")
    print '\n'.join(errors)
    sys.exit()
#if there were no errors then scan
  else:
    scan(options)
