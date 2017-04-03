#!/usr/bin/env python

class Stats:


    def __init__(self):
        self.trafficCount = 0
        self.totalPktSize = 0
        self.numOfProtocol = 0
        self.numOfServer = 0
        self.serverAddr = {}


#test

import csv
import os
import socket
import dpkt
import time
import re

f = open('test.pcap')
pcap = dpkt.pcap.Reader(f)

#
dict = {}

pktCounter = 0


for ts,buff in pcap:

    pktCounter += 1

    try:
        ether = dpkt.ethernet.Ethernet(buff)
        
        # Mac address for identification
        src_mac = (ether.dst).encode("hex")
        dst_mac = (ether.src).encode("hex")
        smac = ':'.join([src_mac[i:i+2] for i in range(0, len(src_mac), 2)])
        dmac = ':'.join([dst_mac[i:i+2] for i in range(0, len(dst_mac), 2)])





        # Packet
        ip = ether.data
        tcp = ip.data
        #src = socket.inet_ntoa(ip.src)
        src = ip.src
        srcport = tcp.sport
        #dst = socket.inet_ntoa(ip.dst)
        dst = ip.dst
        dstport = tcp.dport
        
        # Definition of Time
        showTime = time.gmtime(ts)
        timeF = time.strftime("%Y/%m/%d %H:%M:%S", showTime)
        
        # Packet Size
        sizeP = len(buff)

        
        # Data filtering
        p = re.compile("<Line>(.*?)\</Line>", re.IGNORECASE|re.DOTALL)
        
        
        #group by mac id;
        if smac not in dict:
            dict[smac] = Stats()

        dict[smac].trafficCount += 1
        dict[smac].totalPktSize += sizeP
        if dst not in dict[smac].serverAddr:
            dict[smac].numOfServer+=1
            dict[smac].serverAddr[dst] = 1
        
        # Packet print
        print "PktNr: %s" %(pktCounter)
        print "PktSize: %s" %(sizeP)
        print "Time: %s" %(timeF)
        print "src: (MAC: %s) \033[1;32m(IP:%s)\033[1;m (port:%s) --> dest: (MAC: %s) \033[1;31m(IP:%s)\033[1;m (port:%s)" % (smac,src,srcport,dmac,dst,dstport) + "\n"




    except AttributeError:
        pass

    if pktCounter >= 100:
        break

if not os.path.exists('dict.csv'):
    open('dict.csv', 'a').close()

with open('dict.csv', 'wb') as csv_file:
    writer = csv.writer(csv_file)
    for key, value in dict.items():
       writer.writerow([key, value.trafficCount, value.totalPktSize/value.trafficCount, value.numOfProtocol, value.numOfServer])




