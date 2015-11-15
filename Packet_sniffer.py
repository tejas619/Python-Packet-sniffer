#!/usr/bin/python

import socket
import os
import struct
import binascii

def analyze_udp_header(data):
	udp_hdr = struct.unpack("!4H",data[:8])
	src_port = udp_hdr[0]
	dst_port = udp_hdr[1]
	length = udp_hdr[2]
	chek_sum = udp_hdr[3]
	
	data = data[8:]
	return data

def analyze_tcp_header(data):
	tcp_hdr = struct.unpack("!2H2I4H", data[:20])
	src_port = tcp_hdr[0]
	dst_port = tcp_hdr[1]
	seq_num = tcp_hdr[2]
	ack_num = tcp_hdr[3]
	data_offset = tcp_hdr[4] >> 12
	reserved = (tcp_hdr[4] >> 6) & 0x03ff
	flags = tcp_hdr[4] & 0x003f
	urg = flags & 0x0020
	ack = flags & 0x0010
	psh = flags & 0x0008
	rst = flags & 0x0004
	syn = flags & 0x0002
	fin = flags & 0x0001 
	window = tcp_hdr[5]
	checksum = tcp_hdr[6]
	urg_ptr = tcp_hdr[7]
	
	data = data[20:]
	return data

def analyze_ip_header(data):
	ip_hdr = struct.unpack("!6H4s4s", data[:20])
	ver = ip_hdr[0] >> 12 #everything to the left of version is gonna be 0
	ihl = (ip_hdr[0] >> 8) & 0x0f #we get ihl, but also we get version. hence, make version bits to 0
	tos = ip_hdr[0] & 0x00ff #type of service is last part of our ip_hdr[0]
	tot_len = ip_hdr[1]
	ip_id = ip_hdr[2]
	flags = ip_hdr[3] >> 13 # only going to get 1st 3 bits of flags
	frag_offset = ip_hdr[3] & 0x1fff
	ip_ttl = ip_hdr[4] >> 8 # timetolive
	ip_proto = ip_hdr[4] & 0x00ff # Protocol
	chk_sum = ip_hdr[5] #to get the header checksum bits
	src_addr = socket.inet_ntoa(ip_hdr[6]) #network to address
	dst_addr = socket.inet_ntoa(ip_hdr[7])
	no_frag = flags >> 1
	more_frag = flags & 0x1 
	
	print "|*************IP HEADER************|"
	print "|\tVersion:\t%s" %ver
	print "|\tIHL:\t\t%hu" %ihl
	print "|\tTOS:\t\t%hu" %tos
	print "|\tLength:\t\t%hu" %tot_len
	print "|\tID:\t\t%hu" %ip_id
	print "|\tNo Frag:\t%hu" %no_frag
	print "|\tMore Frag:\t%hu" %more_frag
	print "|\tOffset:\t\t%hu" %frag_offset
	print "|\tTTL:\t\t%hu" %ip_ttl
	print "|\tNExt Protocol:\t%hu" %ip_proto
	print "|\tChecksum:\t%hu" %chk_sum
	print "I am inside analyze_ip_header"
	print "|\tSource IP:\t\t%s" %src_addr
	print "|\tDest IP:\t\t%s" %dst_addr
	
	if ip_proto == 6: # TCP magic numbers
		next_proto = "TCP"
	if ip_proto == 17:
		next_proto = "UDP"
	
	data = data[20:]
	return data, next_proto

def analyze_ether_header(data):
	ip_bool = False
	ethr_hdr = struct.unpack("!6s6sH", data[:14]) 
	dest_mac = binascii.hexlify(ethr_hdr[0])
	src_mac  = binascii.hexlify(ethr_hdr[1])
	proto    = ethr_hdr[2] >> 8
	
	print "|*******************ETHERNET HEADER**********|"
	print "|\tDestination MAC:\t %s:%s:%s:%s:%s:%s" % (dest_mac[0:2],
	dest_mac[2:4],dest_mac[4:6],dest_mac[6:8],dest_mac[8:10],dest_mac[10:12])
	
	print "|\tSource MAC:\t %s:%s:%s:%s:%s:%s" % (src_mac[0:2],
	src_mac[2:4],src_mac[4:6],src_mac[6:8],src_mac[8:10],src_mac[10:12])
	
	print "|Proto:\t%s" % hex(proto)
	
	if proto == 0x08: #IPv4
		ip_bool = True
	
	data = data[14:]
	return data, ip_bool 
	

def main():
	
	sniffer_socket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x003))
	recv_data = sniffer_socket.recv(2048)
	os.system("clear")
	
	data , ip_bool = analyze_ether_header(recv_data)
	
	if ip_bool:
		data, next_proto = analyze_ip_header(data)
	else:
		return
	
	if next_proto == "TCP":
		data = analyze_tcp_header(data)
	elif next_proto == "UDP":
		data = analyze_udp_header(data)
	
while True:
	main()
