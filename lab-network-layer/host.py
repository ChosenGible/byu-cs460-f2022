#!/usr/bin/python3

import argparse
import asyncio
import os
import socket
import sys
import json
import pprint
from prefix import ip_prefix_last_address

from numpy import source

from cougarnet.sim.host import BaseHost
from cougarnet.util import \
        mac_str_to_binary, mac_binary_to_str, \
        ip_str_to_binary, ip_binary_to_str

from forwarding_table import ForwardingTable

#From /usr/include/linux/if_ether.h:
ETH_P_IP = 0x0800 # Internet Protocol packet
ETH_P_ARP = 0x0806 # Address Resolution packet

#From /usr/include/net/if_arp.h:
ARPHRD_ETHER = 1 # Ethernet 10Mbps
ARPOP_REQUEST = 1 # ARP request
ARPOP_REPLY = 2 # ARP reply

#From /usr/include/linux/in.h:
IPPROTO_TCP = 6 # Transmission Control Protocol
IPPROTO_UDP = 17 # User Datagram Protocol

class Host(BaseHost):
    def __init__(self, ip_forward):
        super(Host, self).__init__()

        self._ip_forward = ip_forward
        self._arp_table = {}
        self._queued_pkts = {}

        self._forwarding_table = ForwardingTable()

        routes = json.loads(os.environ['COUGARNET_ROUTES'])
        
        for route in routes:
            prefix = route[0]
            intf = route[1]
            next_hop = route[2]
            self._forwarding_table.add_entry(prefix, intf, next_hop)

        #add ip prefixes for each interface
        for intf in self.physical_interfaces:
            info = self.int_to_info[intf]
            #print(info.ipv4_addrs)
            #print(info.ipv4_prefix_len)
            ip_addr = info.ipv4_addrs[0]
            prefix_len = str(info.ipv4_prefix_len)
            prefix =  ip_addr + '/' + prefix_len
            next_hop = None

            self._forwarding_table.add_entry(prefix, intf, next_hop)


        print()
        # do any additional initialization here

    def is_ip_in_arp_table(self, ip):
        return ip in self._arp_table.keys()

    def set_queued_pkt(self, ip, pkt):
        if not (ip in self._queued_pkts):
            self._queued_pkts[ip] = []
        self._queued_pkts[ip].append(pkt)
        

    def get_queued_pkts(self, ip):
        if ip in self._queued_pkts:
            return self._queued_pkts.pop(ip)
            

    def send_arp_message(self, s_ip, s_mac, d_ip, d_mac, opcode, intf):
        request = b'\x00\x01' + b'\x08\x00' + b'\x06' + b'\x04' + opcode + s_mac + s_ip + d_mac + d_ip

        dest_mac = b'0'
        if (opcode == b'\x00\x01'):
            dest_mac = mac_str_to_binary("ff:ff:ff:ff:ff:ff")
        else:
            dest_mac = d_mac

        frame = dest_mac + s_mac + b'\x08\x06' + request

        self.send_frame(frame, intf)
        print("sent arp frame\n")


    def _handle_frame(self, frame, intf):
        print("recieved frame: ", repr(frame))
        dest_mac = mac_binary_to_str(frame[0:6])
        if (dest_mac == "ff:ff:ff:ff:ff:ff" or dest_mac == self.int_to_info[intf].mac_addr):
            e_type = frame[12:14]
            if (e_type ==  b'\x08\x00'):
                print("ip")
                self.handle_ip(frame[14:], intf)
            elif (e_type == b'\x08\x06'):
                print("arp")
                self.handle_arp(frame[14:], intf)


    def _is_broadcast(self, ip, intf):
        broadcast = ip_prefix_last_address(int.from_bytes(ip, 'big'), socket.AF_INET, self.int_to_info[intf].ipv4_prefix_len)
        
        if (int.from_bytes(ip, 'big') == broadcast):
            return True
        return False

    def handle_ip(self, pkt, intf):
        print("handling ip")
        dest = ip_binary_to_str(pkt[16:20])
        print("dest ip: ", dest)

        is_for_this_host = False

        if (self._is_broadcast(ip_str_to_binary(dest), intf)):
            is_for_this_host = True

        for h_intf in self.physical_interfaces:
            if dest == self.int_to_info[h_intf].ipv4_addrs[0]:
                is_for_this_host == True

        print("for this host? ", is_for_this_host)

        if is_for_this_host:
            ip_type = int.from_bytes(pkt[9:10], byteorder='big')
            print("ip protocol: ", ip_type)

            if ip_type == 6:
                self.handle_tcp(pkt)
            elif ip_type == 17:
                self.handle_udp(pkt)
        else:
            self.not_my_packet(pkt, intf)




    def handle_tcp(self, pkt):
        print("was tcp")
        pass

    def handle_udp(self, pkt):
        print("was udp")
        pass

    def handle_arp(self, pkt, intf):
        print("getting an arp packet: ", repr(pkt))
        opcode = pkt[6:8]
        if (opcode == b'\x00\x01'):
            self.handle_arp_request(pkt, intf)
        else:
            self.handle_arp_response(pkt, intf)

    def handle_arp_response(self, pkt, intf):
        print("was arp response")
        sender_mac = mac_binary_to_str(pkt[8:14])
        sender_ip  = ip_binary_to_str(pkt[14:18])

        print("sender ip: ", sender_ip, ", sender mac: ", sender_mac)
        
        self._arp_table[sender_ip] = sender_mac

        queued_pkts = self.get_queued_pkts(sender_ip)

        for pkt in queued_pkts:
            d_mac = mac_str_to_binary(sender_mac)
            s_mac = mac_str_to_binary(self.int_to_info[intf].mac_addr)
            e_type = b'\x08\x00'
            
            frame = d_mac + s_mac + e_type + pkt

            self.send_frame(frame, intf)
            print("sent frame")

        print("")
            


    def handle_arp_request(self, pkt, intf):
        print("was arp request")
        sender_mac = mac_binary_to_str(pkt[8:14])
        sender_ip  = ip_binary_to_str(pkt[14:18])

        dest_ip  = ip_binary_to_str(pkt[24:28])

        print("sender ip: ", sender_ip, ", sender mac: ", sender_mac)
        
        self._arp_table[sender_ip] = sender_mac

        if (dest_ip == self.int_to_info[intf].ipv4_addrs[0]):
            opcode = b'\x00\02'
            s_mac = mac_str_to_binary(self.int_to_info[intf].mac_addr)
            s_ip  = ip_str_to_binary(dest_ip)
            d_mac = mac_str_to_binary(sender_mac)
            d_ip  = ip_str_to_binary(sender_ip)

            self.send_arp_message(s_ip, s_mac, d_ip, d_mac, opcode, intf)
        else:
            print("lol not me drop\n")

    def send_packet_on_int(self, pkt, intf, next_hop):
        print(f'Attempting to send packet on {intf} with next hop {next_hop}:\n{repr(pkt)}')
        
        if self.is_ip_in_arp_table(next_hop):
            print("hit in table")
            dest_mac = mac_str_to_binary(self._arp_table[next_hop])
            source_mac = mac_str_to_binary(self.int_to_info[intf].mac_addr)
            type_ip = b'\x08\x00'

            print("dest_mac:   ", dest_mac, " ", type(dest_mac))
            print("source_mac: ", source_mac, " ", type(source_mac))
            print("type_ip:    ", type_ip, " ", type(type_ip))
            print("payload:    ", pkt, " ", type(pkt))

            frame = dest_mac + source_mac + type_ip + pkt
            self.send_frame(frame, intf)
            print("sent frame\n")

            
        else:
            print("no hit in table")
            self.set_queued_pkt(next_hop, pkt)
            source_ip  = ip_str_to_binary(self.int_to_info[intf].ipv4_addrs[0])
            source_mac = mac_str_to_binary(self.int_to_info[intf].mac_addr)
            target_mac = mac_str_to_binary("00:00:00:00:00:00")
            opcode     = b'\x00\x01'

            print("source_ip:  ", source_ip,  " ", type(source_ip))
            print("source_mac: ", source_mac, " ", type(source_mac))
            print("dest_ip:    ", next_hop,   " ", type(next_hop))
            print("dest_mac:   ", target_mac, " ", type(target_mac))
            print("opcode:     ", opcode,     " ", type(opcode))

            self.send_arp_message(source_ip, source_mac, ip_str_to_binary(next_hop), target_mac, opcode, intf)


    def send_packet(self, pkt):
        print(f'Attempting to send packet:\n{repr(pkt)}')
        
        dest = ip_binary_to_str(pkt[16:20])
        print("dest ip: ", dest)

        intf, next_hop = self._forwarding_table.get_entry(dest)

        print("interface: ", intf, " next hop: ", next_hop)

        if intf == None:
            print("lol not valid interface\n")
            return
        
        if next_hop == None:
            next_hop = dest
        
        print("on: ", intf, " to: ", next_hop)
        self.send_packet_on_int(pkt, intf, next_hop)


    def forward_packet(self, pkt):
        print("fowarding packet")
        ttl = int.from_bytes(pkt[8:9], byteorder='big')

        ttl -= 1

        if ttl == 0:
            print("expired ttl, drop it")
            return

        new_pkt = pkt[:8] + ttl.to_bytes(1, byteorder='big') + pkt[9:]
        self.send_packet(new_pkt)

    def not_my_frame(self, frame, intf):
        pass

    def not_my_packet(self, pkt, intf):
        print("Forward? ", self._ip_forward)
        if self._ip_forward == True:
            self.forward_packet(pkt)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--router', '-r',
            action='store_const', const=True, default=False,
            help='Act as a router by forwarding IP packets')
    args = parser.parse_args(sys.argv[1:])

    with Host(args.router) as host:
        loop = asyncio.get_event_loop()
        try:
            loop.run_forever()
        finally:
            loop.close()

if __name__ == '__main__':
    main()
