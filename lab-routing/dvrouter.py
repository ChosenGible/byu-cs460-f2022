import asyncio
from curses.has_key import has_key
import json
import socket
import time

NEIGHBOR_CHECK_INTERVAL = 3
DV_TABLE_SEND_INTERVAL = 1
DV_PORT = 5016

from cougarnet.sim.host import BaseHost

from prefix import *
from forwarding_table_native import ForwardingTableNative as ForwardingTable

class DVRouter(BaseHost):
    def __init__(self):
        super(DVRouter, self).__init__()

        self.my_dv = {}

        #setup hostname to ip mapping
        self.hostname_to_ip = {}
        self.hostname_to_ip[self.hostname] = None
        
        #setup hostname timestamps for timeout (don't include self)
        self.hostname_timestamps = {}

        self.neighbor_dvs = {}

        self.forwarding_table = ForwardingTable()

        self._initialize_dv_sock()

        # Do any further initialization here

    def _initialize_dv_sock(self) -> None:
        '''Initialize the socket that will be used for sending and receiving DV
        communications to and from neighbors.
        '''

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.sock.bind(('0.0.0.0', DV_PORT))

    def init_dv(self):
        '''Set up our instance to work with the event loop, initialize our DV,
        and schedule our regular updates to be sent to neighbors.
        '''

        loop = asyncio.get_event_loop()

        # register our socket with the event loop, so we can handle datagrams
        # as they come in
        loop.add_reader(self.sock, self._handle_msg, self.sock)

        # Initialize our DV -- and optionally send our DV to our neighbors
        self.update_dv()

        # Schedule self.send_dv_next() to be called every second
        # (DV_TABLE_SEND_INTERVAL)
        loop.call_later(DV_TABLE_SEND_INTERVAL, self.send_dv_next)


    def _handle_msg(self, sock: socket.socket) -> None:
        ''' Receive and handle a message received on the UDP socket that is
        being used for DV messages.
        '''

        data, addrinfo = sock.recvfrom(65536)
        self.handle_dv_message(data)

    def _send_msg(self, msg: bytes, dst: str) -> None:
        '''Send a DV message, msg, on our UDP socket to dst.'''

        self.sock.sendto(msg, (dst, DV_PORT))

    def handle_dv_message(self, msg: bytes) -> None:
        message_str = msg.decode('utf-8')
        dv_metadata = json.loads(message_str)

        name = dv_metadata['name']
        ip = dv_metadata['ip']
        dv = dv_metadata['dv']

        if (name != self.hostname):
            self.hostname_to_ip[name] = ip
            self.hostname_timestamps[name] = time.time()
            self.neighbor_dvs[name] = dv
            

    def send_dv_next(self):
        '''Send DV to neighbors, and schedule this method to be called again in
        1 second (DV_TABLE_SEND_INTERVAL).
        '''

        self.send_dv()
        loop = asyncio.get_event_loop()
        loop.call_later(DV_TABLE_SEND_INTERVAL, self.send_dv_next)

    def handle_down_link(self, neighbor: str):
        self.log(f'Link down: {neighbor}')
        self.neighbor_dvs.pop[neighbor]
        self.hostname_to_ip.pop[neighbor]
        self.hostname_timestamps.pop[neighbor]

    def resolve_neighbor_dvs(self):
        '''Return a copy of the mapping of neighbors to distance vectors, with
        IP addresses replaced by names in every neighbor DV.
        '''

        neighbor_dvs = {}
        for neighbor in self.neighbor_dvs:
            neighbor_dvs[neighbor] = self.resolve_dv(self.neighbor_dvs[neighbor])
        return neighbor_dvs

    def resolve_dv(self, dv: dict) -> dict:
        '''Return a copy of distance vector dv with IP addresses replaced by
        names.
        '''

        resolved_dv = {}
        for dst, distance in dv.items():
            if '/' not in dst:
                try:
                    dst = socket.getnameinfo((dst, 0), 0)[0]
                except:
                    pass
            resolved_dv[dst] = distance
        return resolved_dv

    def neighbor_ip_to_intf(self, ip):
            for key in self.int_to_info.keys():
                k_ip = self.int_to_info[key].ipv4_addrs[0]
                if ip == k_ip:
                    return key
            return None

    def update_dv(self) -> None:
        print("update start")
        #check timestamps
        curr_time = time.time()
        for n_hostname in self.hostname_timestamps.keys():
            n_timestamp = self.hostname_timestamps[n_hostname]
            if (curr_time - n_timestamp) > 3:
                self.handle_down_link(n_hostname)

        #setup my dv info
        min_dist = {}
        for info in self.int_to_info.values():
            if (len(info.ipv4_addrs) > 0):
                addr = info.ipv4_addrs[0]
                prefix = addr + "/32"
                min_dist[prefix] = (self.hostname, 0)

        #check for least cost neighbor
        for n_hostname in self.neighbor_dvs.keys():
            n_dv = self.neighbor_dvs[n_hostname]
            print("n: ", n_hostname, " dv: ", json.dumps(n_dv))

            for prefix in n_dv.keys:
                p_cost = 1 + n_dv[prefix]
                if not (prefix in min_dist) or min_dist[prefix][1] > p_cost:
                    min_dist[prefix] = (n_hostname, p_cost)
        
        #build new dv
        new_dv = {}
        for prefix in min_dist:
            new_dv[prefix] = min_dist[prefix][1]
            
        print("old DV: ", json.dumps(self.my_dv))
        print("new DV: ", json.dumps(new_dv))

        #check if old != new
        if self.my_dv != new_dv:
            self.my_dv = new_dv

            #update forwarding tables
            self.forwarding_table.flush()
            
            for prefix in min_dist.keys():
                hostname = min_dist[prefix][0]
                next_hop = self.hostname_to_ip[hostname]
                self.forwarding_table.add_entry(prefix, None, next_hop)
        else:
            print("update settled")
        print("Update finished\n")

    def bcast_for_int(self, intf: str) -> str:
        ip_int = ip_str_to_int(self.int_to_info[intf].ipv4_addrs[0])
        ip_prefix_int = ip_prefix(ip_int, socket.AF_INET, self.int_to_info[intf].ipv4_prefix_len)
        ip_bcast_int = ip_prefix_last_address(ip_prefix_int, socket.AF_INET, self.int_to_info[intf].ipv4_prefix_len)
        bcast = ip_int_to_str(ip_bcast_int, socket.AF_INET)
        return bcast

    def send_dv(self) -> None:
        for intf in self.int_to_info.keys():
            if len(self.int_to_info[intf].ipv4_addrs) > 0:
                bcast = self.bcast_for_int(intf)
                dv_with_metadata = {}
                dv_with_metadata['ip'] = self.int_to_info[intf].ipv4_addrs[0]
                dv_with_metadata['name'] = self.hostname
                dv_with_metadata['dv'] = self.my_dv

                dv_message_str = json.dumps(dv_with_metadata)
                dv_message_bytes = dv_message_str.encode('utf-8')

                self._send_msg(dv_message_bytes, bcast)
        pass
