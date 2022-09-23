#!/usr/bin/python3

import asyncio
from sys import byteorder
import time
import binascii

from cougarnet.sim.host import BaseHost

class Switch(BaseHost):
    def __init__(self):
        super(Switch, self).__init__()

        self.macAddressTable = {}

        # do any initialization here...

    def _handle_frame(self, frame, intf):
        print("Start")
        # print('Received frame: %s\n' % repr(frame))

        #purge old entries
        self._purge_table()

        #trunk protocol overhead
        vlan = self._get_vlan_from_frame(frame)
        frame = self._strip_trunk_protocol_from_frame(frame)
        
        #extract destination and source from frame
        dest = frame[0:6]
        source = frame[6:12]

        if vlan == -1:
            vlan = self.int_to_info[intf].vlan

        # if not(self._is_dest_in_vlan(dest, vlan)):
        #     print("drop packet")
        #     return

        #update table with source
        self._add_source_to_table(source, intf)

        # print("frame (s): %s'" % repr(frame))
        print("vlan:      %s" % vlan)
        print("dest:      %s" % repr(dest))
        print("source:    %s\n" % repr(source))

        if dest == b'\xff\xff\xff\xff\xff\xff':
            print("Brodcast")

            for all_intf in self.physical_interfaces:
                if all_intf == intf:
                    continue

                print("source: ", repr(source), " with VLAN: ", self.int_to_info[intf].vlan)
                print("dest:   ", repr(dest),   " with VLAN: ", self.int_to_info[all_intf].vlan)

                self._send_frame_to_intf(frame, all_intf, vlan)

        #check table if destination exists (if):
        elif self._is_dest_in_table(dest):
            print("Found match in table!\n")
            
            #send frame to interface from table
            selected_intf = self.macAddressTable[dest][0]

            # if vlan == -1:
            #     vlan = self.int_to_info[selected_intf].vlan
            #     print("intf: ", selected_intf, " vlan: ", vlan)

            print("source: ", repr(source), " with VLAN: ", self.int_to_info[intf].vlan)
            print("dest:   ", repr(dest),   " with VLAN: ", self.int_to_info[selected_intf].vlan)

            self._send_frame_to_intf(frame, selected_intf, vlan)

        else:
            print("Did not find a match in the table!\n")

            #send frame to all unknown interfaces
            for unknown_intf in self.physical_interfaces:
                # if vlan == -1:
                #     n_vlan = self.int_to_info[unknown_intf].vlan
                #     print("intf: ", unknown_intf, " vlan: ", vlan)

                #ignore known and sending intfaces
                if self._is_intf_in_table(unknown_intf) or unknown_intf == intf:
                    continue

                print("source: ", repr(source), " with VLAN: ", self.int_to_info[intf].vlan)
                print("dest:   ", repr(dest),   " with VLAN: ", self.int_to_info[unknown_intf].vlan)
                #send frame to interface from table
                self._send_frame_to_intf(frame, unknown_intf, vlan)
        
        print("Done\n\n\n")



    def _send_frame_to_intf(self, frame, intf, vlan):
        if vlan != self.int_to_info[intf].vlan and self.int_to_info[intf].vlan != -1:
            print("drop packet")
            return

        if (self._is_trunk_link(intf)):
            #add trunk protocol
            print("hit construct")
            frame = self._construct_trunk_protocol(frame, vlan)
                
        # print("intf: %s" % intf)
        print("sending frame: %s\n" % repr(frame))
        self.send_frame(frame, intf)

    def _construct_trunk_protocol(self, frame, vlan):
        # print("vlan: ", vlan)
        assert vlan != -1
        vbytes = vlan.to_bytes(2, byteorder='big')
        b = b'\x81\x00' + vbytes
        # print(binascii.hexlify(b).decode('latin1'))
        return frame[0:12] + b + frame[12:]

    def _strip_trunk_protocol_from_frame(self, frame):
        if frame[12:14] == b'\x81\x00':
            return frame[0:12] + frame[16:]
        else:
            return frame

    def _get_vlan_from_frame(self, frame):
        if frame[12:14] == b'\x81\x00':
            # print("got trunk header")
            return int.from_bytes(frame[14:16], byteorder='big') 
        else:
            return -1

    def _purge_table(self):
        for k in list(self.macAddressTable.keys()):
            ttl = self.macAddressTable[k][1]

            if ttl < time.time():
                self.macAddressTable.pop(k)

    def _is_dest_in_table(self, dest):
        return dest in self.macAddressTable.keys()

    def _is_dest_in_vlan(self, dest, vlan):
        if not (self._is_dest_in_table(dest)):
            return False
        intf = self.macAddressTable[dest][0]
        intfInfo = self.int_to_info[intf]
        if vlan == intfInfo.vlan:
            return True
        elif intfInfo.vlan == -1:
            return True
        return False

    def _add_source_to_table(self, source, intf):
        ttl = time.time() + 8
        self.macAddressTable[source] = (intf, ttl)

    def _is_intf_in_table(self, intf):
        for value in self.macAddressTable.values():
            if intf in value:
                return True
        return False

def main():
    with Switch() as switch:

        loop = asyncio.get_event_loop()
        try:
            loop.run_forever()
        finally:
            loop.close()

if __name__ == '__main__':
    main()
