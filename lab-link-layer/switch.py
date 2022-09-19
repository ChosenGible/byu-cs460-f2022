#!/usr/bin/python3

import asyncio
import time
from cougarnet.sim.host import BaseHost

class Switch(BaseHost):
    def __init__(self):
        super(Switch, self).__init__()

        self.macAddressTable = {}

        # do any initialization here...

    def _handle_frame(self, frame, intf):
        print('Received frame: %s' % repr(frame))

        #purge old entries
        self._purge_table()

        #check for Trunk Protocol: (if):
        if False:
            pass
            #grab VLAN group
            #Strip trunk protocol
        
        #extract destination and source from frame
        dest = frame[0:6]
        source = frame[6:12]

        #check table if destination exists (if):
        if self._is_dest_in_table(dest):
            #update table with source
            self._add_source_to_table(source, intf)
            
            #send frame to interface from table
            selected_intf = self.macAddressTable[dest][0]

        else:
            #add to table with soruce
            self._add_source_to_table(source, intf)

            
            #send frame to all unknown interfaces
                #check if sending over trunk (if):
                    #add trunk protocol

    def _purge_table(self):
        for k in self.macAddressTable.keys():
            ttl = self.macAddressTable[k][1]

            if ttl < time.time():
                self.macAddressTable.pop(k)

    def _is_dest_in_table(self, dest):
        return dest in self.macAddressTable.keys()

    def _add_source_to_table(self, source, intf):
        ttl = time.time() + 8
        self.macAddressTable[source] = (intf, ttl)

def main():
    with Switch() as switch:

        loop = asyncio.get_event_loop()
        try:
            loop.run_forever()
        finally:
            loop.close()

if __name__ == '__main__':
    main()
