'''
>>> from subnet import IPAddress, Subnet
>>> table = ForwardingTable()
>>> table.add_entry('10.20.0.0/23', 'r1-c', '10.30.0.2')
>>> table.add_entry('10.20.0.0/24', 'r1-d', '10.30.0.6')
>>> table.add_entry('10.20.0.0/25', 'r1-e', '10.30.0.10')
>>> table.add_entry('10.20.0.0/26', 'r1-f', '10.30.0.14')
>>> table.add_entry('10.20.0.0/27', 'r1-g', '10.30.0.18')
>>> table.add_entry('10.20.0.0/28', 'r1-h', '10.30.0.22')
>>> table.add_entry('10.20.0.0/29', 'r1-i', '10.30.0.26')
>>> table.add_entry('10.20.0.0/30', 'r1-j', '10.30.0.30')
>>> table.add_entry('0.0.0.0/0', 'r1-k', '10.30.0.34')

Test the ForwardingTable.get_entry() method
>>> table.get_entry('10.20.0.25')
('someintf', 'someip')
>>> table.get_entry('10.20.0.34')
('someintf', 'someip')
>>> table.get_entry('10.20.1.20')
('someintf', 'someip')
>>> table.get_entry('10.20.3.1')
('someintf', 'someip')
>>> table.get_entry('10.20.0.2')
('someintf', 'someip')
>>> table.get_entry('10.20.0.11')
('someintf', 'someip')
>>> table.get_entry('10.20.0.150')
('someintf', 'someip')
>>> table.get_entry('10.20.0.7')
('someintf', 'someip')
>>> table.get_entry('10.20.0.75')
('someintf', 'someip')
'''

from subnet import IPAddress, Subnet

class ForwardingTable(object):
    def __init__(self):
        self.entries = {}

    def add_entry(self, prefix, intf, next_hop):
        '''
        Add forwarding entry mapping prefix to interface and next hop IP
        address.

        prefix: str or Subnet instance
        '''

        if isinstance(prefix, str):
            prefix = Subnet(prefix)

        if intf is None:
            intf, next_hop1 = self.get_entry(next_hop)

        self.entries[prefix] = (intf, next_hop)

    def remove_entry(self, prefix):
        '''
        Remove the forwarding entry matching prefix.

        prefix: str or Subnet instance
        '''

        if isinstance(prefix, str):
            prefix = Subnet(prefix)

        if prefix in self.entries:
            del self.entries[prefix]

    def flush(self, family=None, global_only=True):
        '''
        Flush the routing table.

        prefix: str
        '''

        routes = self.get_all_entries(family=family, \
                resolve=False, global_only=global_only)

        for prefix in routes:
            self.remove_entry(prefix)


    def get_entry(self, ip_address):
        '''
        Return the subnet entry having the longest prefix match of ip_address.
        The entry is a tuple consisting of interface and next-hop IP address.
        If there is no match, return None, None.

        ip_address: str or IPAddress instance
        '''

        if isinstance(ip_address, str):
            ip_address = IPAddress(ip_address)
        
        #FIXME - complete the rest of the method
        return None, None

    def get_all_entries(self, family=None, resolve=False, global_only=True):

        entries = {}
        for prefix in self.entries:
            intf, next_hop = self.entries[prefix]
            if next_hop is not None or not global_only:
                entries[prefix] = (intf, next_hop)
        return entries
