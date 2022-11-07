from cougarnet.util import \
        ip_str_to_binary, ip_binary_to_str

from headers import IPv4Header, UDPHeader, ICMPHeader,TCPHeader, \
        IP_HEADER_LEN, UDP_HEADER_LEN, TCP_HEADER_LEN, \
        TCPIP_HEADER_LEN, UDPIP_HEADER_LEN
from host import Host
from mysocket import UDPSocket, TCPSocketBase

class TransportHost(Host):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.socket_mapping_udp = {}
        self.socket_mapping_tcp = {}

    def handle_tcp(self, pkt: bytes) -> None:
        ipv4_hdr = IPv4Header.from_bytes(pkt[0:20])
        tcp_hdr = TCPHeader.from_bytes(pkt[20:40])

        key = (ipv4_hdr.dst, tcp_hdr.dport, ipv4_hdr.src, tcp_hdr.sport)
        if key in self.socket_mapping_tcp:
            self.socket_mapping_tcp[key].handle_packet(pkt)
        else:
            key = (ipv4_hdr.dst, tcp_hdr.dport, None, None)
            if key in self.socket_mapping_tcp:
                self.socket_mapping_tcp[key].handle_packet(pkt)
            else:
                self.no_socket_tcp()

    def handle_udp(self, pkt: bytes) -> None:
        ipv4_hdr = IPv4Header.from_bytes(pkt[:20])
        udp_hdr = UDPHeader.from_bytes(pkt[20:28])

        key = (ipv4_hdr.dst, udp_hdr.dport)
        if key in self.socket_mapping_udp:
            self.socket_mapping_udp[key].handle_packet(pkt)
        else:
            self.no_socket_udp()

    def install_socket_udp(self, local_addr: str, local_port: int,
            sock: UDPSocket) -> None:
        self.socket_mapping_udp[(local_addr, local_port)] = sock

    def install_listener_tcp(self, local_addr: str, local_port: int,
            sock: TCPSocketBase) -> None:
        self.socket_mapping_tcp[(local_addr, local_port, None, None)] = sock

    def install_socket_tcp(self, local_addr: str, local_port: int,
            remote_addr: str, remote_port: int, sock: TCPSocketBase) -> None:
        self.socket_mapping_tcp[(local_addr, local_port, \
                remote_addr, remote_port)] = sock

    def no_socket_udp(self, pkt: bytes) -> None:
        icmp_hdr = ICMPHeader(3, 3, 0)
        pkt =

        pass

    def no_socket_tcp(self, pkt: bytes) -> None:
        pass
