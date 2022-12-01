import random

TCP_FLAGS_SYN = 0x02
TCP_FLAGS_RST = 0x04
TCP_FLAGS_ACK = 0x10

TCP_STATE_LISTEN = 0
TCP_STATE_SYN_SENT = 1
TCP_STATE_SYN_RECEIVED = 2
TCP_STATE_ESTABLISHED = 3
TCP_STATE_FIN_WAIT_1 = 4
TCP_STATE_FIN_WAIT_2 = 5
TCP_STATE_CLOSE_WAIT = 6
TCP_STATE_CLOSING = 7
TCP_STATE_LAST_ACK = 8
TCP_STATE_TIME_WAIT = 9
TCP_STATE_CLOSED = 10

from headers import IPv4Header, UDPHeader, TCPHeader, \
        IP_HEADER_LEN, UDP_HEADER_LEN, TCP_HEADER_LEN, \
        TCPIP_HEADER_LEN, UDPIP_HEADER_LEN


#From /usr/include/linux/in.h:
IPPROTO_TCP = 6 # Transmission Control Protocol
IPPROTO_UDP = 17 # User Datagram Protocol

from buffer import TCPSendBuffer, TCPReceiveBuffer


class TCPListenerSocket:
    def __init__(self, local_addr, local_port, handle_new_client_func,
            send_ip_packet_func, notify_on_data_func, event_loop,
            fast_retransmit=False, initial_cwnd=1000, mss=1000,
            congestion_control='none'):

        # These are all vars that are saved away for instantiation of TCPSocket
        # objects when new connections are created.
        self._local_addr = local_addr
        self._local_port = local_port
        self._handle_new_client = handle_new_client_func

        self._send_ip_packet_func = send_ip_packet_func
        self._notify_on_data_func = notify_on_data_func
        self._event_loop = event_loop

        self._fast_retransmit = fast_retransmit
        self._initial_cwnd = initial_cwnd
        self._mss = mss
        self._congestion_control = congestion_control

    def handle_packet(self, pkt):
        ip_hdr = IPv4Header.from_bytes(pkt[:IP_HEADER_LEN])
        tcp_hdr = TCPHeader.from_bytes(pkt[IP_HEADER_LEN:TCPIP_HEADER_LEN])
        data = pkt[TCPIP_HEADER_LEN:]

        if tcp_hdr.flags & TCP_FLAGS_SYN:
            sock = TCPSocket(self._local_addr, self._local_port,
                    ip_hdr.src, tcp_hdr.sport,
                    TCP_STATE_LISTEN,
                    send_ip_packet_func=self._send_ip_packet_func,
                    notify_on_data_func=self._notify_on_data_func,
                    event_loop=self._event_loop,
                    fast_retransmit=self._fast_retransmit,
                    initial_cwnd=self._initial_cwnd, mss=self._mss,
                    congestion_control=self._congestion_control)

            self._handle_new_client(self._local_addr, self._local_port,
                    ip_hdr.src, tcp_hdr.sport, sock)

            sock.handle_packet(pkt)


class TCPSocket:
    def __init__(self, local_addr, local_port,
            remote_addr, remote_port, state,
            send_ip_packet_func, notify_on_data_func, event_loop,
            fast_retransmit=False, initial_cwnd=1000, mss=1000,
            congestion_control='none'):

        # The local/remote address/port information associated with this
        # TCPConnection
        self._local_addr = local_addr
        self._local_port = local_port
        self._remote_addr = remote_addr
        self._remote_port = remote_port

        # The current state (TCP_STATE_LISTEN, TCP_STATE_CLOSED, etc.)
        self.state = state

        # Helpful methods for helping us send IP packets and
        # notifying the application that we have received data.
        self._send_ip_packet = send_ip_packet_func
        self._notify_on_data = notify_on_data_func

        # The event loop
        self._event_loop = event_loop

        # Base sequence number
        self.base_seq_self = self.initialize_seq()

        # Base sequence number for the remote side
        self.base_seq_other = None

        # The largest sequence number that has been acknowledged so far.  This
        # is the next sequence number expected be be received by the remote
        # side.
        self.seq = self.base_seq_self + 1

        # The acknowledgment number to send with any packet.  This represents
        # the largest in-order sequence number not yet received.
        self.ack = None

        self.ssthresh = 64000

        # The maximum segment size (MSS), which represents the maximum number
        # of bytes that may be transmitted in a single TCP segment.
        self.mss = mss

        # The congestion window (cwnd), which represents the total number of
        # bytes that may be outstanding (unacknowledged) at one time
        self.cwnd = initial_cwnd
        self.cwnd_inc = self.cwnd

        self.congestion_control = congestion_control

        # Send, receive, and ready buffers.  The send buffer is initialized
        # with our base sequence number.  The receive buffer is initialized
        # with the base sequence number of the remote side.  The ready buffer
        # is what is tapped into when recv() is called on the socket.
        self.send_buffer = TCPSendBuffer(self.base_seq_self + 1) 
        self.receive_buffer = None
        self.ready_buffer = b''

        # The number of duplicate acknowledgments
        self.num_dup_acks = 0
        self.last_ack = 0

        # Timeout duration in seconds
        self.timeout = 1

        # Active time instance (Event instance or None)
        self.timer = None

        # Whether or not we support fast_retransmit (boolean)
        self.fast_retransmit = fast_retransmit


    @classmethod
    def connect(cls, local_addr, local_port,
            remote_addr, remote_port,
            send_ip_packet_func, notify_on_data_func, event_loop,
            fast_retransmit=False, initial_cwnd=1000, mss=1000,
            congestion_control='none'):
        sock = cls(local_addr, local_port,
                remote_addr, remote_port,
                TCP_STATE_CLOSED,
                send_ip_packet_func, notify_on_data_func, event_loop,
                fast_retransmit=fast_retransmit,
                initial_cwnd=initial_cwnd, mss=mss,
                congestion_control=congestion_control)

        sock.initiate_connection()

        return sock

    def bypass_handshake(self, base_seq_self, base_seq_other):
        '''
        Bypass the TCP three-way handshake.  Allocate a TCPReceiveBuffer
        instance, and initialize it with the base sequence number of the peer
        on the other side of the connection.

        Normally this is done in in handle_syn() (after the SYN is received)
        for the server and in handle_synack() (after the SYNACK is received) in
        the client.
        '''
        self.base_seq_self = base_seq_self
        self.seq = base_seq_self + 1
        self.send_buffer = TCPSendBuffer(self.base_seq_self + 1)

        self.base_seq_other = base_seq_other
        self.ack = base_seq_other + 1
        self.receive_buffer = TCPReceiveBuffer(self.base_seq_other + 1)

    def handle_packet(self, pkt):
        ip_hdr = IPv4Header.from_bytes(pkt[:IP_HEADER_LEN])
        tcp_hdr = TCPHeader.from_bytes(pkt[IP_HEADER_LEN:TCPIP_HEADER_LEN])
        data = pkt[TCPIP_HEADER_LEN:]

        if self.state != TCP_STATE_ESTABLISHED:
            self.continue_connection(pkt)

        if self.state == TCP_STATE_ESTABLISHED:
            if data:
                # handle data
                self.handle_data(pkt)
            if tcp_hdr.flags & TCP_FLAGS_ACK:
                # handle ACK
                self.handle_ack(pkt)

    def initialize_seq(self):
        return random.randint(0, 65535)

    def initiate_connection(self):
        pass

    def handle_syn(self, pkt):
        pass

    def handle_synack(self, pkt):
        pass

    def handle_ack_after_synack(self, pkt):
        pass

    def continue_connection(self, pkt):
        if self.state == TCP_STATE_LISTEN:
            self.handle_syn(pkt)
        elif self.state == TCP_STATE_SYN_SENT:
            self.handle_synack(pkt)
        elif self.state == TCP_STATE_SYN_RECEIVED:
            self.handle_ack_after_synack(pkt)

        if self.state == TCP_STATE_ESTABLISHED:
            pass

    @classmethod
    def create_packet(cls, src, sport, dst, dport,
            seq, ack, flags, data=b''):
        data_len = len(data)
        tcp_hdr = TCPHeader(sport, dport, seq, ack, flags, 0)

        ipv4_len = 20 + 20 + data_len
        ipv4_hdr = IPv4Header(ipv4_len, 64, 6, 0, src, dst)

        return ipv4_hdr.to_bytes() + tcp_hdr.to_bytes() + data

    def send_packet(self, seq, ack, flags, data=b''):
        pkt = self.create_packet(self._local_addr, self._local_port, self._remote_addr, self._remote_port, seq, ack, flags, data)
        self._send_ip_packet(pkt)

    def relative_seq_other(self, seq):
        '''
        Return the specified sequence number (int) relative to the base
        sequence number for the other side of the connection.

        seq: An int value to be made relative to the base sequence number.
        '''

        return seq - self.base_seq_other


    def relative_seq_self(self, seq):
        '''
        Return the specified sequence number (int) relative to our base
        sequence number.

        seq: An int value to be made relative to the base sequence number.
        '''

        return seq - self.base_seq_self

    def send_if_possible(self):
        while (True):
            inAir = self.send_buffer.bytes_outstanding()
            if inAir >= self.cwnd:
                return
            if self.send_buffer.bytes_not_yet_sent() <= 0:
                return

            data, seq = self.send_buffer.get(self.mss)
            flags = TCPHeader.makeFlags(False, False)
            self.send_packet(seq, self.ack, flags, data)
            if (self.timer == None):
                self.start_timer()

    def send(self, data):
        self.send_buffer.put(data)
        self.send_if_possible()

    def recv(self, num):
        data = self.ready_buffer[:num]
        self.ready_buffer = self.ready_buffer[num:]
        return data

    def handle_data(self, pkt):
        ip_hdr = IPv4Header.from_bytes(pkt[:IP_HEADER_LEN])
        tcp_hdr = TCPHeader.from_bytes(pkt[IP_HEADER_LEN:TCPIP_HEADER_LEN])

        seg_data = pkt[TCPIP_HEADER_LEN:]
        seg_seq = tcp_hdr.seq

        self.receive_buffer.put(seg_data, seg_seq)
        ready_data, self.ack = self.receive_buffer.get()

        self.send_ack()

        self.ready_buffer += ready_data
        self._notify_on_data()
        pass

    def handle_ack(self, pkt):
        ip_hdr = IPv4Header.from_bytes(pkt[:IP_HEADER_LEN])
        tcp_hdr = TCPHeader.from_bytes(pkt[IP_HEADER_LEN:TCPIP_HEADER_LEN])

        ack = tcp_hdr.ack

        if self.send_buffer.bytes_outstanding > 0:
            if ack == self.last_ack:
                self.num_dup_acks += 1
            else:
                self.last_ack = ack
                self.num_dup_acks = 0 # first ack seen

        if self.num_dup_acks == 3 and self.fast_retransmit:
            self.fast_retransmiter()

        self.send_buffer.slide(ack)
        self.seq = ack
        self.cancel_timer()
        if (self.send_buffer.bytes_outstanding() > 0):
            self.start_timer()
        
        self.send_if_possible()

    def retransmit(self):
        data, seq = self.send_buffer.get_for_resend(self.mss)
        flags = TCPHeader.makeFlags(False, False)
        self.send_packet(seq, self.ack, flags, data)
        self.cancel_timer()
        self.start_timer()

    def fast_retransmiter(self):
        data, seq = self.send_buffer.get_for_resend(self.mss)
        flags = TCPHeader.makeFlags(False, False)
        self.send_packet(seq, self.ack, flags, data)

    def start_timer(self):
        self.timer = self._event_loop.schedule_event(self.timeout, self.retransmit)

    def cancel_timer(self):
        if not self.timer:
            return
        self._event_loop.cancel_event(self.timer)
        self.timer = None

    def send_ack(self):
        self.send_packet(self.seq, self.ack, TCP_FLAGS_ACK)
