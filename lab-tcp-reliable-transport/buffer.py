import json

class TCPSendBuffer(object):
    def __init__(self, seq: int):
        self.buffer = b''
        self.base_seq = seq
        self.next_seq = self.base_seq
        self.last_seq = self.base_seq

    def bytes_not_yet_sent(self) -> int:
        return self.last_seq - self.next_seq

    def bytes_outstanding(self) -> int:
        return self.next_seq - self.base_seq

    def put(self, data: bytes) -> int:
        # print("start put with data: ", data)
        # print("seqs - base: ", self.base_seq, ", next: ", self.next_seq, ", last: ", self.last_seq)
        # print("buffer: ", self.buffer)
        self.last_seq += len(data)
        self.buffer += data
        # print("seqs - base: ", self.base_seq, ", next: ", self.next_seq, ", last: ", self.last_seq)
        # print("buffer: ", self.buffer)
        # print("end put")
        pass

    def get(self, size: int) -> tuple[bytes, int]:
        # print("Start get with size: ", size)
        # print("seqs - base: ", self.base_seq, ", next: ", self.next_seq, ", last: ", self.last_seq)
        index = self.next_seq - self.base_seq
        # print("Relative next_seq: ", index)
        
        # print(size + self.next_seq)
        if (size + self.next_seq) < self.last_seq:
            # print("Size smaller than buffer")
            data = self.buffer[index:index + size]
            return_seq = self.next_seq
            # print("data: ", data, " seq: ", return_seq)
            self.next_seq += size
            # print("seqs - base: ", self.base_seq, ", next: ", self.next_seq, ", last: ", self.last_seq)
            # print("End get")
            return (data, return_seq)
        else:
            # print("Size greater than buffer")
            data = self.buffer[index:]
            return_seq = self.next_seq
            # print("data: ", data, " seq: ", return_seq)
            self.next_seq = self.last_seq
            # print("seqs - base: ", self.base_seq, ", next: ", self.next_seq, ", last: ", self.last_seq)
            # print("End get")
            return (data, return_seq)

    def get_for_resend(self, size: int) -> tuple[bytes, int]:
        if (size + self.base_seq) < self.last_seq:
            data = self.buffer[0:0 + size]
            return_seq = self.base_seq
            return (data, return_seq)
        else:
            data = self.buffer[0:]
            return_seq = self.base_seq
            return (data, return_seq)


    def slide(self, sequence: int) -> None:
        index = sequence - self.base_seq
        self.buffer = self.buffer[index:]
        self.base_seq = sequence
        


class TCPReceiveBuffer(object):
    def __init__(self, seq: int):
        self.buffer = {}
        self.base_seq = seq

    def put(self, data: bytes, sequence: int) -> None:
        # print("Start put with data ", data, " at ", sequence)
        at = None
        value = None
        if sequence >= self.base_seq:
            at = sequence
            value = data
        elif sequence < self.base_seq and sequence + len(data) >= self.base_seq:
            acceptable_data = data[self.base_seq - sequence:]
            at = self.base_seq
            value = acceptable_data
        else:    
            # print("Seq to small")
            return

        # print("Seq: ", at, "Data: ", value)
        if at not in self.buffer or len(value) > len(self.buffer[at]):
            self.buffer[at] = value
            # print("added data ", value, " at ", at)

        # print("data:", json.dumps(self.buffer, sort_keys=True))

        keys = list(self.buffer.keys())
        keys.sort()

        # print("seqs: ", json.dumps(keys))

        reaching = self.base_seq
        for seq in keys:
            if reaching > seq:
                # print("duplicate found")
                untrimmed_data = self.buffer.pop(seq)
                trimmed_data = untrimmed_data[reaching - seq:]
                seq = reaching
                self.buffer[seq] = trimmed_data
            seq_len = len(self.buffer[seq])
            reaching = seq + seq_len

        # print("data:", json.dumps(self.buffer, sort_keys=True))
        # print("End put")

    def get(self) -> tuple[bytes, int]:
        data = b''

        keys = list(self.buffer.keys())
        keys.sort()

        # print("seqs: ", json.dumps(keys))

        reaching = self.base_seq
        for seq in keys:
            if reaching > seq:
                # print("dupped data")
                untrimmed_data = self.buffer.pop(seq)
                trimmed_data = untrimmed_data[reaching - seq:]
                seq = reaching
                self.buffer[seq] = trimmed_data
            
            if reaching < seq:
                # print("found hole: previous reaching: ", reaching, " curr seq: ", seq)
                break

            seq_len = len(self.buffer[seq])
            reaching = seq + seq_len
            data += self.buffer.pop(seq)
        
        old_base_seq = self.base_seq
        self.base_seq = reaching
        return (data, old_base_seq)
