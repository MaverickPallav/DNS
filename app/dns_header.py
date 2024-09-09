class DNSHeader:
    def __init__(self, id: int = 0, qr: int = 0):
        self.header = bytearray(12)
        self.set_id(id)
        self.set_qr(qr)
        self.set_qdcount(1)

    def set_id(self, value: int):
        if not (0 <= value <= 65535):
            raise ValueError("Transaction ID must be between 0 and 65535")
        
        self.header[0] = (value >> 8) & 0xFF
        self.header[1] = value & 0xFF

    def set_qr(self, value: int):
        if value:
            self.header[2] |= 0x80
        else:
            self.header[2] &= 0x7F
    
    def set_qdcount(self, count: int):
        """Set QDCOUNT, the number of questions in the DNS query."""
        self.header[4] = (count >> 8) & 0xFF
        self.header[5] = count & 0xFF
    
    def set_ancount(self, count: int):
        """Set the Answer Count (ANCOUNT) in the DNS Header."""
        self.header[6] = (count >> 8) & 0xFF
        self.header[7] = count & 0xFF
    
    def encode(self):
        return self.header