class DNSHeader:
    def __init__(self, id: int = 0, qr: int = 0):
        self.header = bytearray(12)
        self.set_id(id)
        self.set_qr(qr)

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
    
    def encode(self):
        return self.header