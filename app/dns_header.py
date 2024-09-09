class DNSHeader:
    def __init__(self, id: int = 0, qr: int = 0, opcode: int = 0, rd: int = 0, qdcount: int = 1, ancount: int = 0):
        self.header = bytearray(12)
        self.set_id(id)
        self.set_flags(qr, opcode, rd)
        self.set_qdcount(qdcount)
        self.set_ancount(ancount)

    def set_id(self, value: int):
        if not (0 <= value <= 65535):
            raise ValueError("Transaction ID must be between 0 and 65535")
        
        self.header[0] = (value >> 8) & 0xFF
        self.header[1] = value & 0xFF

    def set_flags(self, qr: int, opcode: int, rd: int):
        # QR: 1 bit
        # OPCODE: 4 bits
        # AA: 1 bit (Authoritative Answer)
        # TC: 1 bit (Truncation)
        # RD: 1 bit (Recursion Desired)
        # RA: 1 bit (Recursion Available)
        # Z: 3 bits (Reserved, set to 0)
        # RCODE: 4 bits (Response Code)

        self.header[2] = (qr << 7) | (opcode << 3) | (rd)
        self.header[3] = 0x00  # RA=0, AA=0, TC=0, Z=0, RCODE=0

    def set_qdcount(self, count: int):
        self.header[4] = (count >> 8) & 0xFF
        self.header[5] = count & 0xFF

    def set_ancount(self, count: int):
        self.header[6] = (count >> 8) & 0xFF
        self.header[7] = count & 0xFF

    def encode(self):
        return self.header
