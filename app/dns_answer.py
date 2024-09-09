class DNSAnswer:
    def __init__(self, domain: str, ttl: int, ip_address: str):
        self.domain = domain
        self.ttl = ttl
        self.ip_address = ip_address

    def create_answer_section(self, domain_offset: int) -> bytes:
        """Create the answer section for the DNS response using a domain name pointer."""
        # Pointer to domain name (should be the offset from the start of the DNS message)
        name_pointer = b'\xc0' + (domain_offset & 0x3F).to_bytes(1, byteorder='big')
        
        # Type is 1 (A record), encoded as 2 bytes
        rtype = (1).to_bytes(2, byteorder='big')
        
        # Class is 1 (IN class), encoded as 2 bytes
        rclass = (1).to_bytes(2, byteorder='big')
        
        # TTL, encoded as a 4-byte big-endian int
        ttl = (self.ttl).to_bytes(4, byteorder='big')
        
        # Length of the RDATA field (4 bytes for an IPv4 address)
        rdlength = (4).to_bytes(2, byteorder='big')
        
        # IP address in RDATA, encoded as 4 bytes
        rdata = bytes(map(int, self.ip_address.split(".")))
        
        # Combine all parts of the answer section
        return name_pointer + rtype + rclass + ttl + rdlength + rdata
