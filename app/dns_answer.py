class DNSAnswer:
    def __init__(self, domain: str, ttl: int, ip_address: str):
        self.domain = domain
        self.ttl = ttl
        self.ip_address = ip_address

    def encode_domain_name(self) -> bytes:
        """Encode the domain name into DNS label format."""
        labels = self.domain.split(".")
        encoded_name = b""
        for label in labels:
            encoded_name += bytes([len(label)]) + label.encode("utf-8")
        encoded_name += b"\x00"  # Null byte to terminate the domain name
        return encoded_name

    def create_answer_section(self) -> bytes:
        """Create the answer section for the DNS response."""
        name = self.encode_domain_name()
        
        # Type is 1 (A record), encoded as 2 bytes
        rtype = (1).to_bytes(2, byteorder='big')
        
        # Class is 1 (IN class), encoded as 2 bytes
        rclass = (1).to_bytes(2, byteorder='big')
        
        # TTL, encoded as a 4-byte big-endian int
        ttl = (self.ttl).to_bytes(4, byteorder='big')
        
        # Length of the RDATA field (4 bytes for an IPv4 address)
        rdlength = (4).to_bytes(2, byteorder='big')
        
        # IP address in RDATA, encoded as 4-byte big-endian int
        rdata = bytes(map(int, self.ip_address.split(".")))
        
        # Combine all parts of the answer section
        return name + rtype + rclass + ttl + rdlength + rdata