class DNSQuestion:
    def __init__(self, domain: str):
        self.domain = domain

    def encode_domain_name(self) -> bytes:
        """Encode a domain name into the DNS format."""
        labels = self.domain.split(".")
        encoded_name = b""
        for label in labels:
            encoded_name += bytes([len(label)]) + label.encode("utf-8")
        encoded_name += b"\x00"  # Null byte to terminate the domain name
        return encoded_name

    def create_question_section(self) -> bytes:
        """Creates the question section for the DNS query."""
        # Encode the domain name using the class method
        name = self.encode_domain_name()
        
        # Type is 1 (A record), encoded as a 2-byte big-endian int
        qtype = (1).to_bytes(2, byteorder='big')
        
        # Class is 1 (IN class), encoded as a 2-byte big-endian int
        qclass = (1).to_bytes(2, byteorder='big')
        
        # Combine all parts to form the question section
        return name + qtype + qclass