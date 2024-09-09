def parse_dns_query(buf):
    """
    Extract the required fields from the DNS query packet.

    Args:
        buf (bytes): The DNS query packet.

    Returns:
        tuple: A tuple containing (query_id, opcode, rd, qdcount).
    """
    query_id = (buf[0] << 8) | buf[1]
    flags = buf[2:4]
    opcode = (flags[0] >> 3) & 0x0F
    rd = flags[0] & 0x01
    qdcount = (buf[4] << 8) | buf[5]
    
    return query_id, opcode, rd, qdcount

def parse_domain_name(buf: bytes, offset: int) -> str:
    """Parse the domain name from the DNS query starting at the given offset."""
    domain_parts = []

    while True:
        length = buf[offset]

        if length == 0:
            break  # Domain name is terminated by a zero byte
        
        offset += 1
        domain_parts.append(buf[offset:offset + length].decode("utf-8"))
        offset += length

    return ".".join(domain_parts), offset + 1

def parse_questions(buf, offset):
    """Parse DNS question section from buffer starting at offset."""
    questions = []

    while offset < len(buf):
        domain, new_offset = parse_domain_name(buf, offset)
        qtype = int.from_bytes(buf[new_offset:new_offset+2], 'big')
        qclass = int.from_bytes(buf[new_offset+2:new_offset+4], 'big')
        questions.append((domain, qtype, qclass))
        offset = new_offset + 4

        if offset >= len(buf) or buf[offset] == 0:
            break
        
    return questions, offset
