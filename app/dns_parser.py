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