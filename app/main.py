import socket
from dns_header import DNSHeader
from dns_parser import parse_domain_name
from dns_question import DNSQuestion

def main():
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))
    
    while True:
        try:
            buf, source = udp_socket.recvfrom(512)

            dns_header = DNSHeader(1234, 1)

            domain, offset = parse_domain_name(buf, 12)  # The domain starts after the DNS header
            
            dns_question = DNSQuestion(domain)
            question = dns_question.create_question_section()

            response = dns_header.encode() + question

            udp_socket.sendto(response, source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            break

if __name__ == "__main__":
    main()
