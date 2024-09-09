import socket
from dns_header import DNSHeader
from dns_utils import parse_domain_name, parse_dns_query
from dns_question import DNSQuestion
from dns_answer import DNSAnswer

def main():
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))
    
    while True:
        try:
            buf, source = udp_socket.recvfrom(512)

            # Parse the DNS query to get relevant information
            query_id, opcode, rd, qdcount = parse_dns_query(buf)
            
            # Create the DNS header with the appropriate values
            dns_header = DNSHeader(id=query_id, qr=1, opcode=opcode, rd=rd, ancount=1)

            # Parse the domain name from the DNS query
            domain, offset = parse_domain_name(buf, 12)  # Domain starts after the DNS header
            
            # Create the DNS question section
            dns_question = DNSQuestion(domain)
            question = dns_question.create_question_section()

            # Create the DNS answer section
            dns_answer = DNSAnswer(domain, 60, "8.8.8.8")
            answer = dns_answer.create_answer_section()

            dns_header.set_qdcount(1)
            dns_header.set_ancount(1)  

            # Combine header, question, and answer sections into the response
            response = dns_header.encode() + question + answer

            # Send the DNS response
            udp_socket.sendto(response, source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            break

if __name__ == "__main__":
    main()