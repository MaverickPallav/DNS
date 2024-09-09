import socket
from dns_header import DNSHeader
from dns_utils import parse_domain_name, parse_dns_query, parse_questions
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
            dns_header = DNSHeader(id=query_id, qr=1, opcode=opcode, rd=rd, qdcount=qdcount, ancount=qdcount)

            # Parse the DNS question section
            questions, offset = parse_questions(buf, 12)  # Domain starts after the DNS header
            
            question_section = b''
            answer_section = b''

            # Build question and answer sections
            for domain, qtype, qclass in questions:
                # Create the question section
                dns_question = DNSQuestion(domain)
                question_section += dns_question.create_question_section()
                
                # Create the answer section
                dns_answer = DNSAnswer(domain, 60, "8.8.8.8")
                answer_section += dns_answer.create_answer_section()

            # Set QDCOUNT and ANCOUNT in the header
            dns_header.set_qdcount(len(questions))
            dns_header.set_ancount(len(questions))
            
            # Combine header, question, and answer sections into the response
            response = dns_header.encode() + question_section + answer_section

            # Send the DNS response
            udp_socket.sendto(response, source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            break

if __name__ == "__main__":
    main()