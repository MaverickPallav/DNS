import socket
from dns_header import DNSHeader
from dns_utils import parse_dns_query, parse_questions, forward_query
from dns_question import DNSQuestion
from dns_answer import DNSAnswer

def main():
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))
    
    while True:
        try:
            buf, source = udp_socket.recvfrom(512)

            # Parse the DNS query
            query_id, opcode, rd, qdcount = parse_dns_query(buf)
            
            # Parse the DNS question section
            questions, offset = parse_questions(buf, 12)
            
            responses = []
            
            for domain, qtype, qclass in questions:
                # Forward the query and get the response
                dns_query = DNSHeader(id=query_id, qr=0, opcode=opcode, rd=rd, ancount=0)
                dns_query.set_qdcount(1)
                
                dns_question = DNSQuestion(domain)
                question_section = dns_question.create_question_section()
                
                query_packet = dns_query.encode() + question_section
                response = forward_query(query_packet)
                
                # Extract the answer section from the response
                answer_section = response[12:]  # Skipping header part

                # Create a DNS header for the response
                dns_header = DNSHeader(id=query_id, qr=1, opcode=opcode, rd=rd, ancount=1)
                dns_header.set_qdcount(len(questions))
                dns_header.set_ancount(1)
                
                responses.append(dns_header.encode() + question_section + answer_section)
            
            # Send all responses back to the original requester
            for response in responses:
                udp_socket.sendto(response, source)

        except Exception as e:
            print(f"Error receiving or forwarding data: {e}")
            break

if __name__ == "__main__":
    main()