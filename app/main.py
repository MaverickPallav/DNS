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

            for domain, qtype, qclass in questions:
                # Forward the query and get the response
                dns_query = DNSHeader(id=query_id, qr=0, opcode=opcode, rd=rd, ancount=0)
                dns_query.set_qdcount(1)
                
                dns_question = DNSQuestion(domain)
                question_section = dns_question.create_question_section()
                
                query_packet = dns_query.encode() + question_section
                response = forward_query(query_packet)
                
                # Create a DNS header for the response
                dns_header = DNSHeader(id=query_id, qr=1, opcode=opcode, rd=rd, ancount=1)
                dns_header.set_qdcount(len(questions))
                dns_header.set_ancount(1)

                # The domain_offset should be based on where the domain starts in the question section
                domain_offset = len(dns_header.encode()) + len(question_section) - (len(dns_question.encode_domain_name()) + 4)

                # Create the answer section using the domain name pointer
                answer_section = DNSAnswer(domain, ttl=300, ip_address="142.250.72.14").create_answer_section(domain_offset)

                response_packet = dns_header.encode() + question_section + answer_section

                # Debugging info
                # print(f"Query ID: {query_id}")
                # print(f"Header length: {len(dns_header.encode())}")
                # print(f"Question length: {len(question_section)}")
                # print(f"Answer length: {len(answer_section)}")
                # print(f"Total response length: {len(response_packet)}")
                # print(f"Response Packet (hex): {response_packet.hex()}")

                # Send the response back to the original requester
                udp_socket.sendto(response_packet, source)

        except Exception as e:
            print(f"Error receiving or forwarding data: {e}")
            break

if __name__ == "__main__":
    main()
