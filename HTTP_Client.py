from Reliable_UDP import ReliableUDP

class HTTPClient:
    def __init__(self, server_ip, server_port):
        # Initialize reliable UDP
        # The client is not a server, so we set is_server to False
        self.client = ReliableUDP(server_ip, server_port, is_server=False)
        #self.client.enable_packet_loss()
        #self.client.enable_packet_corruption()
        self.server_ip = server_ip
        self.server_port = server_port
        print(f"HTTP Client initialized for server {server_ip}:{server_port}")

        # Perform handshake to establish connection
        self.client.connect(server_ip, server_port)

    def send_request(self, request_text):
        # Send HTTP request to the server
        self.client.send_data(self.server_ip, self.server_port, request_text.encode())

        # Send FIN to indicate end of request
        #self.client.send_packet((self.server_ip, self.server_port), flags=["FIN"])
    
        #print(f"Sent request:\n{request_text}")

    def receive_response(self):
        # Receive HTTP response from the server
        response_bytes = self.client.receive_data()
        #response_text = response_bytes.decode() if response_bytes else ""
        '''response_text = response_bytes.decode() if isinstance(response_bytes, bytes) else response_bytes


        if not response_text:
            print("No response received.")
            return ""
        
        # Split the response into parts
        lines = response_text.split("\r\n")
        status_line = lines[0]

        # Find the empty line that separates headers from the body
        try:
            empty_line_index = lines.index('')
            headers = lines[1:empty_line_index]
            body = "\r\n".join(lines[empty_line_index + 1:])
        except ValueError:
            # No empty line found; invalid/malformed response
            headers = []
            body = ""

        print("Status:", status_line)
        print("Headers:")
        for header in headers:
            print("  ", header)
        print("Body:\n", body)

        return response_text'''
        return response_bytes

    def close(self):
        self.client.close_connection(self.server_ip, self.server_port)
        print("Connection closed.")

if __name__ == "__main__":
    server_ip = "127.0.0.1" # loopback address 
    server_port = 8080

    client = HTTPClient(server_ip, server_port)
    
    # # Example GET request
    get_request = "GET /test_file.txt HTTP/1.0"
    client.send_request(get_request)
    response = client.receive_response()

    #Example POST request
    # post_request = "POST ./test_file.txt HTTP/1.0\r\n\r\nThis is file content."
    # client.send_request(post_request)
    # response = client.receive_response()

    client.close()

