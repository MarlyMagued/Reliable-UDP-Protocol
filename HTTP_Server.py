from Reliable_UDP import ReliableUDP
import os
import time
from mimetypes import guess_type

# Status Codes
OK_MESSAGE = "200 OK"
NOT_FOUND_MESSAGE = "404 NOT FOUND"

def format_headers(body, content_type="text/plain"):
    headers = [
        f"Content-Length: {len(body.encode())}",
        f"Content-Type: {content_type}",
        "Connection: close",
        f"Date: {time.strftime('%a, %d %b %Y %H:%M:%S GMT', time.gmtime())}"
    ]
    return "\r\n".join(headers)

class HTTPServer:
    def __init__(self, ip, port):
        # Initialize reliable UDP
        self.server = ReliableUDP(ip, port, is_server=True)
        print(f"HTTP Server started at {ip}:{port}")

    def accept_connection(self):
        # Accept a connection from a client
        #print("Waiting for a connection...")
        client_address = self.server.accept()
        #print(f"Connection established with {client_address}")
        return client_address

    def send_data(self, client_address, response):
        # Send response message to the client
        # client_address is a tuple (ip, port)
        # reponse string is converted to bytes before sending
        self.server.send_data(client_address[0], client_address[1], response.encode())

        # Send FIN to indicate end of response
        #self.server.send_packet((client_address[0], client_address[1]), flags=["FIN"])

    def handle_get(self, path):
        # Handle GET request
        # This method checks if the requested file exists and returns its content
        # or a 404 error if it does not exist
        if os.path.exists(path):
            with open(path, 'r') as f:
                content = f.read()

            content_type, _ = guess_type(path) # Guess the content type based on the file extension
            
            # If content type is not found, default to text/plain
            if not content_type:
                content_type = "text/plain"

            # Format headers for the response
            headers = format_headers(content, content_type)
            return f"HTTP/1.0 {OK_MESSAGE}\r\n{headers}\r\n\r\n{content}"
        
        else:
            body = "File Not Found"
            headers = format_headers(body)
            return f"HTTP/1.0 {NOT_FOUND_MESSAGE}\r\n{headers}\r\n\r\n{body}"

    def handle_post(self, path, body):
        # Handle POST request
        # This method creates or updates a file with the content from the request body
        if os.path.exists(path):
            with open(path, 'w') as f:
                f.write(body)
                response_body = "File updated"
                status_message = OK_MESSAGE
        else:
            response_body = "File not found"
            status_message = NOT_FOUND_MESSAGE

        headers = format_headers(response_body)
        return f"HTTP/1.0 {status_message}\r\n{headers}\r\n\r\n{response_body}"

    def handle_request(self, request):
        # Handle incoming HTTP request
        # Split request into lines and parse the request line
        lines = request.split("\r\n")
        if not lines or len(lines[0].split()) != 3: # Check if request line is valid
            return "HTTP/1.0 400 Bad Request\r\n\r\nMalformed request"

        # Extract the first line of the request which contains the method, path, and protocol version
        request_line = lines[0]
        method, path, version = request_line.split()

        # Check HTTP version
        if version != "HTTP/1.0":
            return "HTTP/1.0 505 HTTP Version Not Supported\r\n\r\nOnly HTTP/1.0 supported"

        path = path.lstrip("/")  # Remove leading / so it maps to a file name or resource

        if method == "GET":
            return self.handle_get(path)
        
        elif method == "POST":
            # For POST, we need to find the body of the request
            # The body starts after the headers, which are separated by a blank line
            # Find the index of the first empty line and take everything after that as the body
            if '' in lines:
                body_index = lines.index('') + 1
                body = '\r\n'.join(lines[body_index:])
                #print("body is: ",body)
            else:
                body = ''
            return self.handle_post(path, body)
        
        else:
            return "HTTP/1.0 405 Method Not Allowed\r\n\r\nOnly GET and POST supported"

    def run(self):
        # Main loop to accept and handle requests
        while True:
            client_address = self.accept_connection()

            if not client_address:
                print("No client connected. Server shutting down.")
                self.server.shutdown_socket()
                break

            request = self.server.receive_data()

            if not request:
                print(f"No request received from {client_address}. Closing connection.")
                self.server.close(client_address[0], client_address[1])
                continue
            try:
                # Decode the request bytes to string
                if isinstance(request, bytes):
                    request = request.decode()

            except UnicodeDecodeError:
                print(f"Failed to decode request from {client_address}. Closing connection.")
                self.server.close(client_address[0], client_address[1])
                continue
                    
            #print(f"Request from {client_address}:\n{request}")

            response = self.handle_request(request)
            self.send_data(client_address, response)

            # Close the connection with the client
            #self.server.close(client_address[0], client_address[1])
            self.server.close_connection(client_address[0], client_address[1])
            print(f"Connection with {client_address} closed.\n")

if __name__ == "__main__":
    server = HTTPServer("127.0.0.1", 8080) # loopback address and port
    server.run()