"""
This module provides reliability features similar to TCP while using UDP sockets:
- Three-way handshake connection establishment
- Stop-and-wait protocol for reliable data transfer
- Checksum for error detection
- Packet retransmission with timeouts
- Sequence and acknowledgment numbers
- TCP-like flags (SYN, ACK, FIN)
"""
import socket
import hashlib
import time
import struct
import random

def create_packet(self, flags, seq_num, ack_num, data=b''): 
    pass

# Constants
HEADER_FORMAT = '!BII'  # flags (1 byte), seq_num (4), ack_num (4) = 9 bytes
CHECKSUM_SIZE = 32  # MD5 hexdigest = 32 characters
HEADER_SIZE = struct.calcsize(HEADER_FORMAT) + CHECKSUM_SIZE  # header (9) + checksum
MAX_PACKET_SIZE = 1024
MAX_DATA_SIZE = MAX_PACKET_SIZE - HEADER_SIZE
TIMEOUT = 5  # seconds

# Flags
ACK_FLAG = 0b00010000
SYN_FLAG = 0b00000010
FIN_FLAG = 0b00000001
DATA_FLAG = 0b00100000 # flag to indicate the packet contains data

# Flag mapping for flexible flag usage
FLAG_MAP = {
    "ACK": ACK_FLAG,
    "SYN": SYN_FLAG,
    "FIN": FIN_FLAG,
    "DATA": DATA_FLAG,
}

class ReliableUDP:

    def __init__(self, ip, udp_port_number, is_server=False): # is server if false , acts as a client 
        
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # create the UDP socket
        self.sock.settimeout(TIMEOUT) # sets a timeout for receiving data on the socket, socket.timeout exception if no data recieved 
        self.address = (ip, udp_port_number) # stores the IP and port as a tuple
        self.is_server = is_server

        if is_server:
            self.sock.bind(self.address) # if server, binds the socket to the specified IP and port, the server will listen for incoming UDP packets on that address

        # Initialize sequence numbers
        self.seq_num = 0 # initialize sequence number for the sender side, toggles between 0 and 1  to identify whether a packet is new or duplicated 
        self.expected_seq = 0 # initializes the expected sequence number for the receiver side
        
        #ACK packet of the last received in-order packet, we send it when we receive out of order packet
        self.last_ack_packet = create_packet(self,["ACK"],0,0,)
        # Initialize flags for packet loss and corruption simulation
        # These flags are used for testing purposes to simulate network conditions
        self.simulate_loss = False
        self.loss_rate = 0.0
        self.simulate_corruption = False
        self.corruption_rate = 0.0


    def checksum(self, data):
        # Calculate MD5 checksum of the data
        return hashlib.md5(data).hexdigest()
    

    def verify_checksum(self, packet):
        # Extract header and data without the checksum
        header_size = struct.calcsize(HEADER_FORMAT)
        header = packet[:header_size]

        # Calculate checksum for the header and data
        received_checksum = packet[header_size:header_size + CHECKSUM_SIZE].decode()
        data = packet[header_size + CHECKSUM_SIZE:]

        calculated_checksum = self.checksum(header + data) # calculate checksum for verification

        # Compare the calculated checksum with the received checksum
        return calculated_checksum == received_checksum
    

    def enable_packet_loss(self, enable=True): # Enable/disable packet loss simulation
        self.simulate_loss = enable
        #self.loss_rate = rate


    def enable_packet_corruption(self, enable=True): # Enable/disable packet corruption simulation
        self.simulate_corruption = enable
        #self.corruption_rate = rate


    def create_packet(self, flags, seq_num, ack_num, data=b''): 
        """
        Create a packet with header, checksum, and data.

        Args:
            flags: Control flags (SYN, ACK, FIN, DATA)
            seq_num: Sequence number
            ack_num: Acknowledgment number
            data: Payload data (bytes)
            
        Returns:
            Complete packet as bytes
        """
        # if flags is a list,set, or tupe, convert to bitwise OR of flag values
        if isinstance(flags, (list, set, tuple)): 
            flags_value = 0
            for f in flags:
                flags_value |= FLAG_MAP.get(f.upper(), 0)
        else:
            flags_value = flags  # allow direct int value

        # header is packed using struct with the specified format
        # flags (1 byte), seq_num (4 bytes), ack_num (4 bytes)
        header = struct.pack(HEADER_FORMAT, flags_value, seq_num, ack_num)

        # checksum is calculated over the header and data 
        checksum = self.checksum(header + data).encode()

        return header + checksum + data
    

    def send_packet(self, dest_address, flags, data=b''):
        """
        Send a packet and wait for ACK, retransmitting indefinitely on timeout
        
        Args:
            dest_ip: Destination IP address
            dest_port: Destination port
            flags: Packet flags
            data: Payload data
            
        Returns:
            True if ACK received, False otherwise
        """
        #packet = self.create_packet(flags, self.seq_num, 0, data)
        packet = self.create_packet(flags, self.seq_num, self.seq_num +len(data), data)
        header_size = struct.calcsize(HEADER_FORMAT)

        #initial_seq = self.seq_num
        data_len = len(data) if len(data) > 0 else 1
        self.expected_seq = self.seq_num + data_len

        #data_len = len(data) # length of the data to be sent

        while True: # keep trying until ACK received

            # Simulate packet loss 
            if self.simulate_loss: 
                print("\nSimulated packet loss\n")
                self.simulate_loss = False #return flag to false to avoid infinite loop of packet loss
            else:

                # Simulate packet corruption
                if self.simulate_corruption: 
                    corrupted_data = bytearray(packet)
                    corrupted_data[-1] ^= 0xFF # flip the last byte to simulate corruption
                    self.sock.sendto(bytes(corrupted_data), dest_address)
                    print("\nSent CORRUPTED packet\n")
                    self.simulate_corruption = False #return flag to false to avoid infinite loop of packet corruption
                else:

                    # Original packet is sent normally
                    self.sock.sendto(packet, dest_address)
                    print(f"Sent packet (seq = {self.seq_num}, ack = {self.seq_num + data_len})")
                    print("Data content (decoded):\n", data.decode('utf-8', errors='replace'))
                    print("\n")

            try: # wait for ACK
                response, _ = self.sock.recvfrom(MAX_PACKET_SIZE)

                # Check if the received packet is corrupted
                if not self.verify_checksum(response):
                    print("Checksum mismatch, discarding ACK")
                    continue

                # Extract flags and sequence number from the packet
                r_flags, r_seq, r_ack = struct.unpack(HEADER_FORMAT, response[:header_size])

                # Check if the ACK is valid
                # ACK_FLAG is set and the ACK number matches the expected sequence number
                expected_ack = self.seq_num + data_len
                if (r_flags & ACK_FLAG) and r_seq == expected_ack:
                    print(f"Received ACK (seq = {r_seq})")
                    self.seq_num = r_ack
                    return True
                else:
                    print(f"Bad ACK: got {r_seq} expected {expected_ack}")
                
            except socket.timeout:
                print("Timeout, retransmitting\n")


    def send_data(self, dest_ip, dest_port, data):

        address = (dest_ip, dest_port)
        total_sent = 0 # represents the total number of bytes successfully transmitted 

        # Divide data into chunks that fit in one packet
        chunks = [data[i:i + MAX_DATA_SIZE] for i in range(0, len(data), MAX_DATA_SIZE)]

        print(f"Sending {len(chunks)} packet(s)")
        for i, chunk in enumerate(chunks):# send each chunk using Stop-and-Wait

            print(f"Chunk {i+1} size: {len(chunk)}")

            if len(chunk) == 0:
                print(f"Skipping empty chunk {i+1}")
                continue

            if self.send_packet(address, ["DATA"], chunk):
                total_sent += len(chunk) 
                print(f"Chunk {i+1} sent\n")

            else:
                print("Failed to send chunk\n")
                break

        return total_sent
    
    # receiving function for both client and server
    def receive_data(self):

        received_data = bytearray()
        header_size = struct.calcsize(HEADER_FORMAT)
        
        # The receiver keeps listening for incoming packets and processes them
        while True:
            try:

                packet, sender_addr = self.sock.recvfrom(MAX_PACKET_SIZE)

                # Check if the received packet is corrupted
                if not self.verify_checksum(packet):
                    print("Received corrupted packet, discarding")
                    continue

                # Extract flags, sequence number, and acknowledgment number from the packet
                flags, seq_num, ack_num = struct.unpack(HEADER_FORMAT, packet[:header_size])
                data = packet[HEADER_SIZE:]

                # Check if the packet is a FIN packet
                # If the FIN flag is set, send an ACK and close the connection
                if flags & FIN_FLAG:
                    print(f"Received FIN (seq = {seq_num}, ack = {ack_num})")
                    if seq_num == self.expected_seq:
                        self.expected_seq += 1
                        ack_packet = self.create_packet(["ACK"], 0, self.expected_seq)
                        self.sock.sendto(ack_packet, sender_addr)
                        self.seq_num = ack_num 

                    break

                # If the sequence number matches the expected sequence number, process the data
                if seq_num == self.expected_seq:
                    received_data.extend(data)
                    print(f"Received packet (seq = {seq_num}, ack = {ack_num})")
                    print("Size of received data: ",len(data))
                    print("Received data chunk (decoded):\n", data.decode('utf-8', errors='replace'))
                    print("\n")

                    #calculate the number of bytes received to update the expected sequence number
                    increment = len(data) if len(data) > 0 else 1
                    self.expected_seq += increment 

                    #send an ACK for the received packet
                    #ack_packet = self.create_packet(["ACK"], seq_num+len(data), self.expected_seq)
                    ack_packet = self.create_packet(["ACK"], seq_num+len(data), ack_num)
                    self.last_ack_packet = ack_packet
                    self.sock.sendto(ack_packet, sender_addr)
                    print(f"Sent ACK (seq = {seq_num+len(data)})\n")
                    self.seq_num = seq_num + increment

                    break

                # If the sequence number is out of order or a duplicate, send an ACK for the expected sequence number
                else: 
                    print(f"Out-of-order packet: got {seq_num} expected {self.expected_seq}")
                    #ack_packet = self.create_packet(["ACK"], self.seq_num, self.expected_seq)
                    self.sock.sendto(self.last_ack_packet, sender_addr)


            except socket.timeout:
                print("Waiting for packet, continuing to listen")
                continue

        return received_data.decode(errors='ignore')
    
    
    # 3-WAY HANDSHAKE
    # SYN -> SYN-ACK -> ACK
    # Client's connection function
    def connect(self, server_ip, server_port):

        header_size = struct.calcsize(HEADER_FORMAT)
        server_addr = (server_ip, server_port)

        initial_seq = self.seq_num # store the initial sequence number
        syn_packet = self.create_packet(["SYN"], self.seq_num, 0)
        self.sock.sendto(syn_packet, server_addr)
        print(f"Sent SYN (seq = {initial_seq}, ack = 0)")

        while True: # waiting to receive a packet from the server
            try:
                response, _ = self.sock.recvfrom(MAX_PACKET_SIZE)
                flags, r_seq, r_ack = struct.unpack(HEADER_FORMAT, response[:header_size])

                if not self.verify_checksum(response): # verify the checksum of the received packet
                    print("Checksum mismatch, discarding packet")
                    continue

                if (flags & SYN_FLAG) and (flags & ACK_FLAG):
                    if r_ack != self.seq_num + 1: # verify the SYN-ACK packet and check if the ACK number is correct
                        print(f"Bad ACK num: got {r_ack} expected {initial_seq+1}")
                        continue
                    
                    # Update sequence number and send final ACK
                    self.seq_num = initial_seq + 1
                    self.expected_seq = r_seq + 1
                    print(f"Received SYN-ACK (seq = {r_seq}, ack = {r_ack}) ")
                    ack_packet = self.create_packet(["ACK"], self.seq_num, r_seq + 1)
                    self.sock.sendto(ack_packet, server_addr)
                    print("Connection established\n")
                    return
                
            except socket.timeout:
                print("Timeout during handshake, resending SYN")
                self.sock.sendto(syn_packet, server_addr)


    # Server's connection function, Waiting for client to connect
    def accept(self, total_timeout=60):

        header_size = struct.calcsize(HEADER_FORMAT)
        start_time = time.time()

        while True: # server keeps listening for incoming connections
            print("Waiting for incoming connection...")

            try:
                syn_packet, client_addr = self.sock.recvfrom(MAX_PACKET_SIZE)

                if not self.verify_checksum(syn_packet): # verify the checksum of the received packet
                    print("Checksum mismatch, discarding packet")
                    continue

                # Extract flags and sequence number from the packet
                flags, client_seq, client_ack = struct.unpack(HEADER_FORMAT, syn_packet[:header_size])
               
                if flags & SYN_FLAG:
                    self.expected_seq = client_seq + 1 # set the expected sequence number to the received sequence number + 1
                    #self.seq_num += 1  # increment server sequence number before sending SYN-ACK
                    print(f"Received SYN (seq = {client_seq}, ack = {client_ack})")
                    syn_ack = self.create_packet(["SYN", "ACK"], self.seq_num, self.expected_seq)
                    self.sock.sendto(syn_ack, client_addr)
                    print(f"Sent SYN-ACK (seq={self.seq_num}, ack={self.expected_seq})")

                    # Wait for final ACK from the client
                    response, _ = self.sock.recvfrom(MAX_PACKET_SIZE) 

                    if not self.verify_checksum(response): # verify the checksum of the received packet
                        print("Checksum mismatch, discarding packet")
                        continue

                    r_flags, r_seq, r_ack = struct.unpack(HEADER_FORMAT, response[:header_size])
                    if (r_flags & ACK_FLAG) and r_ack == self.seq_num + 1:
                        print(f"Received ACK (seq = {r_seq}, ack = {r_ack}) ")
                        print("Connection established with client\n")
                        self.seq_num += 1
                        self.expected_seq = r_seq
                        return client_addr
                    else:
                        print(f"Bad ACK num: got {r_seq} expected {self.seq_num + 1}")
                        
            except socket.timeout:
                if time.time() - start_time > total_timeout:
                    return None
                # else keep waiting
                continue


    # Connection termination
    # FIN -> ACK -> FIN-ACK -> ACK
    # This method is for client or per-connection cleanup
    def close_connection(self, dest_ip, dest_port):
        header_size = struct.calcsize(HEADER_FORMAT)
        dest_addr = (dest_ip, dest_port)
        fin_seq = self.seq_num
        fin_packet = self.create_packet(["FIN"], self.seq_num, 0)

        print(f"Sending FIN (seq={fin_seq})...")

        while True:
            try:
                self.sock.sendto(fin_packet, dest_addr)
                response, addr = self.sock.recvfrom(MAX_PACKET_SIZE)

                if not self.verify_checksum(response):
                    print("Checksum mismatch, discarding packet")
                    continue

                flags, seq, ack = struct.unpack(HEADER_FORMAT, response[:header_size])

                if (flags & ACK_FLAG) and ack == fin_seq + 1:
                    print("Received ACK for FIN")
                    # Wait for server's FIN now
                    while True:
                        try:
                            response, addr = self.sock.recvfrom(MAX_PACKET_SIZE)
                            if not self.verify_checksum(response):
                                print("Checksum mismatch on server FIN, discarding")
                                continue

                            flags, seq, ack = struct.unpack(HEADER_FORMAT, response[:header_size])

                            if flags & FIN_FLAG:
                                print(f"Received FIN from server (seq={seq})")
                                ack_packet = self.create_packet(["ACK"], self.seq_num, seq + 1)
                                self.sock.sendto(ack_packet, dest_addr)
                                print("Sent ACK for server FIN. Connection closed cleanly.")
                                return
                        except socket.timeout:
                            print("Timeout waiting for server FIN, retrying...")
                            continue

            except socket.timeout:
                print("Timeout waiting for ACK, resending FIN")
            except ConnectionResetError:
                print("Remote host closed the connection. Closing locally.")
            break


    # This is only for when you're completely done (server shutdown)
    def shutdown_socket(self):
        #print("Shutting down socket.")
        self.sock.close()


