import json
import os
import socket
import threading
import struct

# Server configuration
HOST = '127.0.0.1'
PORT = 12345
file_descriptor = None
file_object = None

def handle_client(client_socket):
    data = client_socket.recv(1024)
    event_data = json.loads(data)
    response_int = 0
    if event_data["operation"] == 1:
        filename = event_data["filename"]
        print(f"Received message from BPF program: {filename}")
        global file_descriptor
        global file_object
        # Close the previously opened file
        if file_object:
            file_object.close()

        # Open the new file
        file_object = open(filename, 'w')
        response_int = file_object.fileno()
        print(response_int)

    if event_data["operation"] == 2:
        file_descriptor = event_data["file_descriptor"]
        print(file_descriptor)
        if file_descriptor and file_object:
            data = event_data["data"] + 'atest'
            os.write(file_descriptor, data.encode('utf-8'))

    response_data = struct.pack('I', response_int)
    client_socket.sendall(response_data)

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen(5)
    print(f"Server listening on {HOST}:{PORT}")

    while True:
        client_socket, addr = server_socket.accept()
        client_handler = threading.Thread(target=handle_client, args=(client_socket,))
        client_handler.start()

if __name__ == "__main__":
    start_server()
