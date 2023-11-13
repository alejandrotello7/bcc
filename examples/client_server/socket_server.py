import socket
import threading

# Server configuration
HOST = '127.0.0.1'
PORT = 12345

def handle_client(client_socket):
    data = client_socket.recv(1024)
    print(f"Received message from BPF program: {data.decode('utf-8')}")
    client_socket.close()

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
