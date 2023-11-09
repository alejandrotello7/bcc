import socket

def start_server():
    host = '127.0.0.1'
    port = 12345

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)

    print(f"Server listening on {host}:{port}")

    while True:
        client_socket, addr = server_socket.accept()
        print(f"Connection from {addr}")

        # Define path, syscall name, and value
        path = "/home/atello/bcc/examples/test.txt"
        syscall_name = "write"
        value = "alejandro"

        # Compose the response as a comma-separated string
        response = f"{path},{syscall_name},{value}"

        client_socket.send(response.encode('utf-8'))

        client_socket.close()

if __name__ == "__main__":
    start_server()
