import socket

def execute_operation(path, syscall_name, value):
    if syscall_name == 'write':
        with open(path, 'w') as file:
            file.write(value)
        print(f"Write operation completed successfully!")

def start_client():
    host = '127.0.0.1'
    port = 12345

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))

    # Receive the server's response as a comma-separated string
    response = client_socket.recv(1024).decode('utf-8')

    # Split the received data into path, syscall name, and value
    path, syscall_name, value = response.split(',')

    # Execute the operation based on the received values
    execute_operation(path, syscall_name, value)

    client_socket.close()

if __name__ == "__main__":
    start_client()
