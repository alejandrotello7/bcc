import os
import time

def main():
    # Get the PID of the current process
    pid = os.getpid()
    print(f"My PID: {pid}")

    # Wait for X seconds (replace X with the desired number)
    wait_time = 20
    print(f"Waiting for {wait_time} seconds...")
    time.sleep(wait_time)

    # Open a file called test.txt
    file_path = "/home/atello/bcc/examples/test.txt"
    with open(file_path, 'w') as file:
        fd = file.fileno()
        print("File Descriptor:", fd)
        file.write("Hello, this is a test file!\n")

    print(f"File '{file_path}' created.")

if __name__ == "__main__":
    main()
