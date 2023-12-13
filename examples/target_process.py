import time
import os

def main():
    print("Target process (PID=%d) started" % os.getpid())
    time.sleep(2)  # Allow time for ptrace to attach
    # Attempt to open a file (you can modify this path)
    fd = os.open("/home/atello/bcc/examples/test.txt", os.O_RDONLY)
    # with open(file_path, 'w') as file:
    #     fd = file.fileno()
    #     time.sleep(5)
    #     # print("File Descriptor:", fd)
    #     file.write("Hello(3), this is a test file!\n")

    print("Opened file with FD:", fd)
    # Infinite loop to keep the process alive
    while True:
        pass
if __name__ == "__main__":
        main()