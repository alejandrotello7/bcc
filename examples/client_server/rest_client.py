import httpx


def execute_code(code: str):
    url = "http://127.0.0.1:8000/execute-code"

    try:
        response = httpx.post(url, json={"code": code})
        response.raise_for_status()
        result = response.json()
        print(result)
    except httpx.HTTPStatusError as e:
        print(f"HTTP error: {e}")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    code_to_execute = """
import os
import time
pid = os.getpid()
print(f"My PID: {pid}")

# Wait for X seconds (replace X with the desired number)
wait_time = 40
print(f"Waiting for {wait_time} seconds...")
time.sleep(wait_time)

# Open a file called test.txt
file_path = "/home/atello/bcc/examples/test.txt"
with open(file_path, 'w') as file:
    file.write("Hello, this is a test file!")
print(f"File '{file_path}' created.")
    """
    execute_code(code_to_execute)
