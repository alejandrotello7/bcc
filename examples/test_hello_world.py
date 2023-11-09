# test_open_file.py

file_path = "test.txt"  # Specify the path to the file you want to open

try:
    # Attempt to open the file
    with open(file_path, "r") as file:
        print(f"File '{file_path}' opened successfully.")
except FileNotFoundError:
    print(f"File '{file_path}' not found.")
except Exception as e:
    print(f"Failed to open file '{file_path}': {e}")
