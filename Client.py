import socket
from cryptography.fernet import Fernet

#Load the key from the secret.key file
def load_key():
    try:
        with open("secret.key", "rb") as key_file:
            return key_file.read()
    except FileNotFoundError:
        print("Error: The key file 'secret.key' is missing.")
        exit()

#Decryption function
def decrypt_message(encrypted_message):
    key = load_key()
    fernet = Fernet(key)
    try:
        decrypted_message = fernet.decrypt(encrypted_message).decode()
        return decrypted_message
    except Exception:
        return None  # Return None if decryption fails

#Register new user
def register_user():
    new_username = input("Choose your username: ").strip()
    new_password = input("Choose your password: ").strip()
    command = f"REGISTER|{new_username}|{new_password}"
    return command

#Existing user login
def login_user():
    username = input("Enter your username: ").strip()
    password = input("Enter your password: ").strip()
    command = f"LOGIN|{username}|{password}"
    return command

#Send message
def send_message(username):
    while True:
        message = input("Type a message or 'logout' to logout: ").strip()
        if message.lower() == 'logout':
            print("Logging out...")
            break
        command = f"MESSAGE|{username}|{message}"
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            try:
                client_socket.connect(('127.0.0.1', 12345))
                client_socket.send(command.encode())
                response = client_socket.recv(1024).decode()

                # Handle encrypted responses
                decrypted_response = decrypt_message(response.encode())
                if decrypted_response:
                    print(f"Decrypted response: {decrypted_response}")
                else:
                    print(f" {response}")
            except ConnectionRefusedError:
                print("Could not connect to the server. Please make sure the server is running.")
            except Exception as e:
                print(f"Error: {e}")

#Main client function
def client():
    while True:
        choice = input("Enter R to register, L to login, or Q to quit: ").strip().upper()
        if choice == "R":
            command = register_user()
        elif choice == "L":
            command = login_user()
        elif choice == "Q":
            print("Goodbye!")
            break
        else:
            print("Invalid input.")
            continue

        #Create a socket and connect to the server
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            try:
                client_socket.connect(('127.0.0.1', 12345))
                client_socket.send(command.encode())
                response = client_socket.recv(1024).decode()

                #Display the server's response
                if response.strip():
                    print(response)

                #Check for successful login
                if "successful" in response.lower() or "welcome" in response.lower():
                    username = command.split("|")[1]
                    print("You can now type a message or 'logout' to logout.")
                    send_message(username)
            except ConnectionRefusedError:
                print("Could not connect to the server. Please make sure the server is running.")
            except Exception as e:
                print(f"Error: {e}")

if __name__ == "__main__":
    client()
