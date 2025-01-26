import socket
import threading
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
        #Return None if decryption fails
        return None
#Register new user
def register_user():
    new_username = input("Choose your username: ").strip()
    new_password = input("Choose your password: ").strip()
    command = f"REGISTER|{new_username}|{new_password}"
    return command

# Existing user login
def login_user():
    username = input("Enter your username: ").strip()
    password = input("Enter your password: ").strip()
    command = f"LOGIN|{username}|{password}"
    return command

# Function to listen for messages from the server in real-time
def listen_to_server(client_socket, stop_event):
    while not stop_event.is_set():
        try:
            response = client_socket.recv(1024).decode()
            if response:
                print(f"\n{response}")
            else:
                break
        except Exception as e:
            print(f"Error receiving message: {e}")
            break

#Main client function
def client():
    stop_event = threading.Event()
    while True:
        choice = input("Enter R to register, L to login, or Q to quit: ").strip().upper()
        if choice == "R":
            command = register_user()
        elif choice == "L":
            command = login_user()
        elif choice == "Q":
            print("Goodbye!")
            stop_event.set()
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

                    #Start a thread to listen for incoming messages
                    listener_thread = threading.Thread(
                        target=listen_to_server,
                        args=(client_socket, stop_event),
                        daemon=True
                    )
                    listener_thread.start()

                    #Handle sending messages
                    while True:
                        message = input()
                        if message.lower() == "logout":
                            print("Logging out...")
                            stop_event.set()  # Stop the listener thread
                            break
                        command = f"MESSAGE|{username}|{message}"
                        client_socket.send(command.encode())
            except ConnectionRefusedError:
                print("Could not connect to the server. Please make sure the server is running.")
            except Exception as e:
                print(f"Error: {e}")

if __name__ == "__main__":
    client()
