from datetime import datetime
import json
import threading
import socket
from cryptography.fernet import Fernet
import bcrypt

# Hash passwords securely
def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(stored_password, provided_password):
    return bcrypt.checkpw(provided_password.encode(), stored_password.encode())

# Generate a key for encryption
def generate_key():
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(key)

# Load the key from the secret.key file
def load_key():
    try:
        with open("secret.key", "rb") as key_file:
            return key_file.read()
    except FileNotFoundError:
        generate_key()
        print("The key file 'secret.key' has been generated.")
        return load_key()

# Encryption function
def encrypt_message(message):
    key = load_key()
    fernet = Fernet(key)
    encrypted_message = fernet.encrypt(message.encode())
    return encrypted_message

# Decryption function
def decrypt_message(encrypted_message):
    key = load_key()
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_message).decode()

# If there is an error, the code will jump to the except block
try:
    # Opens the file users.json in read mode ("r")
    with open("users.json", "r") as file:
        users_list = json.load(file)
except FileNotFoundError:
    users_list = {}

active_clients = []

# Broadcast message function
def broadcast_message(message, sender_socket):
    for client in active_clients:
        if client != sender_socket:
            try:
                client.send(message.encode())
            except (socket.error, OSError) as e:
                print(f"Failed to send message to a client: {e}")
                try:
                    active_clients.remove(client)
                    client.close()
                except ValueError:
                    pass

# Handle client connection
def client_connection(client_socket):
    global users_list, active_clients
    active_clients.append(client_socket)

    try:
        while True:
            try:
                data = client_socket.recv(1024).decode()
                if not data:  # If no data, client disconnected
                    print("The client disconnected")
                    break
            except socket.error as e:
                print(f"Error receiving message: {e}")
                break

            command, *args = data.split("|")
            if command == "REGISTER":
                if len(args) != 2 or not args[0] or not args[1]:
                    client_socket.send("Invalid command format or empty username/password.".encode())
                    continue

                username, password = args
                if username in users_list:
                    client_socket.send("Username already taken!".encode())
                else:
                    users_list[username] = {"password": hash_password(password), "messages": []}
                    with open("users.json", "w") as users_file:
                        json.dump(users_list, users_file, indent=4)
                    client_socket.send("Registration successful!".encode())



            elif command == "LOGIN":
                if len(args) != 2 or not args[0] or not args[1]:
                    client_socket.send("Invalid command format or empty username/password.".encode())
                    continue

                username, password = args
                if username in users_list:
                    if verify_password(users_list[username]["password"], password):
                        history = users_list[username]["messages"]
                        history_messages = "\n".join([f"{msg['time']} - {username}: {decrypt_message(msg['message'])}" for msg in history])
                        client_socket.send(f"Welcome back, {username}!\nYour message history:\n{history_messages}".encode())
                    else:
                        client_socket.send("Incorrect password.".encode())
                else:
                    client_socket.send("Username does not exist.".encode())

            elif command == "MESSAGE":
                if len(args) != 2:
                    client_socket.send("Invalid command format.".encode())
                    continue

                username, message = args
                timestamp = datetime.now().strftime("%H:%M:%S")
                if username in users_list:
                    encrypted_message = encrypt_message(message)
                    users_list[username]["messages"].append({"time": timestamp, "message": encrypted_message.decode()})
                    with open("users.json", "w") as users_file:
                        json.dump(users_list, users_file, indent=4)

                    broadcast_message(f"{timestamp} - {username}: {message}", client_socket)

                else:
                    client_socket.send("User not recognized. Please login.".encode())

            else:
                client_socket.send("Invalid command.".encode())

    except Exception as e:
        print(f"Error in client connection: {e}")

    finally:
        try:
            active_clients.remove(client_socket)
        except ValueError:
            pass
        try:
            client_socket.close()
        except Exception as e:
            print(f"Error during socket cleanup: {e}")

# Start the server
def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.settimeout(60)  # Set timeout of 60 seconds for each connection
    server.bind(("0.0.0.0", 12345))
    server.listen(10)
    print("The server is ready and waiting for connections.")
    while True:
        try:
            client_socket, addr = server.accept()
            print("The connection was established with", addr)
            client_handler = threading.Thread(target=client_connection, args=(client_socket,))
            client_handler.start()
        except socket.timeout:
            print("Server timed out while waiting for a new connection.")

if __name__ == "__main__":
    start_server()
