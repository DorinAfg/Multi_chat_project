from datetime import datetime
import json
import threading
import socket
#Provided cryptography
from cryptography.fernet import Fernet
#Provided hash for passwords
import bcrypt

#Hash passwords securely
def hash_password(password):
    #hashpw - Hashes the given password.
    #gensalt - Generates a unique "salt" value to make the hashing process secure and prevent hash collisions.
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

#Verify password against hashed version
def verify_password(stored_password, provided_password):
    #checkpw - Generates a unique "salt" value to make the hashing process secure and prevent hash collisions.
    return bcrypt.checkpw(provided_password.encode(), stored_password.encode())

#Generate a key for encryption
def generate_key():
    #Fernet is a Symmetric Encryption, generate create a key
    key = Fernet.generate_key()
    #write the key in binary to the file secret.key
    with open("secret.key", "wb") as key_file:
        key_file.write(key)

#Load the key from the secret.key file
def load_key():
    try:
        with open("secret.key", "rb") as key_file:
            return key_file.read()
    except FileNotFoundError:
        #Generate the key if it doesn't exist
        generate_key()
        print("The key file 'secret.key' has been generated.")
        #Load the key after generating it
        return load_key()

#Encryption function
def encrypt_message(message):
    key = load_key()
    fernet = Fernet(key)
    encrypted_message = fernet.encrypt(message.encode())
    return encrypted_message

#Decryption function
def decrypt_message(encrypted_message):
    key = load_key()
    fernet = Fernet(key)
    decrypted_message = fernet.decrypt(encrypted_message).decode()
    return decrypted_message

#If there is an error, the code will jump to the except block
try:
    #opens the file users.json in read mode ("r")
    #with make sure the file is automatically closed after it’s read, even if something goes wrong
    with open("users.json", "r") as file:
        #Read the file and converts it into a Python data structure (dict)
        users_list = json.load(file)
except FileNotFoundError:
    #Runs this block if the file doesn’t exist
    users_list = {}


#Function handles communication
def client_connection(client_socket):
    #Declares users_list as a global so changes to it will affect the entire program.
    global users_list
    try:
        while True:
            #Receive data from the client:
            #Receives up to 1024 bytes of data from the client and decodes it to a string.
            data = client_socket.recv(1024).decode()
            #If no data is received, it means the client disconnected.
            if not data:
                #Prints a message and exits the loop.
                print("The client disconnected")
                break
            #Splits the received data into a command and any additional arguments (args).
            command, *args = data.split("|")
            if command == "REGISTER":
                #Checks if the client provided two arguments and Check if username or password are empty
                if len(args) != 2 or not args[0] or not args[1]:
                    client_socket.send("Invalid command format or empty username/password.".encode())
                    continue

                username, password = args
                #Checks if the username already exists.
                if username in users_list:
                    client_socket.send("Username already taken!".encode())
                else:
                    #If it doesn’t, adds the user to users_list
                    users_list[username] = {"password": hash_password(password), "messages": []}
                    #and saves the updated list to users.json
                    with open("users.json", "w") as users_file:
                        json.dump(users_list, users_file, indent=4)
                    client_socket.send("Registration successful!".encode())

            elif command == "LOGIN":
                #Checks if the client provided two arguments and Check if username or password are empty
                if len(args) != 2 or not args[0] or not args[1]:
                    client_socket.send("Invalid command format or empty username/password.".encode())
                    continue

                username, password = args
                #Verifies the username and password
                if username in users_list:
                    if verify_password(users_list[username]["password"], password):
                        client_socket.send(f"Welcome back, {username}!".encode())
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
                    #Adds the message with a timestamp to the user’s message history.
                    users_list[username]["messages"].append({"time": timestamp, "message": encrypted_message.decode()})
                    #Saves the updated users_list to users.json.
                    with open("users.json", "w") as users_file:
                        json.dump(users_list, users_file, indent=4)
                        #Sends the plain message back to the client for readability
                    client_socket.send(f"{timestamp} - {username}: {message}".encode())
                else:
                    client_socket.send("User not recognized. Please login.".encode())
            else:
                client_socket.send("Invalid command.".encode())
    #If any error occurs, sends a generic error message to the client, and exits the loop.
    except Exception as e:
        print(f"Error in client connection: {e}")

    #Ensures the client’s socket is closed when the connection ends.
    finally:
        client_socket.close()

#Start the server
def start_server():
    #creates a new socket object used to communicate over the network
    #AF_INET - IPv4 address
    #SOCK_STREAM -TCP protocol
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #The server listen on all available network interfaces and port 12345
    server.bind(("0.0.0.0", 12345))
    #This tells the server allowing a maximum of 10 clients
    server.listen(10)
    print("The server is ready and waiting for connections.")
    #This starts an infinite loop.
    #The server will keep running and accepting connections until it's stopped.
    while True:
        #Accepts an incoming connection from a client.
        client_socket, addr = server.accept()
        print("The connection was established with", addr)
        #This creates a new thread that will run the client_connection function
        #to handle communication with the connected client
        client_handler = threading.Thread(target=client_connection, args=(client_socket,))
        #This starts the thread
        #client_connection function will run in the background and handle the communication with the client.
        client_handler.start()

if __name__ == "__main__":
    start_server()