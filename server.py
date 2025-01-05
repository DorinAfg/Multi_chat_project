from datetime import datetime
import json
import threading
import socket
#Provided hash for passwords
import bcrypt

#Hash password before saving
def hash_password(password):
    #
    #hashpw - function that makes the password hashed
    #gensalt -
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

#Verify password against hashed version
def verify_password(stored_password, provided_password):
    #checkpw -
    return bcrypt.checkpw(provided_password.encode(), stored_password.encode())

#If there is an error, the code will jump to the except block
try:
#opens the file users.json in read mode ("r")
#with make sure the file is automatically closed after it’s read, even if something goes wrong
    with open("users.json", "r") as file:
        #Read the file and converts it into a Python data structure (dict)
        users_list = json.load(file)
#Runs this block if the file doesn’t exist
except FileNotFoundError:
    users_list = {}
 #Function handles communication.
def client_connection(client_socket):
    #Declares users_list as a global so changes to it will affect the entire program.
    global users_list
    try:
        #open users.json in read mode.
        try:
            with open("users.json", "r") as users_file:
                #Loads the file into the users_list dict.
                users_list = json.load(users_file)
        #If the file doesn’t exist, users_list will be an empty dictionary.
        except FileNotFoundError:
            users_list = {}
        #Keeps the connection open to handle multiple client requests until the client disconnects.
        while True:
            try:
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
                    #Verifies the username and password.
                    if username in users_list:
                        if verify_password(users_list[username]["password"], password):
                            client_socket.send(f"Welcome back, {username}!".encode())
                        else:
                            client_socket.send("Incorrect password.".encode())
                    else:
                        client_socket.send("Username does not exist.".encode())

                elif command == "MESSAGE":
                    #
                    if len(args) != 2:
                        client_socket.send("Invalid command format.".encode())
                        continue

                    username, message = args
                    timestamp = datetime.now().strftime("%H:%M:%S")
                    if username in users_list:
                        #Adds the message with a timestamp to the user’s message history.
                        users_list[username]["messages"].append({"time": timestamp, "message": message})
                        #Saves the updated users_list to users.json.
                        with open("users.json", "w") as users_file:
                            json.dump(users_list, users_file, indent=4)
                        #Sends the formatted message back to the client.
                        client_socket.send(f"{timestamp} - {username}: {message}".encode())
                    else:
                        #If the username isn’t recognized, sends an error.
                        client_socket.send("User not recognized. Please login.".encode())
                #If the command isn't register, login or message sends an error message.
                else:
                    client_socket.send("Invalid command.".encode())
            # If any error occurs, sends a generic error message to the client, and exits the loop.
            except Exception as e:
                print(f"Error while processing client message: {e}")
                client_socket.send("An unexpected error occurred.".encode())
                break
    #If any error occurs, sends a generic error message to the client, and exits the loop.
    except Exception as e:
        print(f"Error in client connection: {e}")
    #Ensures the client’s socket is closed when the connection ends.
    finally:
        client_socket.close()

#Function that start the server
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
    #Server activation
    start_server()
