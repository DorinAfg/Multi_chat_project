import socket
import threading

#send a message from the user to the server
def send_message_to_server(username, message):
    #If there is an error, the code will jump to the except block
    try:
        #This creates a new socket object using IPv4 (AF_INET) and TCP (SOCK_STREAM) for communication
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            # connects the client socket to the server running on 127.0.0.1 on port 12345.
            client_socket.connect(('127.0.0.1', 12345))
            #the command from the user
            command = f"MESSAGE|{username}|{message}"
            # sends the command to the server.
            #The command is a string that encoded into bytes before sending over the socket.
            client_socket.send(command.encode())
            #receives a response from the server
            #It reads up to 1024 bytes from the server and decodes it into a string.
            response = client_socket.recv(1024).decode()
            #print the response from the server
            print(f"Response from server for {username}: {response}")
    #If any error occurs, sends a generic error message to the client, and exits the loop.
    except Exception as e:
        print(f"Error while connecting: {e}")

#Defines a function to send a message to the server for a specific username
def client_message(username):
    message = f"Hello from {username}!"
    send_message_to_server(username, message)

#a function to make multiple clients connecting to the server.
def multiple_clients():
    #5 users
    usernames = [f"user{i}" for i in range(1, 6)]
    #an empty list to store threads.
    threads = []
    #Loops through each username.
    for username in usernames:
        #Creates a new thread to send a message for the current username.
        thread = threading.Thread(target= client_message, args=(username,))
        #Adds the thread to the list of threads.
        threads.append(thread)
        #Starts the thread
        thread.start()

    #Loops through the list of threads.
    for thread in threads:
        #Waits for each thread to finish its task.
        thread.join()


#Ensures this code runs only when the file is executed directly.
if __name__ == "__main__":
    multiple_clients()