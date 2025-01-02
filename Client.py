import socket

#Register new user
def register_user():
    new_username = input("Choose your username: ").strip()
    new_password = input("Choose your password: ").strip()
    #A command 
    command = f"REGISTER|{new_username}|{new_password}"  
    return command

#Existing user login
def login_user():
    username = input("Enter your username: ").strip()
    password = input("Enter your password: ").strip()
    command = f"LOGIN|{username}|{password}"
    return command

#Send Message
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
                print(response)
            except ConnectionRefusedError:
                print("Could not connect to the server. Please make sure the server is running.")
            except Exception as e:
                print(f"Error: {e}")


def client():
    while True:
        choice = input("Enter R to register, L to login, or Q to quit: ").strip().upper()
        if choice == "R":
            command = register_user()
        elif choice == "L":
            username = input("Enter username: ").strip()
            password = input("Enter password: ").strip()
            command = f"LOGIN|{username}|{password}"
        elif choice == "Q":
            print("Goodbye!")
            break
        else:
            print("Invalid input.")
            continue

        #This creates a new socket object using IPv4 (AF_INET) and TCP (SOCK_STREAM) for communication
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            try:
                #connects the client socket to the server running on 127.0.0.1 on port 12345.
                client_socket.connect(('127.0.0.1', 12345))
                #sends the command to the server.
                #The command is a string that encoded into bytes before sending over the socket.
                client_socket.send(command.encode())
                #receives a response from the server
                #It reads up to 1024 bytes from the server and decodes it into a string.
                response = client_socket.recv(1024).decode()
                #checks if the response contains any whitespace characters
                if response.strip():
                     print(response)
                #checks if the response contains the word "successful"
                if "successful" in response.lower():
                    #extracts the username from the command string
                    #The username is the second item in the command after splitting by |. (that's why [1])
                    username = command.split("|")[1]
                    print("You can now type a message or 'logout' to logout.")
                    send_message(username)
            #If any error occurs, sends a generic error message to the client, and exits the loop.
            except ConnectionRefusedError:
                print("Could not connect to the server. Please make sure the server is running.")
            except Exception as e:
                print(f"Error: {e}")

if __name__ == "__main__":
    #Client activation
    client()
 