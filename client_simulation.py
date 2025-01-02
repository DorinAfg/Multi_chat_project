import socket
import threading

def send_message_to_server(username, message):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.connect(('127.0.0.1', 12345))
            command = f"MESSAGE|{username}|{message}"
            client_socket.send(command.encode())
            response = client_socket.recv(1024).decode()
            print(f"Response from server for {username}: {response}")
    except Exception as e:
        print(f"Error while connecting: {e}")

def simulate_client(username):
    message = f"Hello from {username}!"
    send_message_to_server(username, message)

def simulate_multiple_clients():
    usernames = [f"user{i}" for i in range(1, 6)]
    threads = []

    for username in usernames:
        thread = threading.Thread(target=simulate_client, args=(username,))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

if __name__ == "__main__":
    simulate_multiple_clients()