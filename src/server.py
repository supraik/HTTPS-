import socket
import threading
import json

class ChatServer:
    def __init__(self, host='127.0.0.1', port=5555):
        self.host = host
        self.port = port
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.clients = []
        self.usernames = {}
        
    def broadcast(self, message, sender_socket=None):
        """Send message to all connected clients except sender"""
        for client in self.clients:
            if client != sender_socket:
                try:
                    client.send(message)
                except:
                    self.remove_client(client)
    
    def handle_client(self, client_socket, address):
        """Handle individual client connection"""
        print(f"[NEW CONNECTION] {address} connected.")
        
        try:
            # Receive username
            username = client_socket.recv(1024).decode('utf-8')
            self.usernames[client_socket] = username
            
            # Notify all clients about new user
            join_msg = json.dumps({
                'type': 'system',
                'message': f'{username} joined the chat!'
            }).encode('utf-8')
            self.broadcast(join_msg, client_socket)
            
            # Send welcome message to new client
            welcome_msg = json.dumps({
                'type': 'system',
                'message': 'Welcome to the chat! Encryption toggle is available in your client.'
            }).encode('utf-8')
            client_socket.send(welcome_msg)
            
            # Main message loop
            while True:
                message = client_socket.recv(4096)
                if not message:
                    break
                
                # Parse message to add username
                try:
                    msg_data = json.loads(message.decode('utf-8'))
                    msg_data['username'] = username
                    formatted_message = json.dumps(msg_data).encode('utf-8')
                    self.broadcast(formatted_message, client_socket)
                except json.JSONDecodeError:
                    # If not JSON, treat as raw encrypted data
                    self.broadcast(message, client_socket)
                
        except Exception as e:
            print(f"[ERROR] {address}: {e}")
        finally:
            self.remove_client(client_socket)
    
    def remove_client(self, client_socket):
        """Remove client and notify others"""
        if client_socket in self.clients:
            username = self.usernames.get(client_socket, "Unknown")
            self.clients.remove(client_socket)
            
            if client_socket in self.usernames:
                del self.usernames[client_socket]
            
            # Notify others
            leave_msg = json.dumps({
                'type': 'system',
                'message': f'{username} left the chat.'
            }).encode('utf-8')
            self.broadcast(leave_msg)
            
            client_socket.close()
            print(f"[DISCONNECTED] {username} disconnected.")
    
    def start(self):
        """Start the server"""
        self.server.bind((self.host, self.port))
        self.server.listen()
        print(f"[LISTENING] Server is listening on {self.host}:{self.port}")
        print("[INFO] Waiting for connections...")
        
        try:
            while True:
                client_socket, address = self.server.accept()
                self.clients.append(client_socket)
                
                thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, address)
                )
                thread.daemon = True
                thread.start()
                print(f"[ACTIVE CONNECTIONS] {len(self.clients)}")
        except KeyboardInterrupt:
            print("\n[SHUTDOWN] Server shutting down...")
            self.server.close()

if __name__ == "__main__":
    server = ChatServer()
    server.start()