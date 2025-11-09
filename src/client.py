import socket
import threading
import json
import tkinter as tk
from tkinter import scrolledtext, messagebox, simpledialog
from cryptography.fernet import Fernet
import base64
import hashlib

class ChatClient:
    def __init__(self, host='127.0.0.1', port=5555):
        self.host = host
        self.port = port
        self.client_socket = None
        self.username = None
        self.encryption_enabled = False
        
        # Generate encryption key (shared secret - in production, use proper key exchange)
        # Using a fixed key so both clients can communicate
        self.shared_secret = "my_super_secret_key_12345"
        key = hashlib.sha256(self.shared_secret.encode()).digest()
        self.cipher = Fernet(base64.urlsafe_b64encode(key))
        
        # Create GUI
        self.create_gui()
        
    def create_gui(self):
        """Create the chat GUI"""
        self.window = tk.Tk()
        self.window.title("Chat Client")
        self.window.geometry("500x600")
        
        # Top frame for encryption toggle
        top_frame = tk.Frame(self.window)
        top_frame.pack(pady=10)
        
        self.encryption_var = tk.BooleanVar(value=False)
        self.encryption_checkbox = tk.Checkbutton(
            top_frame,
            text="Enable Encryption (AES)",
            variable=self.encryption_var,
            command=self.toggle_encryption,
            font=("Arial", 12, "bold")
        )
        self.encryption_checkbox.pack()
        
        self.status_label = tk.Label(
            top_frame,
            text="Status: Plain Text Mode",
            fg="red",
            font=("Arial", 10)
        )
        self.status_label.pack()
        
        # Chat history area
        chat_frame = tk.Frame(self.window)
        chat_frame.pack(padx=10, pady=5, fill=tk.BOTH, expand=True)
        
        tk.Label(chat_frame, text="Chat History:", font=("Arial", 10, "bold")).pack(anchor="w")
        
        self.chat_display = scrolledtext.ScrolledText(
            chat_frame,
            wrap=tk.WORD,
            width=60,
            height=20,
            state='disabled',
            font=("Arial", 10)
        )
        self.chat_display.pack(fill=tk.BOTH, expand=True)
        
        # Message input area
        input_frame = tk.Frame(self.window)
        input_frame.pack(padx=10, pady=10, fill=tk.X)
        
        tk.Label(input_frame, text="Your Message:", font=("Arial", 10)).pack(anchor="w")
        
        self.message_input = tk.Text(input_frame, height=3, font=("Arial", 10))
        self.message_input.pack(fill=tk.X, pady=5)
        self.message_input.bind("<Return>", lambda e: self.send_message() if not e.state & 1 else None)
        
        self.send_button = tk.Button(
            input_frame,
            text="Send Message",
            command=self.send_message,
            bg="#4CAF50",
            fg="white",
            font=("Arial", 11, "bold"),
            cursor="hand2"
        )
        self.send_button.pack()
        
        # Handle window close
        self.window.protocol("WM_DELETE_WINDOW", self.on_closing)
        
    def toggle_encryption(self):
        """Toggle encryption mode"""
        self.encryption_enabled = self.encryption_var.get()
        if self.encryption_enabled:
            self.status_label.config(text="Status: Encrypted Mode (AES)", fg="green")
            self.display_message("SYSTEM: Encryption ENABLED - Messages are now encrypted", "system")
        else:
            self.status_label.config(text="Status: Plain Text Mode", fg="red")
            self.display_message("SYSTEM: Encryption DISABLED - Messages sent in plain text", "system")
    
    def connect(self):
        """Connect to the server"""
        try:
            # Get username
            self.username = simpledialog.askstring(
                "Username",
                "Enter your username:",
                parent=self.window
            )
            
            if not self.username:
                messagebox.showerror("Error", "Username is required!")
                return False
            
            self.window.title(f"Chat Client - {self.username}")
            
            # Connect to server
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((self.host, self.port))
            
            # Send username
            self.client_socket.send(self.username.encode('utf-8'))
            
            # Start receiving thread
            receive_thread = threading.Thread(target=self.receive_messages)
            receive_thread.daemon = True
            receive_thread.start()
            
            self.display_message(f"Connected to server as {self.username}", "system")
            return True
            
        except Exception as e:
            messagebox.showerror("Connection Error", f"Could not connect to server: {e}")
            return False
    
    def send_message(self):
        """Send message to server"""
        message = self.message_input.get("1.0", tk.END).strip()
        
        if not message:
            return
        
        try:
            if self.encryption_enabled:
                # Encrypt the message
                encrypted_data = self.cipher.encrypt(message.encode('utf-8'))
                # Send as JSON with metadata
                msg_packet = json.dumps({
                    'type': 'encrypted',
                    'data': base64.b64encode(encrypted_data).decode('utf-8')
                }).encode('utf-8')
                self.client_socket.send(msg_packet)
                self.display_message(f"You (encrypted): {message}", "sent")
            else:
                # Send plain text as JSON
                msg_packet = json.dumps({
                    'type': 'plaintext',
                    'message': message
                }).encode('utf-8')
                self.client_socket.send(msg_packet)
                self.display_message(f"You: {message}", "sent")
            
            # Clear input
            self.message_input.delete("1.0", tk.END)
            
        except Exception as e:
            self.display_message(f"Error sending message: {e}", "error")
    
    def receive_messages(self):
        """Receive messages from server"""
        while True:
            try:
                message = self.client_socket.recv(4096)
                if not message:
                    break
                
                # Try to parse as JSON
                try:
                    msg_data = json.loads(message.decode('utf-8'))
                    
                    if msg_data.get('type') == 'system':
                        self.display_message(msg_data['message'], "system")
                    
                    elif msg_data.get('type') == 'plaintext':
                        username = msg_data.get('username', 'Unknown')
                        msg_text = msg_data.get('message', '')
                        self.display_message(f"{username}: {msg_text}", "received")
                    
                    elif msg_data.get('type') == 'encrypted':
                        username = msg_data.get('username', 'Unknown')
                        try:
                            # Decrypt the message
                            encrypted_data = base64.b64decode(msg_data['data'])
                            decrypted_msg = self.cipher.decrypt(encrypted_data).decode('utf-8')
                            self.display_message(f"{username} (encrypted): {decrypted_msg}", "received")
                        except Exception as e:
                            self.display_message(f"{username}: [Encrypted message - decryption failed]", "error")
                
                except json.JSONDecodeError:
                    self.display_message("Received malformed message", "error")
                    
            except Exception as e:
                self.display_message(f"Connection lost: {e}", "error")
                break
    
    def display_message(self, message, msg_type="normal"):
        """Display message in chat window"""
        self.chat_display.config(state='normal')
        
        if msg_type == "system":
            self.chat_display.insert(tk.END, f"• {message}\n", "system")
            self.chat_display.tag_config("system", foreground="blue", font=("Arial", 9, "italic"))
        elif msg_type == "sent":
            self.chat_display.insert(tk.END, f"{message}\n", "sent")
            self.chat_display.tag_config("sent", foreground="green")
        elif msg_type == "received":
            self.chat_display.insert(tk.END, f"{message}\n", "received")
            self.chat_display.tag_config("received", foreground="black")
        elif msg_type == "error":
            self.chat_display.insert(tk.END, f"⚠ {message}\n", "error")
            self.chat_display.tag_config("error", foreground="red")
        else:
            self.chat_display.insert(tk.END, f"{message}\n")
        
        self.chat_display.see(tk.END)
        self.chat_display.config(state='disabled')
    
    def on_closing(self):
        """Handle window close"""
        if self.client_socket:
            self.client_socket.close()
        self.window.destroy()
    
    def run(self):
        """Start the client"""
        if self.connect():
            self.window.mainloop()

if __name__ == "__main__":
    client = ChatClient()
    client.run()
