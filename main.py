import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import secrets
import string
import json
import os
import base64
import pyperclip
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet, InvalidToken

class PasswordManager:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Password Manager")
        self.root.geometry("400x450")
        self.root.resizable(True, True)
        self.root.minsize(400, 450)
        
        # Set application style
        self.style = ttk.Style()
        self.style.configure('TFrame', background='#f0f0f0')
        self.style.configure('TButton', font=('Arial', 10))
        self.style.configure('TCheckbutton', font=('Arial', 10))
        self.style.configure('TLabel', font=('Arial', 10))
        
        # Initialize passkey
        self.passkey = None
        self.passwords_file = "passwords.enc"
        
        # Check if this is first launch
        self.first_launch = not os.path.exists(self.passwords_file)
        
        # Setup UI after handling passkey
        if self.first_launch:
            self.setup_first_launch()
        else:
            self.prompt_for_passkey()
    
    def setup_first_launch(self):
        """Set up initial passkey for first-time users"""
        self.root.withdraw()  # Hide main window
        
        passkey = simpledialog.askstring("First Launch", 
                                         "Welcome to Secure Password Manager!\n\nPlease set your master passkey:", 
                                         show='*')
        
        if not passkey:
            messagebox.showerror("Error", "A passkey is required to use this application.")
            self.root.destroy()
            return
            
        confirm_passkey = simpledialog.askstring("Confirm Passkey", 
                                                "Please confirm your master passkey:", 
                                                show='*')
                                                
        if passkey != confirm_passkey:
            messagebox.showerror("Error", "Passkeys do not match. Please restart the application.")
            self.root.destroy()
            return
            
        self.passkey = passkey
        # Create empty password file
        self.save_passwords({})
        self.root.deiconify()  # Show main window
        self.setup_ui()
        
    def prompt_for_passkey(self):
        """Prompt for passkey on subsequent launches"""
        self.root.withdraw()  # Hide main window
        
        passkey = simpledialog.askstring("Enter Passkey", 
                                         "Please enter your master passkey:", 
                                         show='*')
        
        if not passkey:
            messagebox.showerror("Error", "A passkey is required to use this application.")
            self.root.destroy()
            return
            
        self.passkey = passkey
        
        # Verify passkey by trying to load passwords
        try:
            self.load_passwords()
            self.root.deiconify()  # Show main window
            self.setup_ui()
        except InvalidToken:
            messagebox.showerror("Error", "Invalid passkey. Please restart the application.")
            self.root.destroy()
            
    def setup_ui(self):
        """Set up the main user interface"""
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create tabs
        self.generate_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.generate_tab, text="Generate Password")
        
        # Set up generate tab
        self.setup_generate_tab()
        
    def setup_generate_tab(self):
        """Set up the password generation tab"""
        frame = ttk.Frame(self.generate_tab, padding="10")
        frame.pack(fill=tk.BOTH, expand=True)
        
        # Password length
        ttk.Label(frame, text="Password Length:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.length_var = tk.IntVar(value=16)
        length_entry = ttk.Entry(frame, textvariable=self.length_var, width=5)
        length_entry.grid(row=0, column=1, sticky=tk.W, pady=5)
        
        # Character types
        ttk.Label(frame, text="Include:").grid(row=1, column=0, sticky=tk.W, pady=5)
        
        options_frame = ttk.Frame(frame)
        options_frame.grid(row=1, column=1, sticky=tk.W, pady=5)
        
        self.lowercase_var = tk.BooleanVar(value=True)
        self.uppercase_var = tk.BooleanVar(value=True)
        self.digits_var = tk.BooleanVar(value=True)
        self.special_var = tk.BooleanVar(value=True)
        
        ttk.Checkbutton(options_frame, text="Lowercase (a-z)", variable=self.lowercase_var).pack(anchor=tk.W)
        ttk.Checkbutton(options_frame, text="Uppercase (A-Z)", variable=self.uppercase_var).pack(anchor=tk.W)
        ttk.Checkbutton(options_frame, text="Digits (0-9)", variable=self.digits_var).pack(anchor=tk.W)
        ttk.Checkbutton(options_frame, text="Special (!@#$)", variable=self.special_var).pack(anchor=tk.W)
        
        # Generate button
        generate_btn = ttk.Button(frame, text="Generate Password", command=self.generate_password)
        generate_btn.grid(row=2, column=0, columnspan=2, pady=10)
        
        # Result area
        result_frame = ttk.LabelFrame(frame, text="Generated Password")
        result_frame.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=10)
        
        self.password_var = tk.StringVar()
        password_entry = ttk.Entry(result_frame, textvariable=self.password_var, width=40)
        password_entry.pack(side=tk.LEFT, padx=5, pady=10, expand=True, fill=tk.X)
        
        copy_btn = ttk.Button(result_frame, text="Copy", command=self.copy_password)
        copy_btn.pack(side=tk.RIGHT, padx=5, pady=10)
        
        # Save password section
        save_frame = ttk.LabelFrame(frame, text="Save Password")
        save_frame.grid(row=4, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=10)
        
        ttk.Label(save_frame, text="Label:").pack(side=tk.LEFT, padx=5, pady=10)
        self.label_var = tk.StringVar()
        label_entry = ttk.Entry(save_frame, textvariable=self.label_var, width=20)
        label_entry.pack(side=tk.LEFT, padx=5, pady=10, expand=True, fill=tk.X)
        
        save_btn = ttk.Button(save_frame, text="Save", command=self.save_password)
        save_btn.pack(side=tk.RIGHT, padx=5, pady=10)
        
        # View saved passwords button
        view_btn = ttk.Button(frame, text="View Saved Passwords", command=self.view_passwords)
        view_btn.grid(row=5, column=0, columnspan=2, pady=10)
        
    def generate_password(self):
        """Generate a secure random password"""
        try:
            length = self.length_var.get()
            
            if length <= 0:
                messagebox.showerror("Error", "Password length must be positive")
                return
                
            # Check that at least one character type is selected
            if not (self.lowercase_var.get() or self.uppercase_var.get() or 
                    self.digits_var.get() or self.special_var.get()):
                messagebox.showerror("Error", "Please select at least one character type")
                return
                
            # Build character set
            chars = ""
            if self.lowercase_var.get():
                chars += string.ascii_lowercase
            if self.uppercase_var.get():
                chars += string.ascii_uppercase
            if self.digits_var.get():
                chars += string.digits
            if self.special_var.get():
                chars += string.punctuation
                
            # Generate password using the secrets module
            password = ''.join(secrets.choice(chars) for _ in range(length))
            self.password_var.set(password)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate password: {str(e)}")
    
    def copy_password(self):
        """Copy the generated password to clipboard"""
        password = self.password_var.get()
        if password:
            pyperclip.copy(password)
            messagebox.showinfo("Success", "Password copied to clipboard")
        else:
            messagebox.showinfo("Info", "No password to copy")
    
    def save_password(self):
        """Save the generated password with a label"""
        password = self.password_var.get()
        label = self.label_var.get()
        
        if not password:
            messagebox.showerror("Error", "No password to save")
            return
            
        if not label:
            messagebox.showerror("Error", "Please provide a label for this password")
            return
            
        try:
            # Load existing passwords
            passwords = self.load_passwords()
            
            # Check if label already exists
            if label in passwords:
                overwrite = messagebox.askyesno("Confirm", 
                                              f"A password for '{label}' already exists. Overwrite?")
                if not overwrite:
                    return
            
            # Add new password
            passwords[label] = password
            
            # Save updated passwords
            self.save_passwords(passwords)
            
            messagebox.showinfo("Success", f"Password for '{label}' saved successfully")
            
            # Clear the label field
            self.label_var.set("")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save password: {str(e)}")
    
    def view_passwords(self):
        """Open a window to view saved passwords"""
        try:
            passwords = self.load_passwords()
            
            if not passwords:
                messagebox.showinfo("Info", "No saved passwords found")
                return
                
            # Create view window
            view_window = tk.Toplevel(self.root)
            view_window.title("Saved Passwords")
            view_window.geometry("500x400")
            view_window.resizable(True, True)
            view_window.minsize(500, 400)
            
            # Create treeview
            columns = ('label', 'password')
            tree = ttk.Treeview(view_window, columns=columns, show='headings')
            tree.heading('label', text='Label')
            tree.heading('password', text='Password')
            tree.column('label', width=200)
            tree.column('password', width=250)
            
            # Add scrollbar
            scrollbar = ttk.Scrollbar(view_window, orient=tk.VERTICAL, command=tree.yview)
            tree.configure(yscroll=scrollbar.set)
            
            # Pack widgets
            scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
            tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            
            # Populate treeview
            for label, password in passwords.items():
                tree.insert('', tk.END, values=(label, password))
            
            # Add copy button
            def copy_selected():
                selection = tree.selection()
                if selection:
                    item = tree.item(selection[0])
                    password = item['values'][1]
                    pyperclip.copy(password)
                    messagebox.showinfo("Success", "Password copied to clipboard")
                else:
                    messagebox.showinfo("Info", "No password selected")
            
            copy_btn = ttk.Button(view_window, text="Copy Selected Password", command=copy_selected)
            copy_btn.pack(side=tk.BOTTOM, pady=10)
            
            # Add delete button
            def delete_selected():
                selection = tree.selection()
                if selection:
                    item = tree.item(selection[0])
                    label = item['values'][0]
                    
                    confirm = messagebox.askyesno("Confirm", f"Delete password for '{label}'?")
                    if confirm:
                        passwords = self.load_passwords()
                        if label in passwords:
                            del passwords[label]
                            self.save_passwords(passwords)
                            tree.delete(selection)
                            messagebox.showinfo("Success", f"Password for '{label}' deleted")
                else:
                    messagebox.showinfo("Info", "No password selected")
            
            delete_btn = ttk.Button(view_window, text="Delete Selected Password", command=delete_selected)
            delete_btn.pack(side=tk.BOTTOM, pady=5)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to view passwords: {str(e)}")
    
    def get_encryption_key(self, passkey):
        """Derive encryption key from passkey using PBKDF2"""
        # Use a fixed salt for simplicity (in production, would use a random salt stored with the file)
        salt = b'static_salt_for_demo_purposes'
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        
        key = base64.urlsafe_b64encode(kdf.derive(passkey.encode()))
        return key
    
    def save_passwords(self, passwords):
        """Save passwords dictionary to encrypted file"""
        try:
            # Convert passwords dict to JSON
            data = json.dumps(passwords).encode()
            
            # Get encryption key
            key = self.get_encryption_key(self.passkey)
            
            # Encrypt data
            fernet = Fernet(key)
            encrypted_data = fernet.encrypt(data)
            
            # Write to file
            with open(self.passwords_file, 'wb') as f:
                f.write(encrypted_data)
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save passwords file: {str(e)}")
            raise
    
    def load_passwords(self):
        """Load passwords dictionary from encrypted file"""
        try:
            # Read encrypted data
            with open(self.passwords_file, 'rb') as f:
                encrypted_data = f.read()
            
            # Get encryption key
            key = self.get_encryption_key(self.passkey)
            
            # Decrypt data
            fernet = Fernet(key)
            data = fernet.decrypt(encrypted_data)
            
            # Parse JSON
            passwords = json.loads(data.decode())
            return passwords
            
        except FileNotFoundError:
            # Return empty dict if file doesn't exist
            return {}
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load passwords file: {str(e)}")
            raise

# Main application entry point
if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManager(root)
    root.mainloop()
