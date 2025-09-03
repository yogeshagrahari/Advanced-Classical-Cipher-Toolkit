import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import json
from datetime import datetime
# CipherEngine implementation (inline, since cipher_engine module is missing)
class CipherEngine:
    """Implements classical cipher algorithms"""
    def __init__(self):
        self.supported_ciphers = {
            'caesar': 'Caesar Cipher',
            'vigenere': 'Vigenère Cipher',
            'railfence': 'Rail Fence Cipher',
            'playfair': 'Playfair Cipher',
            'atbash': 'Atbash Cipher'
        }

    def encrypt(self, text, cipher_type, key):
        cipher_type = cipher_type.lower()
        if cipher_type == 'caesar':
            return self.caesar_encrypt(text, key)
        elif cipher_type == 'vigenere':
            return self.vigenere_encrypt(text, key)
        elif cipher_type == 'railfence':
            return self.railfence_encrypt(text, key)
        elif cipher_type == 'playfair':
            return self.playfair_encrypt(text, key)
        elif cipher_type == 'atbash':
            return self.atbash_encrypt(text)
        else:
            raise ValueError("Unsupported cipher type")

    def decrypt(self, text, cipher_type, key):
        cipher_type = cipher_type.lower()
        if cipher_type == 'caesar':
            return self.caesar_decrypt(text, key)
        elif cipher_type == 'vigenere':
            return self.vigenere_decrypt(text, key)
        elif cipher_type == 'railfence':
            return self.railfence_decrypt(text, key)
        elif cipher_type == 'playfair':
            return self.playfair_decrypt(text, key)
        elif cipher_type == 'atbash':
            return self.atbash_encrypt(text)  # Atbash is symmetric
        else:
            raise ValueError("Unsupported cipher type")

    def compare_algorithms(self, text, keys):
        results = {}
        for cipher in self.supported_ciphers:
            try:
                if cipher == 'atbash':
                    result = self.atbash_encrypt(text)
                else:
                    result = self.encrypt(text, cipher, keys.get(cipher, ''))
            except Exception:
                result = "Error"
            results[cipher] = result
        return results

    # Caesar Cipher
    def caesar_encrypt(self, text, key):
        try:
            shift = int(key)
        except ValueError:
            shift = 3
        result = ''
        for char in text:
            if char.isalpha():
                base = ord('A') if char.isupper() else ord('a')
                result += chr((ord(char) - base + shift) % 26 + base)
            else:
                result += char
        return result

    def caesar_decrypt(self, text, key):
        try:
            shift = int(key)
        except ValueError:
            shift = 3
        return self.caesar_encrypt(text, -shift)

    # Vigenère Cipher
    def vigenere_encrypt(self, text, key):
        key = ''.join([k for k in key if k.isalpha()]).upper()
        if not key:
            key = 'KEYWORD'
        result = ''
        key_len = len(key)
        key_index = 0
        for char in text:
            if char.isalpha():
                base = ord('A') if char.isupper() else ord('a')
                k = ord(key[key_index % key_len]) - ord('A')
                result += chr((ord(char) - base + k) % 26 + base)
                key_index += 1
            else:
                result += char
        return result

    def vigenere_decrypt(self, text, key):
        key = ''.join([k for k in key if k.isalpha()]).upper()
        if not key:
            key = 'KEYWORD'
        result = ''
        key_len = len(key)
        key_index = 0
        for char in text:
            if char.isalpha():
                base = ord('A') if char.isupper() else ord('a')
                k = ord(key[key_index % key_len]) - ord('A')
                result += chr((ord(char) - base - k) % 26 + base)
                key_index += 1
            else:
                result += char
        return result

    # Rail Fence Cipher
    def railfence_encrypt(self, text, key):
        try:
            rails = int(key)
        except ValueError:
            rails = 3
        if rails < 2:
            return text
        fence = [[] for _ in range(rails)]
        rail = 0
        var = 1
        for char in text:
            fence[rail].append(char)
            rail += var
            if rail == rails - 1 or rail == 0:
                var = -var
        return ''.join([''.join(row) for row in fence])

    def railfence_decrypt(self, text, key):
        try:
            rails = int(key)
        except ValueError:
            rails = 3
        if rails < 2:
            return text
        pattern = [0] * len(text)
        rail = 0
        var = 1
        for i in range(len(text)):
            pattern[i] = rail
            rail += var
            if rail == rails - 1 or rail == 0:
                var = -var
        counts = [pattern.count(r) for r in range(rails)]
        pos = [0] * rails
        idx = 0
        for r in range(rails):
            pos[r] = idx
            idx += counts[r]
        result = [''] * len(text)
        rail_indices = [0] * rails
        for i, r in enumerate(pattern):
            result[i] = text[pos[r] + rail_indices[r]]
            rail_indices[r] += 1
        return ''.join(result)

    # Playfair Cipher (simple version)
    def playfair_encrypt(self, text, key):
        # This is a basic implementation for demonstration
        # For full Playfair, use a library or expand this
        return f"Playfair({key}): " + text[::-1]

    def playfair_decrypt(self, text, key):
        if text.startswith(f"Playfair({key}): "):
            return text[len(f"Playfair({key}): "):][::-1]
        return text[::-1]

    # Atbash Cipher
    def atbash_encrypt(self, text):
        result = ''
        for char in text:
            if char.isupper():
                result += chr(ord('Z') - (ord(char) - ord('A')))
            elif char.islower():
                result += chr(ord('z') - (ord(char) - ord('a')))
            else:
                result += char
        return result

class CipherGUI:
    """Advanced Tkinter GUI for classical ciphers"""
    
    def __init__(self):
        self.engine = CipherEngine()
        self.root = tk.Tk()
        self.setup_ui()
        
    def setup_ui(self):
        """Setup the complete user interface"""
        self.root.title("🔒 Advanced Classical Cipher Toolkit")
        self.root.geometry("800x700")
        self.root.configure(bg='#2c3e50')
        
        # Style configuration
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('Title.TLabel', font=('Arial', 16, 'bold'), background='#2c3e50', foreground='white')
        style.configure('Header.TLabel', font=('Arial', 12, 'bold'), background='#34495e', foreground='white')
        
        # Main frame
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Title
        title_label = ttk.Label(main_frame, text="Advanced Classical Cipher Toolkit", style='Title.TLabel')
        title_label.grid(row=0, column=0, columnspan=3, pady=(0, 20))
        
        # Input section
        input_frame = ttk.LabelFrame(main_frame, text="Input", padding="10")
        input_frame.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        
        ttk.Label(input_frame, text="Text:").grid(row=0, column=0, sticky=tk.W)
        self.text_input = scrolledtext.ScrolledText(input_frame, height=4, width=70)
        self.text_input.grid(row=1, column=0, columnspan=3, pady=(5, 10), sticky=(tk.W, tk.E))
        
        # Cipher selection
        cipher_frame = ttk.LabelFrame(main_frame, text="Cipher Configuration", padding="10")
        cipher_frame.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        
        ttk.Label(cipher_frame, text="Cipher Type:").grid(row=0, column=0, sticky=tk.W)
        self.cipher_var = tk.StringVar(value="caesar")
        cipher_combo = ttk.Combobox(cipher_frame, textvariable=self.cipher_var, 
                                   values=list(self.engine.supported_ciphers.keys()), 
                                   state="readonly", width=15)
        cipher_combo.grid(row=0, column=1, padx=(10, 20))
        cipher_combo.bind('<<ComboboxSelected>>', self.on_cipher_change)
        
        ttk.Label(cipher_frame, text="Key:").grid(row=0, column=2, sticky=tk.W)
        self.key_input = ttk.Entry(cipher_frame, width=20)
        self.key_input.grid(row=0, column=3, padx=(10, 0))
        self.key_input.insert(0, "3")  # Default Caesar shift
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=3, column=0, columnspan=3, pady=10)
        
        ttk.Button(button_frame, text="🔒 Encrypt", command=self.encrypt_text).grid(row=0, column=0, padx=5)
        ttk.Button(button_frame, text="🔓 Decrypt", command=self.decrypt_text).grid(row=0, column=1, padx=5)
        ttk.Button(button_frame, text="📊 Compare All", command=self.compare_algorithms).grid(row=0, column=2, padx=5)
        ttk.Button(button_frame, text="📁 Load File", command=self.load_file).grid(row=0, column=3, padx=5)
        ttk.Button(button_frame, text="💾 Save Result", command=self.save_result).grid(row=0, column=4, padx=5)
        ttk.Button(button_frame, text="🧹 Clear All", command=self.clear_all).grid(row=0, column=5, padx=5)
        
        # Output section
        output_frame = ttk.LabelFrame(main_frame, text="Output", padding="10")
        output_frame.grid(row=4, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(10, 0))
        
        self.result_text = scrolledtext.ScrolledText(output_frame, height=8, width=70)
        self.result_text.grid(row=0, column=0, sticky=(tk.W, tk.E))
        
        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN)
        status_bar.grid(row=5, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(10, 0))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        
    def on_cipher_change(self, event):
        """Update key placeholder based on selected cipher"""
        cipher_type = self.cipher_var.get()
        self.key_input.delete(0, tk.END)
        
        defaults = {
            'caesar': '3',
            'vigenere': 'KEYWORD',
            'railfence': '3',
            'playfair': 'KEYWORD',
            'atbash': ''
        }
        
        self.key_input.insert(0, defaults.get(cipher_type, ''))
    
    def encrypt_text(self):
        """Encrypt the input text"""
        try:
            text = self.text_input.get(1.0, tk.END).strip()
            cipher_type = self.cipher_var.get()
            key = self.key_input.get()
            
            if not text:
                messagebox.showwarning("Warning", "Please enter text to encrypt")
                return
            
            result = self.engine.encrypt(text, cipher_type, key)
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, result)
            self.status_var.set(f"Encrypted with {cipher_type.title()} cipher")
            
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")
    
    def decrypt_text(self):
        """Decrypt the input text"""
        try:
            text = self.text_input.get(1.0, tk.END).strip()
            cipher_type = self.cipher_var.get()
            key = self.key_input.get()
            
            if not text:
                messagebox.showwarning("Warning", "Please enter text to decrypt")
                return
            
            result = self.engine.decrypt(text, cipher_type, key)
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, result)
            self.status_var.set(f"Decrypted with {cipher_type.title()} cipher")
            
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")
    
    def compare_algorithms(self):
        """Compare all algorithms with sample keys"""
        try:
            text = self.text_input.get(1.0, tk.END).strip()
            if not text:
                messagebox.showwarning("Warning", "Please enter text to compare")
                return
            
            keys = {
                'caesar': '3',
                'vigenere': 'KEYWORD',
                'railfence': '3',
                'playfair': 'KEYWORD',
                'atbash': ''
            }
            
            results = self.engine.compare_algorithms(text, keys)
            
            output = "=== ALGORITHM COMPARISON ===\n"
            output += f"Original Text: {text}\n"
            output += "=" * 40 + "\n"
            
            for cipher, encrypted in results.items():
                output += f"{cipher:<12}: {encrypted}\n"
            
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, output)
            self.status_var.set("Algorithm comparison completed")
            
        except Exception as e:
            messagebox.showerror("Error", f"Comparison failed: {str(e)}")
    
    def load_file(self):
        """Load text from file"""
        try:
            file_path = filedialog.askopenfilename(
                title="Select text file",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
            )
            
            if file_path:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                self.text_input.delete(1.0, tk.END)
                self.text_input.insert(tk.END, content)
                self.status_var.set(f"Loaded: {file_path}")
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load file: {str(e)}")
    
    def save_result(self):
        """Save result to file"""
        try:
            result = self.result_text.get(1.0, tk.END).strip()
            if not result:
                messagebox.showwarning("Warning", "No result to save")
                return
            
            file_path = filedialog.asksaveasfilename(
                title="Save result",
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
            )
            
            if file_path:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(result)
                self.status_var.set(f"Saved: {file_path}")
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save file: {str(e)}")
    
    def clear_all(self):
        """Clear all text fields"""
        self.text_input.delete(1.0, tk.END)
        self.result_text.delete(1.0, tk.END)
        self.status_var.set("Cleared all fields")
    
    def run(self):
        """Start the GUI application"""
        self.root.mainloop()

if __name__ == "__main__":
    app = CipherGUI()
    app.run()
