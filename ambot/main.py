from cryptography.fernet import Fernet
import os
import hashlib
import shutil
from dotenv import load_dotenv
import click

def generate_key():
    """Generate a key and save it to a file"""
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(key)
    return key

def load_key():
    """Load the key from the current directory"""
    if not os.path.exists("secret.key"):
        return generate_key()
    
    with open("secret.key", "rb") as key_file:
        return key_file.read()

def calculate_checksum(filename):
    """Calculate SHA-256 checksum of a file"""
    sha256_hash = hashlib.sha256()
    with open(filename, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def save_file(filename, content):
    """Save content to a file"""
    try:
        with open(filename, 'wb') as file:
            file.write(content)
        print(f"File saved successfully as: {filename}")
        return True
    except Exception as e:
        print(f"Error saving file: {str(e)}")
        return False

def upload_file(source_path, destination_folder="uploads"):
    """Upload (copy) a file to the uploads folder"""
    try:
        # Create uploads directory if it doesn't exist
        if not os.path.exists(destination_folder):
            os.makedirs(destination_folder)
        
        # Get the filename from the source path
        filename = os.path.basename(source_path)
        destination_path = os.path.join(destination_folder, filename)
        
        # Copy the file
        shutil.copy2(source_path, destination_path)
        
        # Calculate and save checksum
        checksum = calculate_checksum(destination_path)
        checksum_file = destination_path + ".checksum"
        with open(checksum_file, "w") as f:
            f.write(checksum)
        
        print(f"File uploaded successfully to: {destination_path}")
        print(f"Checksum saved to: {checksum_file}")
        return True
    except Exception as e:
        print(f"Error uploading file: {str(e)}")
        return False

def download_file(filename, destination_folder="downloads"):
    """Download (copy) a file from the uploads folder"""
    try:
        # Create downloads directory if it doesn't exist
        if not os.path.exists(destination_folder):
            os.makedirs(destination_folder)
        
        source_path = os.path.join("uploads", filename)
        destination_path = os.path.join(destination_folder, filename)
        
        # Check if source file exists
        if not os.path.exists(source_path):
            print(f"Error: Source file {source_path} not found!")
            return False
        
        # Copy the file
        shutil.copy2(source_path, destination_path)
        print(f"File downloaded successfully to: {destination_path}")
        return True
    except Exception as e:
        print(f"Error downloading file: {str(e)}")
        return False

def verify_file_integrity(filename):
    """Verify file integrity using stored checksum"""
    try:
        # Calculate current checksum
        current_checksum = calculate_checksum(filename)
        
        # Read stored checksum
        checksum_file = filename + ".checksum"
        if not os.path.exists(checksum_file):
            print("Error: Checksum file not found!")
            return False
        
        with open(checksum_file, "r") as f:
            stored_checksum = f.read().strip()
        
        # Compare checksums
        if current_checksum == stored_checksum:
            print("File integrity verified: Checksums match!")
            return True
        else:
            print("Warning: File integrity check failed! Checksums do not match.")
            print(f"Stored checksum: {stored_checksum}")
            print(f"Current checksum: {current_checksum}")
            return False
    except Exception as e:
        print(f"Error verifying file integrity: {str(e)}")
        return False

def encrypt_file(filename):
    """Encrypt the file"""
    key = load_key()
    f = Fernet(key)

    with open(filename, "rb") as file:
        file_data = file.read()

    encrypted_data = f.encrypt(file_data)

    with open(filename + ".encrypted", "wb") as file:
        file.write(encrypted_data)
    
    print(f"File encrypted successfully! Output: {filename}.encrypted")

def decrypt_file(filename):
    """Decrypt the file"""
    key = load_key()
    f = Fernet(key)

    with open(filename, "rb") as file:
        encrypted_data = file.read()

    decrypted_data = f.decrypt(encrypted_data)

    # Remove .encrypted extension if present
    output_filename = filename.replace('.encrypted', '.decrypted')
    
    with open(output_filename, "wb") as file:
        file.write(decrypted_data)
    
    print(f"File decrypted successfully! Output: {output_filename}")

@click.command()
def main():
    """Simple file encryption/decryption tool"""
    while True:
        print("\nFile Management and Encryption Tool")
        print("1. Encrypt a file")
        print("2. Decrypt a file")
        print("3. Upload a file")
        print("4. Download a file")
        print("5. Verify file integrity")
        print("6. Exit")
        
        choice = input("Enter your choice (1-6): ")
        
        if choice == "6":
            break
        
        if choice in ["1", "2", "3", "5"]:
            filename = input("Enter the filename: ")
            if not os.path.exists(filename):
                print("Error: File not found!")
                continue
        
        try:
            if choice == "1":
                encrypt_file(filename)
            elif choice == "2":
                decrypt_file(filename)
            elif choice == "3":
                upload_file(filename)
            elif choice == "4":
                filename = input("Enter the filename to download: ")
                download_file(filename)
            elif choice == "5":
                verify_file_integrity(filename)
            else:
                print("Invalid choice! Please select 1-6.")
        except Exception as e:
            print(f"An error occurred: {str(e)}")

if __name__ == "__main__":
    main()
