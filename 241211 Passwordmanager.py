import os
import random
import string
from cryptography.fernet import Fernet

# Encryption Functions
def generate_key():# Generates a unique symmetric encryption key and saves it to the key.key file. The fernet library is used.
    key = Fernet.generate_key() # Generates a new encryption key.
    try:
        with open("key.key", "wb") as key_file:
            key_file.write(key) # Writes the generated key to the key.key file.
    except Exception as e:
        print(f"Error generating key: {e}") # Handles file writing errors.
        exit(1)

def load_key(): # Loads the encryption key from the key.key file.
    try:
        with open("key.key", "rb") as key_file:
            return key_file.read() # Reads and returns the encryption key.
    except FileNotFoundError:
        print("Error: Encryption key not found. Please initialize the manager.")
        exit(1)

def encrypt_message(message): # Encrypts a plaintext message using the loaded encryption key.
    key = load_key()
    f = Fernet(key)
    encrypted_message = f.encrypt(message.encode())
    return encrypted_message

def decrypt_message(encrypted_message): # Decrypts an encrypted message back to plaintext.
    key = load_key()
    f = Fernet(key)
    try:
        decrypted_message = f.decrypt(encrypted_message).decode() # Decrypts and decodes the message.
        return decrypted_message # Returns the decrypted plaintext message.
    except Exception:
        return None # Returns None if decryption fails.

# Master Password Logic
def initialize_master_password():# Initializes the master password if it doesn't already exist. The user has to cofirm the password before it is set.
    if not os.path.exists("master.key"):  # Checks if the file 'master.key' exists.
        print("No master password found. Please set a new one.")
        master_password = input("Master password: ")
        confirm_password = input("Confirm master password: ")
        if master_password != confirm_password: # Checks whether the passwords are equal.
            print("Passwords do not match. Please try again.")
            exit(1)

        encrypted_master_password = encrypt_message(master_password)  # Encrypts the new master password.
        try:
            with open("master.key", "wb") as file:
                file.write(encrypted_master_password) # Saves the encrypted password in the master.key file.
            print("Master password successfully set.")
        except Exception as e:
            print(f"Error setting master password: {e}") # Handles file writing errors.
            exit(1)
    else:
        print("Master password found.") # Indicates that the master password file exists.

def verify_master_password():# Validates the master password entered by the user.
    if not os.path.exists("master.key"): # Checks if the master password file exists.
        print("Error: No master password found. Please initialize the manager.")
        exit(1)
    try:
        with open("master.key", "rb") as file:
            encrypted_master_password = file.read()  # Reads the encrypted master password.
    except Exception as e:
        print(f"Error reading master password file: {e}") # Handles file reading errors.
        exit(1)

    attempts = 3  # The user is allowed three attempts to enter the correct master password.
    while attempts > 0:
        master_password = input("Enter the master password: ")
        decrypted_master_password = decrypt_message(encrypted_master_password)  # Decrypts the stored password.

        if decrypted_master_password is None: # Checks if decryption is successful.
            print("Error: Master password decryption failed.")
            exit(1)

        if master_password == decrypted_master_password: # Compares user input with the stored password.
            print("Access granted.")
            del master_password  # Clear sensitive data
            del decrypted_master_password
            return True # Grants access if the password matches.
        else:
            attempts -= 1 # Every unsucessfull attempt decreases the counter by 1.
            print(f"Wrong password. {attempts} attempts left.")
    print("Too many failed attempts. Access denied.")
    exit(1) # Exits the programm after 3 failed attempts.

def change_master_password(): # Allows the user to change their master password.
    print("Change Master Password")
    if verify_master_password(): # User identification by verifying the current password.
        print("Please enter your new master password.")
        new_master_password = input("New master password: ")
        confirm_password = input("Confirm new master password: ")

        if new_master_password != confirm_password: # Checks whether the passwords are equal.
            print("Passwords do not match. Please try again.")
            return

        encrypted_master_password = encrypt_message(new_master_password) # Encrypts the new password.
        try:
            with open("master.key", "wb") as file:
                file.write(encrypted_master_password) # Saves the new encrypted master password to the master.key file.
            print("Master password successfully changed!")
        except Exception as e:
            print(f"Error changing master password: {e}") # Handles file writing errors.

# Password Manager Functions
def save_password(account, password): # Saves an encrypted password for a specific account to the passwords.txt file.
    account = check_account_exists(account) # Checks for duplicate account names.
    encrypted_password = encrypt_message(password) # Encrypts the password.
    try:
        with open("passwords.txt", "a") as file:
            file.write(f"{account}:{encrypted_password.decode()}\n") # Appends the account and password to the file.
        print("Password saved!")
    except Exception as e:
        print(f"Error saving password: {e}") # Handles file writing errors.

def retrieve_password(account): # Retrieves and decrypts the password for a specific account.
    if not os.path.exists("passwords.txt"): # Checks if the password file exists.
        print("No saved passwords found.") # Informs the user if no data is found.
        return

    try:
        with open("passwords.txt", "r") as file:
            for line in file: # Iterates through each line in the file.
                account_name, encrypted_password = line.strip().split(":") # Splits the account up and encrypted password.
                if account == account_name: # Checks if the account matches the user input.
                    decrypted_password = decrypt_message(encrypted_password.encode()) # Decrypts the password.
                    if decrypted_password:
                        print(f"Password for {account}: {decrypted_password}") # Displays the decrypted password.
                    else:
                        print(f"Error retrieving the password for {account}.") # Handles decryption errors.
                    return
        print("Account not found.") # Informs the user if the account does not exist.
    except Exception as e:
        print(f"Error reading password file: {e}") # Handles file reading errors.

def delete_password(account): # Deletes the password for a specific account
    if not os.path.exists("passwords.txt"): # Checks if the passwords file exists. If not it exits the function.
        print("No saved passwords found.")
        return

    try:
        with open("passwords.txt", "r") as file:
            lines = file.readlines()

        updated_lines = [line for line in lines if not line.startswith(account + ":")] # Create a new list to store updated lines

        if len(updated_lines) == len(lines): # Compares the length of the updated list with the original list. If unchanged, the account doesn't exist.
            print(f"No password found for account: {account}")
            return
        with open("passwords.txt", "w") as file: # Opens the password.txt file 
            file.writelines(updated_lines) # Overwrites the relevant lines with updated content (delete)
        print(f"Password for account '{account}' has been deleted.")
    except Exception as e:
        print(f"Error deleting password: {e}") # Handles file deleting errors

def change_password(account): # Changes the password for a specific account
    if not os.path.exists("passwords.txt"): # Checks if the passwords file exists and if not it exits the function
        print("No saved passwords found.")
        return

    try:
        with open("passwords.txt", "r") as file: # Opens the passwords.txt file in read mode to read all existing entries
            lines = file.readlines() # Reads all lines into a list

        for i, line in enumerate(lines):  #Iterates through the lines
            account_name, _ = line.strip().split(":") # Splits each line into the account and password
            if account_name == account: # Checks if the account matches the specified account
                new_password = input(f"Enter a new password for account '{account}': ") # Defines the new password from user input
                encrypted_password = encrypt_message(new_password) # Encrypts the new password
                lines[i] = f"{account}:{encrypted_password.decode()}\n" # Replaces the old password with the new one in the lines
                with open("passwords.txt", "w") as file:
                    file.writelines(lines) # Writes all updated lines back to the passwords.txt file.
                print(f"Password for account '{account}' has been changed.")
                return

        print(f"Account '{account}' not found.")
    except Exception as e:
        print(f"Error changing password: {e}") # Handles any other errors

def check_account_exists(account): # Checks for duplicate account names
    if not os.path.exists("passwords.txt"):
        # If the passwords file doesn't exist, return the original account name
        return account
    try:
        with open("passwords.txt", "r") as file: # Opens the password file to check for existing accounts
            lines = file.readlines()  # Reads all lines into a list

        for line in lines:# Check each line for an existing account name
            account_name, _ = line.strip().split(":") # Split each line into account and password
            if account_name == account: # Checks if the account name already exists
                print(f"An account with the name '{account}' already exists.")
                new_account = input("Please enter a different account name: ") # Asks for another account name
                return check_account_exists(new_account)  # Recursively checks the new name until a uniqe name is provided.
        return account  # Return the original name if there is no conflict
    except Exception as e:
        print(f"Error checking account name: {e}") # Handles errors
        return account

# Password Generator
def generate_password(length=12, exclude_symbols=False):
    if length < 8: # Checks if the password is at least 8 characters
        print("A secure password should be at least 8 characters long. Please enter a higher number.")
        return None

    if exclude_symbols: # Define character sets for the password generation. The user can decide whether symbols shall be used or not.
        characters = string.ascii_letters + string.digits  # Exclude symbols
    else:
        characters = string.ascii_letters + string.digits + string.punctuation  # Include symbols

    password = ''.join(random.choice(characters) for i in range(length)) # Generate a random password using the character pool
    return password

# Reset Manager
def reset_manager(): # Resets the password manager by deleting all data.
    print("WARNING: This will delete all saved data!")
    confirmation = input("Type 'RESET' to reset the manager: ") # Asks for user confirmation (RESET)
    if confirmation == "RESET": # Checks if the user confirmed the reset correctly.
        try: # Deletes the relevant files (key.key, master.key and passwords.txt)
            if os.path.exists("passwords.txt"):
                os.remove("passwords.txt")
            if os.path.exists("master.key"):
                os.remove("master.key")
            if os.path.exists("key.key"):
                os.remove("key.key")
            print("Password manager has been reset.")
        except Exception as e:
            print(f"Error resetting manager: {e}") # Handles file deletion errors.
    else: # Cancels the reset if confirmation is not provided
        print("Reset aborted.")

# Main Program
def main():# Main logic for the password manager
    # Load the encryption key if it exists, otherwise generate a new one
    if not os.path.exists("key.key"): # Checks if the encryption key exists.
        print("Encryption key not found. Generating a new one...")
        generate_key() # Generates a new key if missing.

    initialize_master_password() # Initialize the master password and validate it

    if not verify_master_password():# Ensure the master password is verified before the user can access the manager
        print("Access to the password manager denied.")
        return

    while True: # Prompts the main menu for the user. The user can input a number between 1 and 6 to access the relevant function.
        print("\nPassword Manager")
        print("1. Save a password")
        print("2. Retrieve a password")
        print("3. Generate a password")
        print("4. Change master password")
        print("5. Reset manager")
        print("6. Delete a password")
        print("7. Change a password")
        print("8. Exit")
        choice = input("Choose an option: ")

        if choice == "1": # Save password option
            account = input("Account name: ")
            password = input("Password: ")
            save_password(account, password)
        elif choice == "2": # Retrieve password option
            account = input("Account name: ")
            retrieve_password(account)
        elif choice == "3":# Password generator option
            try:
                length = int(input("Password length (minimum 8 characters): ")) # Ask the user to input the password length
                exclude = input("Exclude symbols? (yes/no): ").strip().lower()  # Ask the user about excluding symbols
                exclude_symbols = exclude == "yes"  # Convert response to a boolean value

                password = generate_password(length, exclude_symbols)  # Generates the password
                if password:
                    print(f"Generated password: {password}")
                    if input("Save this password? (yes/no): ").lower() == "yes": # Lets the user save the password in a specific account
                        account = input("For which account should it be saved? ")
                        save_password(account, password)
            except ValueError:
                print("Invalid input. Please enter a valid number.")
        elif choice == "4": # Change master password option
            change_master_password()
        elif choice == "5": # Reset manager option
            reset_manager()
        elif choice == "6": # Delete an account option
            account = input("Enter the account name to delete: ")
            delete_password(account)
        elif choice == "7": # Change a password option
            account = input("Enter the account name to change: ")
            change_password(account)
        elif choice == "8": # Exit program option.
            print("Exiting Password Manager.")
            break
        else:
            print("Invalid choice. Please try again.") # Handles invalid inputs

if __name__ == "__main__": # Executes the main program only when run directly.
    main()