import json
import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

VAULT_FILE = "vault.dat"
SALT_FILE = "salt.bin"

def get_or_create_salt():
    if os.path.exists(SALT_FILE):
        with open(SALT_FILE, "rb") as f:
            return f.read()
    salt = os.urandom(16)
    with open(SALT_FILE, "wb") as f:
        f.write(salt)
    return salt

def derive_key(master_password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode()))

def encrypt_vault(vault: dict, key: bytes) -> bytes:
    f = Fernet(key)
    return f.encrypt(json.dumps(vault).encode())

def decrypt_vault(data: bytes, key: bytes) -> dict:
    f = Fernet(key)
    return json.loads(f.decrypt(data).decode())

def load_vault(key: bytes) -> dict:
    if not os.path.exists(VAULT_FILE):
        return {}
    with open(VAULT_FILE, "rb") as f:
        data = f.read()
    try:
        return decrypt_vault(data, key)
    except Exception:
        print("Wrong master password or vault is corrupted.")
        exit(1)

def save_vault(vault: dict, key: bytes):
    with open(VAULT_FILE, "wb") as f:
        f.write(encrypt_vault(vault, key))

def main():
    master = input("Enter master password: ").strip()
    if not master:
        print("Master password cannot be empty.")
        exit(1)

    salt = get_or_create_salt()
    key = derive_key(master, salt)

    print("\n🔐 Password Manager")
    while True:
        print("\n1. Add entry")
        print("2. View entry")
        print("3. List sites")
        print("4. Delete entry")
        print("5. Quit")
        choice = input("\nChoose an option: ").strip()

        if choice == "1":
            site = input("Site (e.g. github.com): ").strip()
            username = input("Username: ").strip()
            password = input("Password: ").strip()

            if not site or not username or not password:
                print("Site, username, and password cannot be empty.")
                continue

            vault = load_vault(key)

            if site in vault:
                confirm = input(f"{site} already exists. Overwrite? (y/n): ").strip().lower()
                if confirm != "y":
                    print("Cancelled.")
                    continue

            vault[site] = {"username": username, "password": password}
            save_vault(vault, key)
            print(f"Entry for {site} saved.")

        elif choice == "2":
            site = input("Site to look up: ").strip()
            if not site:
                print("Site cannot be empty.")
                continue
            vault = load_vault(key)
            if site in vault:
                print(f"\nSite:     {site}")
                print(f"Username: {vault[site]['username']}")
                print(f"Password: {vault[site]['password']}")
            else:
                print(f"No entry found for {site}.")

        elif choice == "3":
            vault = load_vault(key)
            if not vault:
                print("Vault is empty.")
            else:
                print("\nSaved sites:")
                for site in vault:
                    print(f"  - {site}")

        elif choice == "4":
            site = input("Site to delete: ").strip()
            if not site:
                print("Site cannot be empty.")
                continue
            vault = load_vault(key)
            if site not in vault:
                print(f"No entry found for {site}.")
                continue
            confirm = input(f"Delete {site}? (y/n): ").strip().lower()
            if confirm == "y":
                del vault[site]
                save_vault(vault, key)
                print(f"{site} deleted.")
            else:
                print("Cancelled.")

        elif choice == "5":
            print("Goodbye.")
            break

        else:
            print("Invalid option, try again.")

if __name__ == "__main__":
    main()
