from cryptography import x509
from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.x509.oid import NameOID
import datetime
import base64

class SecureSocialMediaApp:
    def __init__(self):
        # Stores users' information, including their private keys, certificates, and permissions
        self.users = {}
        self.messages = []

    def generate_keys_and_certificate(self, user_name):
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        # Generate a self-signed certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, user_name),
        ])
        certificate = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            # Our certificate will be valid for 10 days
            datetime.datetime.utcnow() + datetime.timedelta(days=10)
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(user_name)]),
            critical=False,
        ).sign(private_key, hashes.SHA256())

        # Serialize private key and certificate
        private_key_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        certificate_bytes = certificate.public_bytes(serialization.Encoding.PEM)

        # Store user information
        # Initialize the user's entry before setting subkeys
        self.users[user_name] = {}  # This line ensures the dictionary for the user is created.
        self.users[user_name]["private_key"] = private_key_bytes
        self.users[user_name]["certificate"] = certificate_bytes
        self.users[user_name]['permissions'] = []  
        self.users[user_name]['sent_messages'] = []
        self.users[user_name]['received_messages'] = []

    def log_message(self, sender, receiver, message, encrypted_message, has_permission):
        """Log the message for both sender and receiver with permission info."""
        # If the sender is the same as the receiver, they automatically have permission
        if sender == receiver:
            has_permission = True
    
        encrypted_message_base64 = base64.b64encode(encrypted_message).decode('utf-8')
    
        self.users[sender]['sent_messages'].append({
            'to': receiver,
            'message': message if sender == receiver or has_permission else encrypted_message_base64,
            'encrypted_message': encrypted_message_base64,
            'has_permission': has_permission
        })
    
        self.users[receiver]['received_messages'].append({
            'from': sender,
            'message': message if has_permission else encrypted_message_base64,
            'encrypted_message': encrypted_message_base64,
            'has_permission': has_permission
        })


    def get_user_certificate(self, user_name):
        """Retrieve the certificate of a user."""
        return self.users[user_name]["certificate"] if user_name in self.users else None

    def get_user_private_key(self, user_name):
        """Retrieve the private key of a user."""
        return self.users[user_name]["private_key"] if user_name in self.users else None

    def add_permission(self, user_name, allowed_user):
        """Allow `allowed_user` to decrypt messages sent by `user_name`."""
        if user_name in self.users and allowed_user in self.users:
            self.users[user_name]['permissions'].append(allowed_user)

    def remove_permission(self, user_name, disallowed_user):
        """Remove decryption permission for `disallowed_user` from `user_name`'s messages."""
        if user_name in self.users and disallowed_user in self.users:
            self.users[user_name]['permissions'] = [
                user for user in self.users[user_name]['permissions']
                if user != disallowed_user
            ]

    def encrypt_message_for_user(self, message, sender, receiver, encrypt_for_all=False):
        """Encrypt a message from `sender` to `receiver`. If encrypt_for_all is True, ignore permission checks."""
        # If encrypting for all, ignore permission check
        if not encrypt_for_all and receiver not in self.users[sender]['permissions']:
            raise InvalidKey("Receiver is not authorized to decrypt sender's messages.")    
        
        # Encrypt the message
        return self.encrypt_message(message, receiver)  


    def decrypt_message_from_user(self, encrypted_message_base64, receiver, sender):
        try:
            # Decode the Base64-encoded encrypted message
            encrypted_message_bytes = base64.b64decode(encrypted_message_base64)
    
            # Proceed with your existing decryption logic using encrypted_message_bytes
            decrypted_message = self.decrypt_message(encrypted_message_bytes, receiver)
            return decrypted_message
        except Exception as e:
            # Handle decryption errors or other exceptions
            return f"Error decrypting message: {str(e)}"
    
    def encrypt_message(self, message, receiver):
        """Encrypt a message using the receiver's public key."""
        certificate_pem = self.get_user_certificate(receiver)
        certificate = x509.load_pem_x509_certificate(certificate_pem)
        public_key = certificate.public_key()
        encrypted = public_key.encrypt(
            message.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted

    def decrypt_message(self, encrypted_message, receiver):
        """Decrypt a message using the receiver's private key."""
        private_key_pem = self.get_user_private_key(receiver)
        private_key = serialization.load_pem_private_key(
            private_key_pem,
            password=None,
        )
        original_message = private_key.decrypt(
            encrypted_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return original_message.decode()


    def get_received_messages_with_permission_check(self, user_name):
        """Retrieve received messages for a user, decrypting them if the user has permission."""
        if user_name not in self.users:
            return []

        received_messages = self.users[user_name]['received_messages']
        decrypted_messages = []

        for message in received_messages:
            sender = message['from']
            encrypted_message_base64 = message['encrypted_message']
            has_permission = message['has_permission']

            if has_permission:
                # The user has permission to decrypt the message
                try:
                    decrypted_message = self.decrypt_message_from_user(encrypted_message_base64, user_name, sender)
                except Exception as e:
                    decrypted_message = f"Error decrypting message: {str(e)}"
            else:
                # The user does not have permission; return the encrypted message
                decrypted_message = encrypted_message_base64

            decrypted_messages.append({
                'from': sender,
                'message': decrypted_message,
                'has_permission': has_permission
            })

        return decrypted_messages

    def handle_message_for_all_users(self, sender, message):
        for user_name in self.users:
            # Check if the sender has given decryption permission to the user
            has_permission = user_name in self.users[sender]['permissions']
            # Encrypt the message for the user
            encrypted_message = self.encrypt_message(message, user_name)
            # Log the message
            self.log_message(sender, user_name, message, encrypted_message, has_permission)

    def get_users_with_permission(self, user_name):
        """Get a list of users who have permission to decrypt messages sent by `user_name`."""
        if user_name not in self.users:
            return []  # Return an empty list if the user does not exist

        return self.users[user_name]['permissions']