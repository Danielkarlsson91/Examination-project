# Import Communication class from communication module
from communication import Communication
# Import cryptographic functions from mbedtls library
from mbedtls import pk, hmac, hashlib, cipher
import time
import struct

class Session:
    # Define RSA key size constant (256 bytes = 2048 bits)
    __RSA_SIZE = 256
    # Define RSA public exponent
    __EXPONENT = 65537
    # Define secret key for cryptographic operations
    __SECRET_KEY = b"Fj2-;wu3Ur=ARl2!Tqi6IuKM3nG]8z1+"
    
    # Command constants for device communication
    __CLOSE = 0          # Command to close connection
    __GET_TEMP = 1       # Command to get temperature
    __TOGGLE_RELAY = 3   # Command to toggle relay state
    
    # Status codes for operation results
    STATUS_OKAY = 0              # Operation completed successfully
    STATUS_ERROR = 1             # General error occurred
    STATUS_EXPIRED = 2           # Session has expired
    STATUS_HASH_ERROR = 3        # Hash verification failed
    STATUS_BAD_REQUEST = 4       # Invalid request format
    STATUS_INVALID_SESSION = 5   # Session is invalid
    STATUS_CONNECTION_ERROR = 6  # Connection error occurred

    def __init__(self, port):
        """
        Initialize a Session instance with a given communication port.
        Args:
            port (str): The port to use for communication.
        """
        # Create Communication object for serial connection
        self.communication = Communication(port)

        # Check if the communication port is open
        if not self.communication.open():
            raise Exception("Failed to connect")
        
        # Initialize session ID
        self.__SESSION_ID = bytes([0] * 8)  # Create 8 zero bytes

        # Initialize HMAC key
        self.__hmac = hashlib.sha256()
        self.__hmac.update(self.__SECRET_KEY)
        self.__hmac = self.__hmac.digest()
        self.__hmac = hmac.new(self.__hmac, digestmod="SHA256")

        # Initialize RSA key pair and exchange keys
            
        # Skapa temp key
        self.__clientRSA = pk.RSA()
        self.__clientRSA.generate(self.__RSA_SIZE * 8, self.__EXPONENT)
        buffer = self.__clientRSA.export_public_key()
        
        # Write public temp key
        if not self.__write(buffer):
            raise Exception("1) Failed to exchange keys")

        # Read server public key <-- spara den
        buffer = self.__read(self.__RSA_SIZE * 2)
        if 0 == len(buffer):
            raise Exception("2) Failed to exchange keys")
        print("read1")
        # Decrypt server public key med temp private key
        self.__serverRSA  = self.__clientRSA.decrypt(buffer[0 : self.__RSA_SIZE])
        self.__serverRSA += self.__clientRSA.decrypt(buffer[self.__RSA_SIZE : self.__RSA_SIZE * 2])
        self.__serverRSA = pk.RSA().from_DER(self.__serverRSA)

        # create a new pair of keys
        del self.__clientRSA
        self.__clientRSA = pk.RSA()
        self.__clientRSA.generate(self.__RSA_SIZE * 8, self.__EXPONENT)
        buffer = self.__clientRSA.export_public_key()

        buffer = self.__clientRSA.export_public_key() + self.__clientRSA.sign(Session.__SECRET_KEY, "SHA256")
        buffer = self.__serverRSA.encrypt(buffer[0:184]) + self.__serverRSA.encrypt(buffer[184:368]) + self.__serverRSA.encrypt(buffer[368:550])

        if not self.__write(buffer):
            raise Exception("3) Failed to exchange keys")
        print("Write2")
        buffer = self.__read(self.__RSA_SIZE)
        if 0 == len(buffer):
            raise Exception("4) Failed to exchange keys")
        
        if b"DONE" != self.__clientRSA.decrypt(buffer):
            raise Exception("5) Failed to exchange keys")
        
        print("Key exchange")

    def __read(self, size) -> bytes:
        """
        Read data and verify HMAC
        
        Args:
            size: Number of bytes to read
            
        Returns:
            Verified data
        """

        buffer = b''
        try:
            # Read data with HMAC (data + 32 bytes for HMAC)
            buffer = self.communication.receive(size + self.__hmac.digest_size)
            
            if len(buffer) > self.__hmac.digest_size:            
                # Separate data and HMAC
                received_hmac = buffer[size:size+self.__hmac.digest_size]
                
                # Calculate HMAC for verification
                self.__hmac.update(buffer[0:size])
                calculated_hmac = self.__hmac.digest()
                
                # Verify HMAC
                if calculated_hmac != received_hmac:
                    buffer = b''
            else:
                buffer = b''
            
        except Exception as e:
            print(f"Read error: {e}")
            pass

        return buffer

    def __write(self, msg) -> bool:
        """
        Write data with HMAC protection
        
        Args:
            msg: Data to send
        """
        self.__hmac.update(msg)
        print(len(msg))
        msg += self.__hmac.digest()
        print(len(msg))
        print(msg.hex())
        return self.communication.send(msg)


    def __start_session(self):
        """
        Establish a new session with the server
        """
        try:
            # Generate session ID (8 random bytes)
            import secrets
            self.__SESSION_ID = secrets.token_bytes(8)
            
            # Record session start time
            self.__session_start_time = time.time()
            
            # Send session ID to server
            self.__send(self.__SESSION_ID)
            
            # Verify server response
            response = self.__receive(1)
            if response != b'\x01':
                raise Exception("Session establishment failed")
            
            print("Session established successfully")
        except Exception as e:
            print(f"Session establishment error: {e}")
            raise

    def __check_session_validity(self):
        """
        Check if the current session is still valid
        """
        if not self.__session_start_time:
            return False
        
        # Check if session has expired
        current_time = time.time()
        if current_time - self.__session_start_time > self.__SESSION_TIMEOUT:
            return False
        
        return True

    def __receive(self, length: int) -> bytes:
        """
        Receive encrypted data from the server
        
        Args:
            length (int): Number of bytes to receive
        
        Returns:
            bytes: Decrypted received data
        """
        if not self.__check_session_validity():
            raise Exception("Session expired")
        
        try:
            # Receive encrypted data
            encrypted_data = self.communication.communication_read(length + 32)  # Include HMAC
            
            # Separate HMAC and encrypted data
            received_hmac = encrypted_data[-32:]
            encrypted_payload = encrypted_data[:-32]
            
            # Verify HMAC
            calculated_hmac = self.__HMAC_KEY.copy()
            calculated_hmac.update(encrypted_payload)
            if calculated_hmac.digest() != received_hmac:
                raise Exception("HMAC verification failed")
            
            # Decrypt payload (use AES decryption)
            aes = cipher.AES.new(self.__HMAC_KEY.digest()[:16], cipher.MODE_ECB)
            decrypted_data = aes.decrypt(encrypted_payload)
            
            return decrypted_data[:length]
        
        except Exception as e:
            print(f"Receive error: {e}")
            return b''

    def __send(self, buf: bytes) -> bool:
        """
        Send encrypted data to the server
        
        Args:
            buf (bytes): Data to send
        
        Returns:
            bool: True if sending was successful, False otherwise
        """
        if not self.__check_session_validity():
            raise Exception("Session expired")
        
        try:
            # Pad data to AES block size (16 bytes)
            pad_length = 16 - (len(buf) % 16)
            padded_data = buf + bytes([pad_length] * pad_length)
            
            # Encrypt payload
            aes = cipher.AES.new(self.__HMAC_KEY.digest()[:16], cipher.MODE_ECB)
            encrypted_payload = aes.encrypt(padded_data)
            
            # Calculate HMAC
            hmac_calc = self.__HMAC_KEY.copy()
            hmac_calc.update(encrypted_payload)
            hmac_digest = hmac_calc.digest()
            
            # Combine encrypted payload and HMAC
            full_message = encrypted_payload + hmac_digest
            
            # Send encrypted message
            self.communication.communication_send(full_message)
            return True
        
        except Exception as e:
            print(f"Send error: {e}")
            return False

    def close_session(self):
        """
        Close the current session
        """
        try:
            # Send close command
            command = self.__CLOSE.to_bytes(1, 'big')
            self.__send(command)
            
            # Reset session variables
            self.__SESSION_ID = bytes([0] * 8)
            self.__session_start_time = None
            
            return self.STATUS_OKAY, "Session Closed"
        
        except Exception as e:
            return self.STATUS_ERROR, f"Error closing session: {e}"

    def toggle_relay(self):
        """
        Toggle the relay state and return status.
        Returns:
            tuple: (status_code, message)
        """
        try:
            # Check session validity
            if not self.__check_session_validity():
                return self.STATUS_EXPIRED, "Session Expired"
            
            # Convert toggle relay command to bytes
            command = self.__TOGGLE_RELAY.to_bytes(1, 'big')
            # Send encrypted command to device
            self.__send(command)
            
            # Read encrypted response from device
            response = self.__receive(1)
            
            # Process response based on received byte
            if response == b'\x01':  # If device returns 0x01
                self.relay_state = True
                return self.STATUS_OKAY, "Relay State: On"
            elif response == b'\x00':  # If device returns 0x00
                self.relay_state = False
                return self.STATUS_OKAY, "Relay State: Off"
            else:
                # Return error if unexpected response received
                return self.STATUS_ERROR, "Unexpected response from device"
                
        except Exception as e:
            # Return connection error if any exception occurs
            return self.STATUS_CONNECTION_ERROR, f"Error: {e}"
        
    def get_temperature(self):
        """
        Get the current temperature from the device.
        Returns:
            tuple: (status_code, message)
        """
        try:
            # Check session validity
            if not self.__check_session_validity():
                return self.STATUS_EXPIRED, "Session Expired"
            
            # Convert get temperature command to bytes
            command = self.__GET_TEMP.to_bytes(1, 'big')
            # Send encrypted command to device
            self.__send(command)

            # Read encrypted 4 bytes (float temperature)
            response = self.__receive(4)
            if len(response) == 4:
                # Convert bytes to float
                temperature = struct.unpack('!f', response)[0]
                return self.STATUS_OKAY, f"Temperature: {temperature:.2f} °C"
            else:
                # Return error if the response length is unexpected
                return self.STATUS_ERROR, "Failed to read temperature"
        
        except Exception as e:
            # Return connection error if any exception occurs
            return self.STATUS_CONNECTION_ERROR, f"Error: {e}"