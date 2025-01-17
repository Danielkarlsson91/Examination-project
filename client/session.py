# Import Communication class from communication module
from communication import Communication
# Import cryptographic functions from mbedtls library
from mbedtls import pk, hmac, hashlib, cipher

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
        # Initialize relay state tracking variable
        self.relay_state = False
        # Initialize session ID
        self.__SESSION_ID = bytes([0] * 8)  # Create 8 zero bytes

        # Check if the communication port is open
        if not self.communication.communication_open():
            raise Exception("Failed to connect")
        
        # Initialize HMAC key
        sha256 = hashlib.sha256()
        sha256.update(self.__SECRET_KEY)
        hmac_key = sha256.digest()
        self.__HMAC_KEY = hmac.new(hmac_key, digestmod="SHA256")
        print("      HMAC Key =", self.__HMAC_KEY.digest().hex())
    
    def toggle_relay(self):
        """
        Toggle the relay state and return status.
        Returns:
            tuple: (status_code, message)
        """
        try:
            # Convert toggle relay command to bytes
            command = self.__TOGGLE_RELAY.to_bytes(1, 'big')
            # Send command to device
            self.communication.communication_send(command)
            
            # Read response from device
            response = self.communication.communication_read(1)
            
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
            # Convert get temperature command to bytes
            command = self.__GET_TEMP.to_bytes(1, 'big')
            # Send command to device
            self.communication.communication_send(command)

            # Read 4 bytes (float temperature)
            response = self.communication.communication_read(4)
            if len(response) == 4:
                # Convert bytes to float
                temperature = float.fromhex(response.hex())
                return self.STATUS_OKAY, f"Temperature: {temperature:.2f} °C"
            else:
                # Return error if the response length is unexpected
                return self.STATUS_ERROR, "Failed to read temperature"
        
        except Exception as e:
            # Return connection error if any exception occurs
            return self.STATUS_CONNECTION_ERROR, f"Error: {e}"
