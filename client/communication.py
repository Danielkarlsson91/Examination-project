# Import the pyserial library for serial communication
import serial
import sys

# Define default baud rate for serial communication speed (115200 bits per second)
BAUDRATE = 115200

# Define a class to handle serial communication operations
class Communication:
    # Constructor method to initialize the Communication object
    def __init__(self, port, baudrate=BAUDRATE):
        """
        Initialize serial communication.
        
        Args:
            port (str): Serial port to connect to
            baudrate (int, optional): Communication speed. Defaults to 115200.
        """
        try:
            # Create a new Serial object with specified port and baudrate
            self.__ser = serial.Serial(
                port=port, 
                baudrate=baudrate, 
                bytesize=serial.EIGHTBITS,
                parity=serial.PARITY_NONE,
                stopbits=serial.STOPBITS_ONE,
            )
        except serial.SerialException as e:
            print(f"Error initializing serial communication: {e}")
            raise

    # Method to send data through the serial connection
    def send(self, buffer: bytes) -> bool:
        """
        Send data through serial connection.
        
        Args:
            buffer (bytes): Data to send
        
        Returns:
            int: Number of bytes written
        
        Raises:
            Exception: If serial connection is not open
        """
        # Check if serial connection is open
        status = False

        try:
            if self.__ser.is_open:
                self.__ser.reset_output_buffer()
                status = (len(buffer) == self.__ser.write(buffer))
        except:
            pass

        return status

    # Method to read data from the serial connection
    def receive(self, size: int) -> bytes:
        """
        Read data from serial connection.
        
        Args:
            size (int): Number of bytes to read
        
        Returns:
            bytes: Data read from serial port
        
        Raises:
            Exception: If serial connection is not open or read fails
        """
        # Check if serial connection is open
        if not self.__ser.is_open:
            # If not open, raise an exception with error message
            raise Exception("Serial connection is not open.")
        
        try:
            # Read specified number of bytes from serial port and return the data
            self.__ser.reset_input_buffer()
            data = self.__ser.read(size)
            
            # Check if we read the expected number of bytes
            if len(data) != size:
                raise Exception(f"Expected {size} bytes, but read {len(data)} bytes")
            
            return data
        except Exception as e:
            print(f"Error reading data: {e}")
            raise

    # Method to open the serial connection
    def open(self) -> bool:
        """
        Open the serial connection.
        
        Returns:
            bool: True if connection is open, False otherwise
        """
        try:
            # Check if serial connection is not open
            if not self.__ser.is_open:
                # If not open, open the serial connection
                self.__ser.open()
            # Return the current state of the serial connection (True if open)
            return self.__ser.is_open
        except Exception as e:
            print(f"Error opening serial connection: {e}")
            return False

    # Method to close the serial connection
    def close(self):
        """
        Close the serial connection.
        """
        try:
            # Check if serial connection is open
            if self.__ser.is_open:
                # If open, close the serial connection
                self.__ser.close()
        except Exception as e:
            print(f"Error closing serial connection: {e}")

    def __del__(self):
        """
        Destructor to ensure serial connection is closed when object is deleted.
        """
        try:
            if hasattr(self, 'ser') and self.__ser.is_open:
                self.__ser.close()
        except:
            pass