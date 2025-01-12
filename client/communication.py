# Import the pyserial library for serial communication
import serial

# Define default baud rate for serial communication speed (115200 bits per second)
BAUDRATE = 115200

# Define a class to handle serial communication operations
class Communication:
    # Constructor method to initialize the Communication object
    def __init__(self, port, baudrate=BAUDRATE):
        # Create a new Serial object with specified port and baudrate
        self.ser = serial.Serial(port, baudrate)

    # Method to send data through the serial connection
    def communication_send(self, buffer: bytes) -> int:
        # Check if serial connection is open
        if not self.ser.is_open:
            # If not open, raise an exception with error message
            raise Exception("Serial connection is not open.")
        # Write the buffer data to serial port and return number of bytes written
        return self.ser.write(buffer)

    # Method to read data from the serial connection
    def communication_read(self, size: int) -> bytes:
        # Check if serial connection is open
        if not self.ser.is_open:
            # If not open, raise an exception with error message
            raise Exception("Serial connection is not open.")
        # Read specified number of bytes from serial port and return the data
        return self.ser.read(size)

    # Method to open the serial connection
    def communication_open(self) -> bool:
        # Check if serial connection is not open
        if not self.ser.is_open:
            # If not open, open the serial connection
            self.ser.open()
        # Return the current state of the serial connection (True if open)
        return self.ser.is_open

    # Method to close the serial connection
    def communication_close(self):
        # Check if serial connection is open
        if self.ser.is_open:
            # If open, close the serial connection
            self.ser.close()

# Check if this file is being run directly (not imported as a module)
if __name__ == "__main__":
    # Print success message if module is run directly
    print("Communication module is running successfully!")