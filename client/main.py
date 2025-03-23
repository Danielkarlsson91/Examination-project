import sys
import traceback
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QPushButton, QTextEdit, QVBoxLayout, 
    QHBoxLayout, QWidget, QLabel, QMessageBox, QLineEdit, QDialog
)
from PyQt6.QtCore import QThread, pyqtSignal, Qt
from PyQt6.QtGui import QFont

from session import Session

class SerialConfigDialog(QDialog):
    """Dialog for configuring serial port settings"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Serial Port Configuration")
        self.setModal(True)
        
        layout = QVBoxLayout()
        
        # Port input
        self.port_label = QLabel("Serial Port:")
        self.port_input = QLineEdit()
        self.port_input.setPlaceholderText("/dev/ttyUSB0")
        
        layout.addWidget(self.port_label)
        layout.addWidget(self.port_input)
        
        # Buttons
        button_layout = QHBoxLayout()
        self.ok_button = QPushButton("Connect")
        self.cancel_button = QPushButton("Cancel")
        
        button_layout.addWidget(self.ok_button)
        button_layout.addWidget(self.cancel_button)
        
        layout.addLayout(button_layout)
        
        self.setLayout(layout)
        
        # Connections
        self.ok_button.clicked.connect(self.accept)
        self.cancel_button.clicked.connect(self.reject)
    
    def get_port(self):
        return self.port_input.text() or "/dev/ttyUSB0"

class ClientGui(QMainWindow):
    def __init__(self):
        super().__init__()
        
        # Open serial port configuration dialog at startup
        dialog = SerialConfigDialog(self)
        if dialog.exec():
            port = dialog.get_port()
        else:
            port = "/dev/ttyUSB0"  # Default if user cancels
        
        self.session = Session(port)
        
        self.initUI()

    def initUI(self):
        """Initialize the user interface"""
        self.setWindowTitle("Secure Client Application")
        self.setGeometry(100, 100, 600, 500)

        # Central widget and main layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout()

        # Connection status
        self.connection_status = QLabel("Not Connected")
        self.connection_status.setStyleSheet("color: red; font-weight: bold;")
        main_layout.addWidget(self.connection_status)

        # Buttons layout
        button_layout = QHBoxLayout()
        
        # Buttons
        self.connect_button = QPushButton("Connect")
        self.connect_button.clicked.connect(self.open_serial_config)
        
        self.get_temp_button = QPushButton("Get Temperature")
        self.get_temp_button.clicked.connect(self.get_temperature)
        self.get_temp_button.setEnabled(False)
        
        self.toggle_relay_button = QPushButton("Toggle Relay")
        self.toggle_relay_button.clicked.connect(self.toggle_relay)
        self.toggle_relay_button.setEnabled(False)
        
        self.close_session_button = QPushButton("Close Session")
        self.close_session_button.clicked.connect(self.close_session)
        self.close_session_button.setEnabled(False)

        # Add buttons to layout
        button_layout.addWidget(self.connect_button)
        button_layout.addWidget(self.get_temp_button)
        button_layout.addWidget(self.toggle_relay_button)
        button_layout.addWidget(self.close_session_button)

        main_layout.addLayout(button_layout)

        # Log area
        self.log_area = QTextEdit()
        self.log_area.setReadOnly(True)
        self.log_area.setFont(QFont("Monospace", 10))
        self.log_area.setStyleSheet("""
            QTextEdit {
                background-color: black; 
                color: lime; 
                border: 1px solid #333;
            }
        """)
        main_layout.addWidget(self.log_area)

        # Clear log button
        self.clear_log_button = QPushButton("Clear Log")
        self.clear_log_button.clicked.connect(self.clear_log)
        main_layout.addWidget(self.clear_log_button)

        # Set main layout
        central_widget.setLayout(main_layout)

    def open_serial_config(self):
        """Open serial port configuration dialog"""
        dialog = SerialConfigDialog(self)
        if dialog.exec():
            port = dialog.port_input.text() or "/dev/ttyUSB0"
            self.establish_session(port)

    def establish_session(self, port):
        """Establish a new session"""
        try:
            # Close existing session if any
            if self.session:
                self.session.close_session()

            # Create new session
            self.session = Session(port)
            
            # Update UI
            self.connection_status.setText(f"Connected to {port}")
            self.connection_status.setStyleSheet("color: green; font-weight: bold;")
            
            # Enable buttons
            self.get_temp_button.setEnabled(True)
            self.toggle_relay_button.setEnabled(True)
            self.close_session_button.setEnabled(True)
            
            # Log success
            self.log_message("Session established successfully")
        except Exception as e:
            # Show error dialog
            QMessageBox.critical(self, "Connection Error", 
                                 f"Failed to establish session: {str(e)}")

    def get_temperature(self):
        """Get temperature in a background thread"""
        if not self.session:
            QMessageBox.warning(self, "No Session", "Please establish a session first.")
            return
        
        worker = ThreadWorker(self.session.get_temperature)
        worker.result.connect(self.handle_operation_result)
        worker.start()

    def toggle_relay(self):
        """Toggle relay in a background thread"""
        if not self.session:
            QMessageBox.warning(self, "No Session", "Please establish a session first.")
            return
        
        worker = ThreadWorker(self.session.toggle_relay)
        worker.result.connect(self.handle_operation_result)
        worker.start()

    def close_session(self):
        """Close current session"""
        if not self.session:
            QMessageBox.warning(self, "No Session", "No active session to close.")
            return
        
        worker = ThreadWorker(self.session.close_session)
        worker.result.connect(self.handle_session_close)
        worker.start()

    def handle_operation_result(self, status, message):
        """Handle results from temperature and relay operations"""
        if status == 0:  # STATUS_OKAY
            self.log_message(message)
        else:
            self.log_message(f"Operation failed: {message}", is_error=True)

    def handle_session_close(self, status, message):
        """Handle session closing"""
        if status == 0:  # STATUS_OKAY
            # Reset UI
            self.connection_status.setText("Not Connected")
            self.connection_status.setStyleSheet("color: red; font-weight: bold;")
            
            # Disable buttons
            self.get_temp_button.setEnabled(False)
            self.toggle_relay_button.setEnabled(False)
            self.close_session_button.setEnabled(False)
            
            # Clear session
            self.session = None
            
            self.log_message("Session closed successfully")
        else:
            self.log_message(f"Session close failed: {message}", is_error=True)

    def log_message(self, message, is_error=False):
        """Log messages to the text area"""
        color = "red" if is_error else "lime"
        formatted_message = f'<span style="color: {color};">{message}</span>'
        self.log_area.append(formatted_message)

    def clear_log(self):
        """Clear the log area"""
        self.log_area.clear()

def main():
    """Main application entry point"""
    app = QApplication(sys.argv)
    
    # Style the application
    app.setStyle('Fusion')
    
    # Create and show the main window
    window = ClientGui()
    window.show()
    
    # Execute the application
    sys.exit(app.exec())

if __name__ == "__main__":
    main()