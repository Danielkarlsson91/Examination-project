import sys
from PyQt6.QtWidgets import QApplication, QMainWindow, QPushButton

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__() 

        self.setWindowTitle("My App")

        # Create a central widget to hold multiple buttons
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        # Create a vertical layout to arrange the buttons
        layout = QVBoxLayout()
        central_widget.setLayout(layout)

        # Create and add the first button
        button1 = QPushButton("Press me!")
        button1.setCheckable(True)
        button1.clicked.connect(self.the_button_was_clicked)
        self.setCentralWidget(button1)

        button2 = QPushButton("Click me too!")
        button2.setCheckable(True)
        button2.clicked.connect(self.the_button2_was_clicked)
        layout.addWidget(button2)

        # Create the third button
        button3 = QPushButton("Another button!")
        button3.setCheckable(True)
        button3.clicked.connect(self.the_button3_was_clicked)
        layout.addWidget(button3)

    # Define click handler for the first button
    def the_button_was_clicked(self):
        print("Clicked!") 

    # Define click handler for the second button
    def the_button2_was_clicked(self):
        print("Button 2 was clicked!")

    # Define click handler for the third button
    def the_button3_was_clicked(self):
        print("Button 3 was clicked!")

# Create an instance of QApplication
app = QApplication(sys.argv)

# Create an instance of the main window
window = MainWindow()

# Show the main window
window.show()

# Start the application's event loop
app.exec()