import sys
from PyQt6.QtWidgets import QApplication, QMainWindow, QPushButton

# Define the main window class that inherits from QMainWindow
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__() # Call the parent class (QMainWindow) initializer

        # Set the title of the main window
        self.setWindowTitle("My App")

        # Create a QPushButton widget with the label "Press me!"
        button = QPushButton("Press me!")
        button.setCheckable(True)
        button.clicked.connect(self.the_button_was_clicked)

        self.setCentralWidget(button)

    def the_button_was_clicked(self):
        print("Clicked")

app = QApplication(sys.argv)

window = MainWindow()
window.show()

app.exec()