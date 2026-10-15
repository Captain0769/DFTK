import sys
from PyQt5.QtWidgets import QApplication
from gui.main_window import MainWindow

def main():
    """Main entry point for AMAAN Digital Forensic Toolkit"""
    app = QApplication(sys.argv)
    app.setApplicationName("AMAAN - Digital Forensic Toolkit")
    app.setApplicationVersion("1.0.0")
    
    window = MainWindow()
    window.show()
    
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
