import sys
from PyQt6.QtWidgets import QApplication, QMainWindow, QPushButton, QFileDialog, QTextEdit, QVBoxLayout, QWidget
from backend import PEAnalyzer

class PEAnalyzerGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("PE Analyzer")
        self.setGeometry(200, 200, 600, 400)

        self.layout = QVBoxLayout()
        self.text_area = QTextEdit()
        self.load_button = QPushButton("Load PE File")
        self.load_button.clicked.connect(self.load_pe_file)

        self.layout.addWidget(self.load_button)
        self.layout.addWidget(self.text_area)

        container = QWidget()
        container.setLayout(self.layout)
        self.setCentralWidget(container)

    def load_pe_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Open PE File", "", "Executable Files (*.exe *.dll)")
        if file_path:
            pe_analyzer = PEAnalyzer(file_path)
            pe_analyzer.load_file()

            headers = pe_analyzer.get_headers()
            sections = pe_analyzer.get_sections()
            file_hash = pe_analyzer.calculate_hash()

            result = f"File: {file_path}\n\nHeaders:\n{headers}\n\nSections:\n{sections}\n\nMD5 Hash:\n{file_hash}"
            self.text_area.setText(result)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = PEAnalyzerGUI()
    window.show()
    sys.exit(app.exec())
