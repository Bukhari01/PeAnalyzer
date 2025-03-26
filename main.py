import sys
from PyQt6.QtWidgets import (QApplication, QMainWindow, QPushButton, QFileDialog, QTextEdit, QVBoxLayout, 
                             QWidget, QLabel, QLineEdit, QHBoxLayout, QMessageBox)
from PyQt6.QtGui import QFont
from backend import PEAnalyzer

class PEAnalyzerGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("PE Analyzer")
        self.setGeometry(200, 200, 800, 600)
        
        self.pe_analyzer = None
        
        self.layout = QVBoxLayout()
        
        # Title Label
        self.title_label = QLabel("PE Analyzer Tool")
        self.title_label.setFont(QFont("Arial", 16, QFont.Weight.Bold))
        self.layout.addWidget(self.title_label)
        
        # Load File Button
        self.load_button = QPushButton("Load PE File")
        self.load_button.clicked.connect(self.load_pe_file)
        self.layout.addWidget(self.load_button)
        
        # Header Editing
        self.header_layout = QHBoxLayout()
        self.header_field = QLineEdit()
        self.header_field.setPlaceholderText("Enter header field (e.g., Machine)")
        self.header_value = QLineEdit()
        self.header_value.setPlaceholderText("Enter new value (hex)")
        self.edit_header_button = QPushButton("Edit Header")
        self.edit_header_button.clicked.connect(self.edit_header)
        
        self.header_layout.addWidget(self.header_field)
        self.header_layout.addWidget(self.header_value)
        self.header_layout.addWidget(self.edit_header_button)
        
        self.layout.addLayout(self.header_layout)
        
        # Text Area for Displaying Results
        self.text_area = QTextEdit()
        self.text_area.setReadOnly(True)
        self.text_area.setFont(QFont("Courier", 10))
        self.layout.addWidget(self.text_area)
        
        # Save Report Button
        self.save_report_button = QPushButton("Save Report")
        self.save_report_button.clicked.connect(self.save_report)
        self.layout.addWidget(self.save_report_button)
        
        # Save Modified PE File Button
        self.save_pe_button = QPushButton("Save Modified PE File")
        self.save_pe_button.clicked.connect(self.save_modified_pe)
        self.layout.addWidget(self.save_pe_button)
        
        container = QWidget()
        container.setLayout(self.layout)
        self.setCentralWidget(container)
    
    def load_pe_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Open PE File", "", "Executable Files (*.exe *.dll)")
        if file_path:
            self.pe_analyzer = PEAnalyzer(file_path)
            self.pe_analyzer.load_file()
            
            headers = self.pe_analyzer.get_headers()
            sections = self.pe_analyzer.get_sections()
            imports = self.pe_analyzer.get_imports()
            file_hash = self.pe_analyzer.calculate_hash()
            risk_score = self.pe_analyzer.calculate_risk_score()
            
            result = f"<b>File:</b> {file_path}<br><br>"
            result += f"<b>Headers:</b><br>{headers}<br><br>"
            result += f"<b>Sections:</b><br>{sections}<br><br>"
            result += f"<b>MD5 Hash:</b> {file_hash}<br><br>"
            result += f"<b>Imported APIs:</b><br>{imports}<br><br>"
            result += f"<b>Risk Score:</b> {risk_score['score']}<br>"
            result += f"<b>Suspicious APIs:</b> {risk_score['suspicious_apis']}<br>"
            
            self.text_area.setHtml(result)
    
    def edit_header(self):
        if not self.pe_analyzer:
            QMessageBox.warning(self, "Error", "No PE file loaded.")
            return
        
        field = self.header_field.text().strip()
        value = self.header_value.text().strip()
        if field and value:
            result = self.pe_analyzer.edit_header(field, value)
            QMessageBox.information(self, "Header Edit", result)
        else:
            QMessageBox.warning(self, "Input Error", "Please provide a valid field and value.")
    
    def save_report(self):
        if not self.pe_analyzer:
            QMessageBox.warning(self, "Error", "No PE file loaded.")
            return
        
        analysis_results = {
            "headers": self.pe_analyzer.get_headers(),
            "sections": self.pe_analyzer.get_sections(),
            "imports": self.pe_analyzer.get_imports(),
            "hash": self.pe_analyzer.calculate_hash(),
            "risk_score": self.pe_analyzer.calculate_risk_score()
        }
        
        message = self.pe_analyzer.save_results(analysis_results)
        QMessageBox.information(self, "Save Report", message)
    
    def save_modified_pe(self):
        if not self.pe_analyzer:
            QMessageBox.warning(self, "Error", "No PE file loaded.")
            return
        
        new_file_path, _ = QFileDialog.getSaveFileName(self, "Save Modified PE", "", "Executable Files (*.exe *.dll)")
        if new_file_path:
            message = self.pe_analyzer.save_modified_pe(new_file_path)
            QMessageBox.information(self, "Save PE File", message)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = PEAnalyzerGUI()
    window.show()
    sys.exit(app.exec())
