import sys
import os
from PyQt6.QtWidgets import (QApplication, QMainWindow, QPushButton, QFileDialog, 
                             QTextEdit, QVBoxLayout, QWidget, QLabel, QTabWidget, 
                             QTableWidget, QTableWidgetItem, QMessageBox, QTreeWidget, 
                             QTreeWidgetItem, QInputDialog, QDialog, QFormLayout, QLineEdit)
from PyQt6.QtGui import QFont
from PyQt6.QtCore import Qt
from backend import PEAnalyzer

class HeaderEditDialog(QDialog):
    def __init__(self, headers, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Edit Headers")
        self.headers = headers
        self.layout = QFormLayout()
        
        # Create input fields for each header
        self.header_inputs = {}
        for header_type, fields in headers.items():
            for field, value in fields.items():
                input_field = QLineEdit(str(value))
                self.layout.addRow(f"{header_type} - {field}", input_field)
                self.header_inputs[f"{header_type}_{field}"] = input_field
        
        # Add buttons
        self.save_button = QPushButton("Save Changes")
        self.save_button.clicked.connect(self.accept)
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.clicked.connect(self.reject)
        
        self.layout.addRow(self.save_button, self.cancel_button)
        self.setLayout(self.layout)
    
    def get_edited_values(self):
        edited_values = {}
        for key, input_field in self.header_inputs.items():
            header_type, field = key.split('_', 1)
            edited_values[header_type] = {field: input_field.text()}
        return edited_values

class PEAnalyzerGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Advanced PE Analyzer")
        self.setGeometry(100, 100, 1000, 800)
        
        self.pe_analyzer = None
        
        # Main layout
        main_layout = QVBoxLayout()
        
        # Load File Button
        self.load_button = QPushButton("Load PE File")
        self.load_button.clicked.connect(self.load_pe_file)
        main_layout.addWidget(self.load_button)
        
        # Tabbed Interface
        self.tab_widget = QTabWidget()
        
        # Tabs
        self.headers_tab = QWidget()
        self.sections_tab = QWidget()
        self.imports_tab = QWidget()
        self.strings_tab = QWidget()
        self.risk_tab = QWidget()
        
        # Setup tabs
        self.setup_headers_tab()
        self.setup_sections_tab()
        self.setup_imports_tab()
        self.setup_strings_tab()
        self.setup_risk_tab()
        
        # Add tabs
        self.tab_widget.addTab(self.headers_tab, "Headers")
        self.tab_widget.addTab(self.sections_tab, "Sections")
        self.tab_widget.addTab(self.imports_tab, "Imports")
        self.tab_widget.addTab(self.strings_tab, "Strings")
        self.tab_widget.addTab(self.risk_tab, "Risk Assessment")
        
        main_layout.addWidget(self.tab_widget)
        
        # Action Buttons
        action_layout = QVBoxLayout()
        
        # Edit Headers Button
        self.edit_headers_button = QPushButton("Edit Headers")
        self.edit_headers_button.clicked.connect(self.edit_headers)
        action_layout.addWidget(self.edit_headers_button)
        
        # Save Report Button
        self.save_report_button = QPushButton("Save Risk Report")
        self.save_report_button.clicked.connect(self.save_risk_report)
        action_layout.addWidget(self.save_report_button)
        
        # Save Modified PE Button
        self.save_modified_pe_button = QPushButton("Save Modified PE")
        self.save_modified_pe_button.clicked.connect(self.save_modified_pe)
        action_layout.addWidget(self.save_modified_pe_button)
        
        main_layout.addLayout(action_layout)
        
        # Set up main container
        container = QWidget()
        container.setLayout(main_layout)
        self.setCentralWidget(container)
        
        # Initially disable buttons
        self.edit_headers_button.setEnabled(False)
        self.save_report_button.setEnabled(False)
        self.save_modified_pe_button.setEnabled(False)
    
    def setup_headers_tab(self):
        layout = QVBoxLayout()
        self.headers_tree = QTreeWidget()
        self.headers_tree.setHeaderLabels(["Property", "Value"])
        layout.addWidget(self.headers_tree)
        self.headers_tab.setLayout(layout)
    
    def setup_sections_tab(self):
        layout = QVBoxLayout()
        self.sections_table = QTableWidget()
        self.sections_table.setColumnCount(4)
        self.sections_table.setHorizontalHeaderLabels(["Section", "Virtual Size", "Virtual Address", "Raw Size"])
        layout.addWidget(self.sections_table)
        self.sections_tab.setLayout(layout)
    
    def setup_imports_tab(self):
        layout = QVBoxLayout()
        self.imports_tree = QTreeWidget()
        self.imports_tree.setHeaderLabels(["DLL", "Function", "Address"])
        layout.addWidget(self.imports_tree)
        self.imports_tab.setLayout(layout)
    
    def setup_strings_tab(self):
        layout = QVBoxLayout()
        self.strings_text = QTextEdit()
        self.strings_text.setReadOnly(True)
        layout.addWidget(self.strings_text)
        self.strings_tab.setLayout(layout)
    
    def setup_risk_tab(self):
        layout = QVBoxLayout()
        self.risk_tree = QTreeWidget()
        self.risk_tree.setHeaderLabels(["Risk Category", "Details"])
        
        self.risk_score_label = QLabel("Risk Score: N/A")
        self.risk_score_label.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        layout.addWidget(self.risk_score_label)
        layout.addWidget(self.risk_tree)
        self.risk_tab.setLayout(layout)
    
    def load_pe_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Open PE File", "", "Executable Files (*.exe *.dll)")
        if file_path:
            self.pe_analyzer = PEAnalyzer(file_path)
            load_result = self.pe_analyzer.load_file()
            
            if load_result is True:
                # Enable buttons
                self.edit_headers_button.setEnabled(True)
                self.save_report_button.setEnabled(True)
                self.save_modified_pe_button.setEnabled(True)
                
                # Populate tabs
                self.populate_headers()
                self.populate_sections()
                self.populate_imports()
                self.populate_strings()
                self.populate_risk_assessment()
            else:
                QMessageBox.warning(self, "Error", str(load_result))
    
    def populate_headers(self):
        self.headers_tree.clear()
        headers = self.pe_analyzer.get_headers()
        
        # Recursively add headers to tree
        def add_headers(parent, headers_dict):
            for key, value in headers_dict.items():
                if isinstance(value, dict):
                    item = QTreeWidgetItem(parent, [key, ""])
                    add_headers(item, value)
                else:
                    QTreeWidgetItem(parent, [key, str(value)])
        
        add_headers(self.headers_tree.invisibleRootItem(), headers)
        self.headers_tree.expandAll()
    
    def populate_sections(self):
        sections = self.pe_analyzer.get_sections()
        self.sections_table.setRowCount(len(sections))
        
        for row, (name, details) in enumerate(sections.items()):
            self.sections_table.setItem(row, 0, QTableWidgetItem(name))
            self.sections_table.setItem(row, 1, QTableWidgetItem(details['Virtual Size']))
            self.sections_table.setItem(row, 2, QTableWidgetItem(details['Virtual Address']))
            self.sections_table.setItem(row, 3, QTableWidgetItem(details['Raw Size']))
    
    def populate_imports(self):
        self.imports_tree.clear()
        imports = self.pe_analyzer.get_imports()
        
        for dll, funcs in imports.items():
            dll_item = QTreeWidgetItem(self.imports_tree, [dll, "", ""])
            for func in funcs:
                QTreeWidgetItem(dll_item, [
                    "", 
                    func['name'], 
                    func['address']
                ])
    
    def populate_strings(self):
        strings = self.pe_analyzer.get_strings()
        self.strings_text.setText('\n'.join(strings))
    
    def populate_risk_assessment(self):
        risk_assessment = self.pe_analyzer.calculate_risk_score()
        
        # Update risk score label
        self.risk_score_label.setText(f"Risk Score: {risk_assessment['score']}/100")
        self.risk_score_label.setStyleSheet(
            f"color: {'red' if risk_assessment['score'] > 50 else 'green'}"
        )
        
        # Populate risk details
        self.risk_tree.clear()
        details = risk_assessment['details']
        
        # Risky APIs
        apis_item = QTreeWidgetItem(self.risk_tree, ["Suspicious APIs"])
        for api in details.get('risky_apis', []):
            QTreeWidgetItem(apis_item, [api])
        
        # Suspicious Strings
        strings_item = QTreeWidgetItem(self.risk_tree, ["Suspicious Strings"])
        for string in details.get('suspicious_strings', []):
            QTreeWidgetItem(strings_item, [string])
    
    def edit_headers(self):
        if not self.pe_analyzer:
            QMessageBox.warning(self, "Error", "No PE file loaded.")
            return
        
        # Get current headers
        headers = self.pe_analyzer.get_headers()
        
        # Open edit dialog
        edit_dialog = HeaderEditDialog(headers, self)
        
        if edit_dialog.exec() == QDialog.DialogCode.Accepted:
            # Get edited values
            edited_values = edit_dialog.get_edited_values()
            
            # Apply changes
            for header_type, fields in edited_values.items():
                for field, value in fields.items():
                    result = self.pe_analyzer.edit_header(header_type, field, value)
                    if "Error" in result:
                        QMessageBox.warning(self, "Edit Error", result)
            
            # Refresh headers
            self.populate_headers()
    
    def save_risk_report(self):
        if not self.pe_analyzer:
            QMessageBox.warning(self, "Error", "No PE file loaded.")
            return
        
        try:
            report_path = self.pe_analyzer.save_risk_report()
            QMessageBox.information(
                self, "Report Saved", 
                f"Risk report saved in results folder:\n{report_path}"
            )
        except Exception as e:
            QMessageBox.warning(self, "Error", str(e))
    
    def save_modified_pe(self):
        if not self.pe_analyzer:
            QMessageBox.warning(self, "Error", "No PE file loaded.")
            return
        
        # Open file dialog to choose save location
        new_file_path, _ = QFileDialog.getSaveFileName(
            self, 
            "Save Modified PE File", 
            "", 
            "Executable Files (*.exe *.dll)"
        )
        
        if new_file_path:
            try:
                result = self.pe_analyzer.save_modified_pe(new_file_path)
                QMessageBox.information(
                    self, "PE File Saved", 
                    result
                )
            except Exception as e:
                QMessageBox.warning(self, "Error", str(e))

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = PEAnalyzerGUI()
    window.show()
    sys.exit(app.exec())