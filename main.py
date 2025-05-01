import sys
import os
import re
from PyQt6.QtWidgets import (QApplication, QMainWindow, QPushButton, QFileDialog, 
                             QTextEdit, QVBoxLayout, QWidget, QLabel, QTabWidget, 
                             QTableWidget, QTableWidgetItem, QMessageBox, QTreeWidget, 
                             QTreeWidgetItem, QInputDialog, QDialog, QFormLayout, QLineEdit,
                             QHBoxLayout, QProgressBar, QMenu)
from PyQt6.QtGui import QFont, QColor
from PyQt6.QtCore import Qt
from backend import PEAnalyzer

class HeaderEditDialog(QDialog):
    VALIDATION_RULES = {
        'e_magic': (r'^0x5a4d$', "Must be 0x5A4D (MZ)"),
        'e_lfanew': (r'^0x[0-9a-fA-F]{4,8}$', "Invalid PE offset"),
        'Machine': (r'^0x[0-9a-fA-F]{4}$', "Must be 2-byte hex value"),
        'Characteristics': (r'^0x[0-9a-fA-F]{4}$', "Invalid characteristics flags")
    }

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

    def accept(self):
        # Validate inputs before accepting
        errors = []
        for key, input_field in self.header_inputs.items():
            _, field = key.split('_', 1)
            value = input_field.text()
            
            if field in self.VALIDATION_RULES:
                regex, msg = self.VALIDATION_RULES[field]
                if not re.match(regex, value):
                    errors.append(f"{field}: {msg}")
        
        if errors:
            QMessageBox.warning(self, "Validation Error", "\n".join(errors))
        else:
            super().accept()

class SectionEditDialog(QDialog):
    def __init__(self, section_name, section_data, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"Edit Section: {section_name}")
        self.section_name = section_name
        self.section_data = section_data
        
        self.layout = QFormLayout()
        
        # Create input fields for each section property
        self.field_inputs = {}
        for field, value in section_data.items():
            input_field = QLineEdit(str(value))
            self.layout.addRow(f"{field}:", input_field)
            self.field_inputs[field] = input_field
        
        # Add buttons
        button_layout = QHBoxLayout()
        self.save_button = QPushButton("Save Changes")
        self.save_button.clicked.connect(self.accept)
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.clicked.connect(self.reject)
        
        button_layout.addWidget(self.save_button)
        button_layout.addWidget(self.cancel_button)
        
        self.layout.addRow("", button_layout)
        self.setLayout(self.layout)
    
    def get_edited_values(self):
        edited_values = {}
        for field, input_field in self.field_inputs.items():
            edited_values[field] = input_field.text()
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
        
        # Edit Sections Button
        self.edit_sections_button = QPushButton("Edit Selected Section")
        self.edit_sections_button.clicked.connect(self.edit_selected_section)
        action_layout.addWidget(self.edit_sections_button)
        
        # Report Buttons
        report_layout = QHBoxLayout()
        self.save_report_button = QPushButton("Save Risk Report")
        self.save_report_button.clicked.connect(self.save_risk_report)
        self.export_strings_button = QPushButton("Export Strings Report")
        self.export_strings_button.clicked.connect(self.export_strings_report)
        report_layout.addWidget(self.save_report_button)
        report_layout.addWidget(self.export_strings_button)
        action_layout.addLayout(report_layout)
        
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
        self.toggle_buttons(False)

    def toggle_buttons(self, enabled):
        self.edit_headers_button.setEnabled(enabled)
        self.edit_sections_button.setEnabled(enabled)
        self.save_report_button.setEnabled(enabled)
        self.export_strings_button.setEnabled(enabled)
        self.save_modified_pe_button.setEnabled(enabled)
    
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
        self.sections_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.sections_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.sections_table.customContextMenuRequested.connect(self.show_section_context_menu)
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
        self.strings_tree = QTreeWidget()
        self.strings_tree.setHeaderLabels(["Category", "String"])
        self.strings_search = QLineEdit()
        self.strings_search.setPlaceholderText("Search strings...")
        self.strings_search.textChanged.connect(self.filter_strings)
        layout.addWidget(self.strings_search)
        layout.addWidget(self.strings_tree)
        self.strings_tab.setLayout(layout)
    
    def setup_risk_tab(self):
        layout = QVBoxLayout()
        self.risk_tree = QTreeWidget()
        self.risk_tree.setHeaderLabels(["Risk Category", "Details"])
        
        self.risk_score_label = QLabel("Risk Score: N/A")
        self.risk_score_label.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        
        self.risk_progress = QProgressBar()
        self.risk_progress.setRange(0, 100)
        self.risk_progress.setTextVisible(True)
        
        layout.addWidget(self.risk_score_label)
        layout.addWidget(self.risk_progress)
        layout.addWidget(self.risk_tree)
        self.risk_tab.setLayout(layout)
    
    def load_pe_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Open PE File", "", "Executable Files (*.exe *.dll)")
        if file_path:
            self.pe_analyzer = PEAnalyzer(file_path)
            load_result = self.pe_analyzer.load_file()
            
            if load_result is True:
                self.toggle_buttons(True)
                self.populate_headers()
                self.populate_sections()
                self.populate_imports()
                self.populate_strings()
                self.populate_risk_assessment()
            else:
                QMessageBox.warning(self, "Error", str(load_result))
                self.toggle_buttons(False)
    
    def populate_headers(self):
        self.headers_tree.clear()
        headers = self.pe_analyzer.get_headers()
        
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
        risky_apis = self.pe_analyzer.RISKY_APIS.keys()

        for dll, funcs in imports.items():
            dll_item = QTreeWidgetItem(self.imports_tree, [dll, "", ""])
            for func in funcs:
                item = QTreeWidgetItem(dll_item, ["", func['name'], func['address']])
                if func['name'] in risky_apis:
                    item.setForeground(1, QColor(255, 0, 0))
                    item.setToolTip(1, f"Risk score: {self.pe_analyzer.RISKY_APIS[func['name']]}")
    
    def populate_strings(self):
        self.strings_tree.clear()
        categorized_strings = self.pe_analyzer.get_strings(categorize=True)
        
        if isinstance(categorized_strings, dict):
            for category, strings in categorized_strings.items():
                category_item = QTreeWidgetItem(self.strings_tree, [category.upper()])
                for s in strings:
                    QTreeWidgetItem(category_item, ["", s])
            self.strings_tree.expandAll()
        else:
            QTreeWidgetItem(self.strings_tree, ["ERROR", categorized_strings])
    
    def filter_strings(self):
        search_text = self.strings_search.text().lower()
        for top_index in range(self.strings_tree.topLevelItemCount()):
            top_item = self.strings_tree.topLevelItem(top_index)
            for child_index in range(top_item.childCount()):
                child = top_item.child(child_index)
                child.setHidden(search_text not in child.text(1).lower())
    
    def populate_risk_assessment(self):
        risk_assessment = self.pe_analyzer.calculate_risk_score()
        score = risk_assessment['score']
        
        # Update progress bar
        self.risk_progress.setValue(score)
        self.risk_progress.setFormat(f"Risk Level: {score}%")
        self.risk_progress.setStyleSheet(f"""
            QProgressBar::chunk {{
                background-color: {self.get_risk_color(score)};
            }}
        """)
        
        # Update label
        self.risk_score_label.setText(f"Risk Score: {score}/100")
        self.risk_score_label.setStyleSheet(
            f"color: {self.get_risk_color(score)}"
        )
        
        # Populate details
        self.risk_tree.clear()
        details = risk_assessment['details']
        
        apis_item = QTreeWidgetItem(self.risk_tree, ["Suspicious APIs"])
        for api in details.get('risky_apis', []):
            QTreeWidgetItem(apis_item, [api])
        
        strings_item = QTreeWidgetItem(self.risk_tree, ["Suspicious Strings"])
        for string in details.get('suspicious_strings', []):
            QTreeWidgetItem(strings_item, [string])
    
    def get_risk_color(self, score):
        if score < 30: return 'green'
        elif score < 60: return 'orange'
        else: return 'red'
    
    def show_section_context_menu(self, pos):
        menu = QMenu()
        hex_view_action = menu.addAction("View Hex Characteristics")
        hex_view_action.triggered.connect(self.view_section_hex)
        menu.exec(self.sections_table.viewport().mapToGlobal(pos))
    
    def view_section_hex(self):
        selected = self.sections_table.selectedItems()
        if selected:
            section_name = selected[0].text()
            sections = self.pe_analyzer.get_sections()
            characteristics = sections[section_name]['Characteristics']
            QMessageBox.information(self, "Section Characteristics", 
                                  f"Hex: {characteristics}\nDec: {int(characteristics, 16)}")
    
    def edit_headers(self):
        if not self.pe_analyzer:
            QMessageBox.warning(self, "Error", "No PE file loaded.")
            return
        
        headers = self.pe_analyzer.get_headers()
        edit_dialog = HeaderEditDialog(headers, self)
        
        if edit_dialog.exec() == QDialog.DialogCode.Accepted:
            edited_values = edit_dialog.get_edited_values()
            for header_type, fields in edited_values.items():
                for field, value in fields.items():
                    result = self.pe_analyzer.edit_header(header_type, field, value)
                    if "Error" in result:
                        QMessageBox.warning(self, "Edit Error", result)
            self.populate_headers()
    
    def edit_selected_section(self):
        if not self.pe_analyzer:
            QMessageBox.warning(self, "Error", "No PE file loaded.")
            return
        
        selected_rows = self.sections_table.selectionModel().selectedRows()
        if not selected_rows:
            QMessageBox.warning(self, "Error", "No section selected.")
            return
        
        row_index = selected_rows[0].row()
        section_name = self.sections_table.item(row_index, 0).text()
        sections = self.pe_analyzer.get_sections()
        
        if section_name not in sections:
            QMessageBox.warning(self, "Error", f"Section '{section_name}' not found.")
            return
        
        edit_dialog = SectionEditDialog(section_name, sections[section_name], self)
        if edit_dialog.exec() == QDialog.DialogCode.Accepted:
            edited_values = edit_dialog.get_edited_values()
            for field, value in edited_values.items():
                result = self.pe_analyzer.edit_section(section_name, field, value)
                if "Error" in result:
                    QMessageBox.warning(self, "Edit Error", result)
            self.populate_sections()
    
    def save_risk_report(self):
        if not self.pe_analyzer:
            QMessageBox.warning(self, "Error", "No PE file loaded.")
            return
        
        try:
            report_path = self.pe_analyzer.save_risk_report()
            QMessageBox.information(self, "Report Saved", f"Risk report saved in results folder:\n{report_path}")
        except Exception as e:
            QMessageBox.warning(self, "Error", str(e))
    
    def export_strings_report(self):
        if not self.pe_analyzer:
            QMessageBox.warning(self, "Error", "No PE file loaded.")
            return
        
        try:
            report_path = self.pe_analyzer.save_strings_report()
            QMessageBox.information(self, "Report Saved", f"Strings report saved in results folder:\n{report_path}")
        except Exception as e:
            QMessageBox.warning(self, "Error", str(e))
    
    def save_modified_pe(self):
        if not self.pe_analyzer:
            QMessageBox.warning(self, "Error", "No PE file loaded.")
            return
        
        new_file_path, _ = QFileDialog.getSaveFileName(
            self, "Save Modified PE File", "", "Executable Files (*.exe *.dll)"
        )
        
        if new_file_path:
            try:
                result = self.pe_analyzer.save_modified_pe(new_file_path)
                QMessageBox.information(self, "PE File Saved", result)
            except Exception as e:
                QMessageBox.warning(self, "Error", str(e))

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = PEAnalyzerGUI()
    window.show()
    sys.exit(app.exec())