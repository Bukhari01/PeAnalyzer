import pefile
import hashlib
import json
import os

class PEAnalyzer:
    RISKY_APIS = {
        "VirtualAlloc": 3,
        "WriteProcessMemory": 5,
        "CreateRemoteThread": 7,
        "LoadLibrary": 3,
        "GetProcAddress": 4
    }

    def __init__(self, file_path):
        self.file_path = file_path
        self.pe = None

    def load_file(self):
        """Loads the PE file."""
        try:
            self.pe = pefile.PE(self.file_path)
            return True
        except Exception as e:
            return f"Error loading file: {e}"

    def get_headers(self):
        """Extracts PE headers."""
        if not self.pe:
            return "PE file not loaded."

        headers = {
            "Machine": hex(self.pe.FILE_HEADER.Machine),
            "Number of Sections": self.pe.FILE_HEADER.NumberOfSections,
            "Time Date Stamp": hex(self.pe.FILE_HEADER.TimeDateStamp),
            "Characteristics": hex(self.pe.FILE_HEADER.Characteristics)
        }
        return headers

    def edit_header(self, field, value):
        """Edits a PE header field."""
        if not self.pe:
            return "PE file not loaded."

        try:
            if hasattr(self.pe.FILE_HEADER, field):
                setattr(self.pe.FILE_HEADER, field, int(value, 16))
                return f"Updated {field} to {value}"
            else:
                return f"Invalid field: {field}"
        except Exception as e:
            return f"Error modifying header: {e}"

    def get_sections(self):
        """Extracts sections in the PE file."""
        if not self.pe:
            return "PE file not loaded."

        sections = {}
        for section in self.pe.sections:
            sections[section.Name.decode().strip('\x00')] = {
                "Virtual Size": hex(section.Misc_VirtualSize),
                "Virtual Address": hex(section.VirtualAddress),
                "Raw Size": hex(section.SizeOfRawData)
            }
        return sections

    def get_imports(self):
        """Extracts imported APIs."""
        if not self.pe:
            return "PE file not loaded."

        imports = {}
        try:
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode()
                imports[dll_name] = [imp.name.decode() for imp in entry.imports if imp.name]
        except AttributeError:
            return "No imported APIs found."
        return imports

    def calculate_hash(self):
        """Calculates MD5 hash of the file."""
        try:
            with open(self.file_path, "rb") as f:
                file_hash = hashlib.md5(f.read()).hexdigest()
            return file_hash
        except Exception as e:
            return f"Error calculating hash: {e}"

    def calculate_risk_score(self):
        """Generates a risk score based on imported APIs."""
        imports = self.get_imports()
        if isinstance(imports, str):  # Check for error message
            return {"score": 0, "suspicious_apis": "No imports found."}
        
        risk_score = 0
        suspicious_apis = []
        
        for dll, functions in imports.items():
            for func in functions:
                if func in self.RISKY_APIS:
                    risk_score += self.RISKY_APIS[func]
                    suspicious_apis.append(func)
        
        return {"score": risk_score, "suspicious_apis": suspicious_apis}

    def save_results(self, analysis_results):
        """Saves the report as <filename>result.json."""
        base_name = os.path.splitext(os.path.basename(self.file_path))[0]
        result_file = f"{base_name}result.json"
        with open(result_file, "w") as f:
            json.dump(analysis_results, f, indent=4)
        return f"Saved report as {result_file}"

    def save_modified_pe(self, new_file_path):
        """Saves modified PE file as a new copy."""
        if not self.pe:
            return "PE file not loaded."
        try:
            self.pe.write(new_file_path)
            return f"Modified PE saved as {new_file_path}"
        except Exception as e:
            return f"Error saving modified PE: {e}"
