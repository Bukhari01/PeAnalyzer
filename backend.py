import pefile
import hashlib
import json
import os
import re

class PEAnalyzer:
    RISKY_APIS = {
        "VirtualAlloc": 5,
        "VirtualProtect": 4,
        "WriteProcessMemory": 7,
        "CreateRemoteThread": 8,
        "LoadLibrary": 4,
        "GetProcAddress": 5,
        "OpenProcess": 6,
        "ReadProcessMemory": 6,
        "ShellExecute": 5,
        "WinExec": 5,
        "URLDownloadToFile": 7,
        "InternetOpenUrl": 6,
        "CreateMutex": 3,
        "SetWindowsHookEx": 7,
        "RegisterHotKey": 3
    }

    def __init__(self, file_path):
        self.file_path = file_path
        self.pe = None
        self.results_folder = "results"
        
        # Create results folder if it doesn't exist
        if not os.path.exists(self.results_folder):
            os.makedirs(self.results_folder)

    def load_file(self):
        """Loads the PE file."""
        try:
            self.pe = pefile.PE(self.file_path)
            return True
        except Exception as e:
            return str(e)

    def get_headers(self):
        """Comprehensive header extraction."""
        if not self.pe:
            return "PE file not loaded."

        headers = {
            "DOS Header": {
                "e_magic": hex(self.pe.DOS_HEADER.e_magic),
                "e_lfanew": hex(self.pe.DOS_HEADER.e_lfanew)
            },
            "File Header": {
                "Machine": hex(self.pe.FILE_HEADER.Machine),
                "Number of Sections": self.pe.FILE_HEADER.NumberOfSections,
                "Time Date Stamp": self.pe.FILE_HEADER.TimeDateStamp,
                "Characteristics": hex(self.pe.FILE_HEADER.Characteristics)
            },
            "Optional Header": {
                "Magic": hex(self.pe.OPTIONAL_HEADER.Magic),
                "Major Linker Version": self.pe.OPTIONAL_HEADER.MajorLinkerVersion,
                "Minor Linker Version": self.pe.OPTIONAL_HEADER.MinorLinkerVersion,
                "Size of Code": self.pe.OPTIONAL_HEADER.SizeOfCode,
                "Entry Point": hex(self.pe.OPTIONAL_HEADER.AddressOfEntryPoint)
            }
        }
        return headers

    def edit_header(self, header_type, field, value):
        """Edit specific header fields."""
        if not self.pe:
            return "PE file not loaded."

        try:
            # Convert value to appropriate type (hex or int)
            if value.startswith('0x'):
                value = int(value, 16)
            else:
                value = int(value)

            # Edit DOS Header
            if header_type == "DOS_HEADER":
                if hasattr(self.pe.DOS_HEADER, field):
                    setattr(self.pe.DOS_HEADER, field, value)
                    return f"Updated DOS Header {field}"

            # Edit File Header
            elif header_type == "FILE_HEADER":
                if hasattr(self.pe.FILE_HEADER, field):
                    setattr(self.pe.FILE_HEADER, field, value)
                    return f"Updated File Header {field}"

            # Edit Optional Header
            elif header_type == "OPTIONAL_HEADER":
                if hasattr(self.pe.OPTIONAL_HEADER, field):
                    setattr(self.pe.OPTIONAL_HEADER, field, value)
                    return f"Updated Optional Header {field}"

            return f"Invalid field: {field}"
        except Exception as e:
            return f"Error modifying header: {e}"

    def get_sections(self):
        """Extracts sections with detailed information."""
        if not self.pe:
            return "PE file not loaded."

        sections = {}
        for section in self.pe.sections:
            sections[section.Name.decode().strip('\x00')] = {
                "Virtual Size": hex(section.Misc_VirtualSize),
                "Virtual Address": hex(section.VirtualAddress),
                "Raw Size": hex(section.SizeOfRawData),
                "Characteristics": hex(section.Characteristics)
            }
        return sections

    def edit_section(self, section_name, field, value):
        """Edit specific section attributes."""
        if not self.pe:
            return "PE file not loaded."

        try:
            for section in self.pe.sections:
                decoded_name = section.Name.decode().strip('\x00')
                if decoded_name == section_name:
                    # Convert value to appropriate type
                    if value.startswith('0x'):
                        value = int(value, 16)
                    else:
                        value = int(value)
                    
                    # Edit section attributes
                    if hasattr(section, field):
                        setattr(section, field, value)
                        return f"Updated section {section_name} {field}"
            
            return f"Section {section_name} not found"
        except Exception as e:
            return f"Error modifying section: {e}"

    def get_imports(self):
        """Extracts imported APIs with more details."""
        if not self.pe:
            return "PE file not loaded."

        imports = {}
        try:
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode()
                imports[dll_name] = [
                    {
                        "name": imp.name.decode() if imp.name else "N/A", 
                        "hint": imp.hint,
                        "address": hex(imp.address) if imp.address else "N/A"
                    } 
                    for imp in entry.imports
                ]
        except AttributeError:
            return "No imported APIs found."
        return imports

    def get_strings(self, min_length=4, max_length=100, categorize=True):
        """
        Extracts strings from the file with improved organization and display.
        
        Args:
            min_length (int): Minimum string length to extract
            max_length (int): Maximum string length to extract
            categorize (bool): Whether to categorize strings by type
            
        Returns:
            dict or list: Categorized strings dict if categorize=True, otherwise flat list
        """
        try:
            # Validate parameters
            min_length = int(min_length) if min_length else 4
            max_length = int(max_length) if max_length else 100
            
            # Read the file content
            with open(self.file_path, 'rb') as f:
                content = f.read()
            
            extracted_strings = set()  # Use a set to automatically handle duplicates
            
            # 1. Extract ASCII strings using regex
            ascii_pattern = re.compile(b'[\\x20-\\x7E]{%d,%d}' % (min_length, max_length))
            ascii_matches = ascii_pattern.findall(content)
            
            for match in ascii_matches:
                try:
                    string = match.decode('ascii', errors='ignore')
                    if string and all(c.isprintable() for c in string):
                        extracted_strings.add(string)
                except Exception:
                    continue
            
            # 2. Extract UTF-16 (wide char) strings - common in Windows executables
            i = 0
            current_unicode = ""
            
            while i < len(content) - 1:
                # Check if we have a printable ASCII char followed by a null byte (UTF-16LE pattern)
                if i + 1 < len(content) and 32 <= content[i] <= 126 and content[i+1] == 0:
                    current_unicode += chr(content[i])
                    i += 2  # Skip the pair (char + null)
                else:
                    # End of a potential wide string
                    if len(current_unicode) >= min_length:
                        extracted_strings.add(current_unicode)
                    current_unicode = ""
                    i += 1
            
            # Don't forget the last string if it meets our criteria
            if len(current_unicode) >= min_length:
                extracted_strings.add(current_unicode)
            
            # Convert to list and sort
            result = sorted(list(extracted_strings))
            
            # If not categorizing, just return the sorted list
            if not categorize:
                return result
                
            # Otherwise categorize the strings for better display
            categories = {
                "file_paths": [],
                "imports": [],
                "exports": [],
                "sections": [],
                "error_messages": [],
                "compiler_info": [],
                "urls": [],
                "registry": [],
                "api_functions": [],
                "misc": []
            }
            
            # Define patterns for categorization
            patterns = {
                "file_paths": [r"[\\/][\w\-. ]+[\\/][\w\-. ]+", r"\.[a-zA-Z]{1,4}$", r"^[A-Z]:\\"],
                "imports": [r"^__imp_", r"^Import", r"\.dll$", r"\.so$"],
                "exports": [r"^Export"],
                "sections": [r"^\.[a-zA-Z]+$"],
                "error_messages": [r"error", r"failed", r"invalid", r"cannot", r"unable"],
                "compiler_info": [r"GCC", r"MSVC", r"compile", r"link", r"build"],
                "urls": [r"http", r"www\."],
                "registry": [r"HKEY_", r"registry"]
            }
            
            # Process API functions separately - common Windows API calls
            api_functions = [
                "Virtual", "Create", "Open", "Read", "Write", "Get", "Set", "Alloc", "Free", 
                "Load", "Message", "Registry", "File", "Memory", "Thread", "Process", "Handle"
            ]
            
            # Categorize each string
            for string in result:
                categorized = False
                
                # Check for API functions
                if any(api in string for api in api_functions) and not categorized:
                    categories["api_functions"].append(string)
                    categorized = True
                    
                # Check other categories
                for category, regex_list in patterns.items():
                    if categorized:
                        break
                        
                    for pattern in regex_list:
                        if re.search(pattern, string, re.IGNORECASE):
                            categories[category].append(string)
                            categorized = True
                            break
                
                # If not categorized, put in misc
                if not categorized:
                    categories["misc"].append(string)
            
            # Remove empty categories
            return {k: v for k, v in categories.items() if v}
            
        except Exception as e:
            return {"error": [f"Error extracting strings: {str(e)}"]}

    def save_strings_report(self, min_length=4, max_length=100):
        """
        Saves a formatted strings report to a file.
        
        Args:
            min_length (int): Minimum string length to extract
            max_length (int): Maximum string length to extract
            
        Returns:
            str: Path to the saved report
        """
        strings_data = self.get_strings(min_length, max_length, categorize=True)
        
        # Generate filename based on original file
        base_name = os.path.splitext(os.path.basename(self.file_path))[0]
        report_path = os.path.join(self.results_folder, f"{base_name}_strings_report.txt")
        
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(f"Strings Report for {self.file_path}\n")
            f.write("="*60 + "\n\n")
            
            if "error" in strings_data:
                f.write("ERROR EXTRACTING STRINGS:\n")
                f.write("\n".join(strings_data["error"]))
                return report_path
                
            # Write each category with a nice header
            for category, strings in strings_data.items():
                if strings:  # Only write non-empty categories
                    header = f" {category.replace('_', ' ').upper()} "
                    f.write(f"{header.center(60, '=')}\n")
                    
                    # Format and write the strings
                    for s in sorted(strings):
                        f.write(f"{s}\n")
                        
                    f.write("\n\n")  # Add space between categories
        
        return report_path

    def calculate_risk_score(self):
        """Generates a comprehensive risk score."""
        imports = self.get_imports()
        strings = self.get_strings()
        
        if isinstance(imports, str) or isinstance(strings, str):
            return {"score": 0, "details": "Unable to analyze"}
        
        risk_score = 0
        suspicious_elements = {
            "risky_apis": [],
            "suspicious_strings": []
        }
        
        # Check imported APIs
        for dll, funcs in imports.items():
            for func in funcs:
                func_name = func['name']
                if func_name in self.RISKY_APIS:
                    risk_score += self.RISKY_APIS[func_name]
                    suspicious_elements["risky_apis"].append(func_name)
        
        # Check suspicious strings (customize as needed)
        suspicious_patterns = [
            "decrypt", "payload", "shellcode", 
            "inject", "hook", "bypass", 
            "hidden", "stealth", "persistence"
        ]
        
        for string in strings:
            for pattern in suspicious_patterns:
                if pattern in string.lower():
                    risk_score += 2
                    suspicious_elements["suspicious_strings"].append(string)
        
        return {
            "score": min(risk_score, 100),  # Cap at 100
            "details": suspicious_elements
        }

    def save_risk_report(self):
        """Saves risk assessment report in results folder."""
        risk_assessment = self.calculate_risk_score()
        
        # Generate filename based on original file
        base_name = os.path.splitext(os.path.basename(self.file_path))[0]
        report_path = os.path.join(self.results_folder, f"{base_name}_risk_report.json")
        
        # Save report
        with open(report_path, "w") as f:
            json.dump(risk_assessment, f, indent=4)
        
        return report_path

    def save_modified_pe(self, new_file_path):
        """Saves modified PE file to specified location."""
        if not self.pe:
            return "PE file not loaded."
        
        try:
            self.pe.write(new_file_path)
            return f"Modified PE saved as {new_file_path}"
        except Exception as e:
            return f"Error saving modified PE: {e}"