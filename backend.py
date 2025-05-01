import pefile
import hashlib
import json
import os
import re

class PEAnalyzer:
    # Dictionary of potentially risky Windows APIs with risk scores and descriptions
    RISKY_APIS = {
        # Memory manipulation APIs
        "VirtualAlloc": {"score": 5, "description": "Allocates memory in the virtual address space of the calling process"},
        "VirtualProtect": {"score": 4, "description": "Changes the protection on a region of committed pages in the virtual address space"},
        "WriteProcessMemory": {"score": 7, "description": "Writes data to an area of memory in a specified process"},
        "ReadProcessMemory": {"score": 6, "description": "Reads data from an area of memory in a specified process"},
        
        # Process/Thread manipulation
        "CreateRemoteThread": {"score": 8, "description": "Creates a thread that runs in the virtual address space of another process"},
        "OpenProcess": {"score": 6, "description": "Opens an existing local process object"},
        "CreateProcess": {"score": 5, "description": "Creates a new process and its primary thread"},
        "TerminateProcess": {"score": 4, "description": "Terminates the specified process and all of its threads"},
        
        # DLL/Module manipulation
        "LoadLibrary": {"score": 4, "description": "Loads the specified module into the address space of the calling process"},
        "GetProcAddress": {"score": 5, "description": "Retrieves the address of an exported function or variable from the specified DLL"},
        "GetModuleHandle": {"score": 3, "description": "Retrieves a module handle for the specified module"},
        
        # File system operations
        "CreateFile": {"score": 4, "description": "Creates or opens a file or I/O device"},
        "WriteFile": {"score": 4, "description": "Writes data to the specified file or input/output (I/O) device"},
        "ReadFile": {"score": 3, "description": "Reads data from the specified file or input/output (I/O) device"},
        
        # Network operations
        "URLDownloadToFile": {"score": 7, "description": "Downloads a file from the Internet"},
        "InternetOpenUrl": {"score": 6, "description": "Opens a resource specified by a complete FTP or HTTP URL"},
        "WSAStartup": {"score": 3, "description": "Initiates use of the Winsock DLL by a process"},
        "connect": {"score": 4, "description": "Establishes a connection to a specified socket"},
        
        # System manipulation
        "ShellExecute": {"score": 5, "description": "Performs an operation on a specified file"},
        "WinExec": {"score": 5, "description": "Runs the specified application"},
        "CreateMutex": {"score": 3, "description": "Creates or opens a named or unnamed mutex object"},
        "SetWindowsHookEx": {"score": 7, "description": "Installs an application-defined hook procedure into a hook chain"},
        "RegisterHotKey": {"score": 3, "description": "Defines a system-wide hot key"},
        
        # Registry operations
        "RegCreateKey": {"score": 4, "description": "Creates the specified registry key"},
        "RegSetValue": {"score": 4, "description": "Sets the data for the specified value in the specified registry key"},
        "RegOpenKey": {"score": 3, "description": "Opens the specified registry key"},
        
        # Anti-debugging/anti-analysis
        "IsDebuggerPresent": {"score": 6, "description": "Determines whether the calling process is being debugged"},
        "CheckRemoteDebuggerPresent": {"score": 6, "description": "Determines whether the specified process is being debugged"},
        "OutputDebugString": {"score": 3, "description": "Sends a string to the debugger for display"}
    }

    def __init__(self, file_path):
        self.file_path = file_path
        self.pe = None
        self.results_folder = "results"
        
        # Create results folder if it doesn't exist
        if not os.path.exists(self.results_folder):
            os.makedirs(self.results_folder)

    def load_file(self):
        """Loads the PE file with minimal validation."""
        try:
            # Load PE file with minimal validation
            self.pe = pefile.PE(self.file_path, fast_load=True)
            # Parse directories we need
            self.pe.parse_data_directories([
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'],
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']
            ])
            return True
        except Exception as e:
            return f"Error loading file: {str(e)}"

    def get_headers(self):
        """Get headers with minimal processing."""
        if not self.pe:
            return "PE file not loaded."

        try:
            headers = {
                "DOS Header": {
                    "e_magic": hex(self.pe.DOS_HEADER.e_magic),
                    "e_lfanew": hex(self.pe.DOS_HEADER.e_lfanew)
                },
                "File Header": {
                    "Machine": hex(self.pe.FILE_HEADER.Machine),
                    "NumberOfSections": self.pe.FILE_HEADER.NumberOfSections,
                    "TimeDateStamp": self.pe.FILE_HEADER.TimeDateStamp,
                    "Characteristics": hex(self.pe.FILE_HEADER.Characteristics)
                },
                "Optional Header": {
                    "Magic": hex(self.pe.OPTIONAL_HEADER.Magic),
                    "MajorLinkerVersion": self.pe.OPTIONAL_HEADER.MajorLinkerVersion,
                    "MinorLinkerVersion": self.pe.OPTIONAL_HEADER.MinorLinkerVersion,
                    "SizeOfCode": self.pe.OPTIONAL_HEADER.SizeOfCode,
                    "AddressOfEntryPoint": hex(self.pe.OPTIONAL_HEADER.AddressOfEntryPoint)
                }
            }
            return headers
        except Exception as e:
            return {"Error": str(e)}

    def edit_header(self, header_type, field, value):
        """Edit header fields and update PE file."""
        try:
            # Convert value to appropriate type
            if isinstance(value, str):
                if value.startswith('0x'):
                    value = int(value, 16)
                else:
                    value = int(value)

            # Get header object
            header_obj = None
            if header_type == "DOS_HEADER":
                header_obj = self.pe.DOS_HEADER
            elif header_type == "FILE_HEADER":
                header_obj = self.pe.FILE_HEADER
            elif header_type == "OPTIONAL_HEADER":
                header_obj = self.pe.OPTIONAL_HEADER

            if not header_obj:
                return f"Invalid header type: {header_type}"

            # Set the value and force PE update
            setattr(header_obj, field, value)
            self.pe.__data__ = self.pe.__data__  # Force update of PE structure
            
            return f"Updated {header_type}.{field}"

        except Exception as e:
            return f"Error modifying header: {str(e)}"

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
        """Edit section attributes without restrictions."""
        try:
            # Find the section
            target_section = None
            for section in self.pe.sections:
                if section.Name.decode().strip('\x00') == section_name:
                    target_section = section
                    break
            
            if not target_section:
                return f"Section {section_name} not found"

            # Convert value to appropriate type
            if isinstance(value, str):
                if value.startswith('0x'):
                    value = int(value, 16)
                else:
                    value = int(value)

            # Set new value without validation
            setattr(target_section, field, value)
            return f"Updated section {section_name}.{field}"

        except Exception as e:
            return f"Error modifying section: {str(e)}"

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
        """Generates a comprehensive risk score based on imported APIs and suspicious strings."""
        imports = self.get_imports()
        strings = self.get_strings()
        
        if isinstance(imports, str) or isinstance(strings, str):
            return {"score": 0, "details": "Unable to analyze"}
        
        risk_score = 0
        suspicious_elements = {
            "risky_apis": [],
            "suspicious_strings": [],
            "api_details": {}
        }
        
        # Check imported APIs
        for dll, funcs in imports.items():
            for func in funcs:
                func_name = func['name']
                if func_name in self.RISKY_APIS:
                    api_info = self.RISKY_APIS[func_name]
                    risk_score += api_info['score']
                    suspicious_elements["risky_apis"].append(func_name)
                    suspicious_elements["api_details"][func_name] = {
                        "risk_score": api_info['score'],
                        "description": api_info['description']
                    }
        
        # Check suspicious strings
        suspicious_patterns = [
            # Anti-analysis
            "debug", "detect", "analysis", "virtual", "vmware", "vbox",
            # Malicious behavior
            "payload", "shellcode", "inject", "hook", "bypass", "exploit",
            # Persistence
            "startup", "registry", "service", "scheduled",
            # Network
            "http", "ftp", "socket", "connect", "download",
            # File operations
            "delete", "modify", "overwrite", "encrypt", "decrypt",
            # System manipulation
            "elevate", "privilege", "admin", "system"
        ]
        
        for string in strings:
            for pattern in suspicious_patterns:
                if pattern in string.lower():
                    risk_score += 2
                    suspicious_elements["suspicious_strings"].append(string)
                    break
        
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
        """Saves the modified PE file."""
        try:
            # Write the modified file without validation
            self.pe.write(filename=new_file_path)
            return f"Successfully saved modified PE file"
        except Exception as e:
            return f"Error saving file: {str(e)}"