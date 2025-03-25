import pefile
import hashlib

class PEAnalyzer:
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

    def calculate_hash(self):
        """Calculates MD5 hash of the file."""
        try:
            with open(self.file_path, "rb") as f:
                file_hash = hashlib.md5(f.read()).hexdigest()
            return file_hash
        except Exception as e:
            return f"Error calculating hash: {e}"


