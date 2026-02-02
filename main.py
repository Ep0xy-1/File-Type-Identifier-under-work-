#!/usr/bin/env python3
"""
File Type Identifier
Identifies file types based on magic bytes (file signatures) and extensions.

Author: Your friendly neighborhood developer
Purpose: Stop getting fooled by renamed files!
""" 

import os
import sys
from pathlib import Path


class FileTypeIdentifier:
    """Identifies file types using magic bytes and file extensions."""

    # This is where the magic happens! Every file type has a unique signature
    # at the beginning - kind of like a fingerprint. We store them here.
    # Fun fact: these are called "magic bytes" because they magically tell us
    # what a file really is, regardless of what someone named it!
    MAGIC_BYTES = {
        # Images - these are the most common ones you'll encounter
        b'\xFF\xD8\xFF': {'type': 'JPEG', 'ext': ['.jpg', '.jpeg']},  # JPEG always starts with this!
        b'\x89PNG\r\n\x1a\n': {'type': 'PNG', 'ext': ['.png']},  # PNG literally says "PNG" in the header
        b'GIF87a': {'type': 'GIF', 'ext': ['.gif']},  # Old school GIF format
        b'GIF89a': {'type': 'GIF', 'ext': ['.gif']},  # Newer GIF format (supports animation)
        b'BM': {'type': 'BMP', 'ext': ['.bmp']},  # Windows bitmap - super simple signature
        b'II*\x00': {'type': 'TIFF', 'ext': ['.tif', '.tiff']},  # TIFF little-endian
        b'MM\x00*': {'type': 'TIFF', 'ext': ['.tif', '.tiff']},  # TIFF big-endian
        b'RIFF': {'type': 'WEBP/AVI', 'ext': ['.webp', '.avi']},  # RIFF container (used by multiple formats)

        # Documents - PDFs and Office files
        b'%PDF': {'type': 'PDF', 'ext': ['.pdf']},  # PDF files literally start with "%PDF"
        b'PK\x03\x04': {'type': 'ZIP/DOCX/XLSX/JAR', 'ext': ['.zip', '.docx', '.xlsx', '.jar', '.apk']},  # Modern Office files are actually ZIP archives!
        b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1': {'type': 'MS Office (old)', 'ext': ['.doc', '.xls', '.ppt']},  # Old school Office files

        # Archives - compressed stuff
        b'\x1f\x8b': {'type': 'GZIP', 'ext': ['.gz']},  # GZIP compression
        b'Rar!\x1a\x07': {'type': 'RAR', 'ext': ['.rar']},  # RAR files say "Rar!" at the start, how polite!
        b'7z\xBC\xAF\x27\x1C': {'type': '7-Zip', 'ext': ['.7z']},  # 7-Zip signature

        # Executables - be careful with these!
        b'MZ': {'type': 'Windows Executable', 'ext': ['.exe', '.dll']},  # Windows executables (named after Mark Zbikowski)
        b'\x7fELF': {'type': 'Linux Executable (ELF)', 'ext': ['']},  # Linux/Unix executables

        # Media files - videos and music
        b'\x00\x00\x00\x18ftypmp42': {'type': 'MP4', 'ext': ['.mp4']},  # MP4 variant 1
        b'\x00\x00\x00\x1cftypmp42': {'type': 'MP4', 'ext': ['.mp4']},  # MP4 variant 2
        b'\x00\x00\x00\x20ftypmp42': {'type': 'MP4', 'ext': ['.mp4']},  # MP4 variant 3
        b'ID3': {'type': 'MP3', 'ext': ['.mp3']},  # MP3 with ID3 tags
        b'\xFF\xFB': {'type': 'MP3', 'ext': ['.mp3']},  # MP3 MPEG-1 Layer 3
        b'\xFF\xF3': {'type': 'MP3', 'ext': ['.mp3']},  # MP3 MPEG-2 Layer 3
        b'\xFF\xF2': {'type': 'MP3', 'ext': ['.mp3']},  # MP3 MPEG-2.5 Layer 3
        b'ftyp': {'type': 'MP4/M4V/MOV', 'ext': ['.mp4', '.m4v', '.mov']},  # Generic MP4 container

        # Special text files with Byte Order Mark (BOM)
        b'\xEF\xBB\xBF': {'type': 'UTF-8 with BOM', 'ext': ['.txt', '.xml', '.html']},  # UTF-8 encoded with BOM
    }

    def __init__(self):
        # Figure out the longest signature we need to read
        # This way we don't read more of the file than necessary
        self.max_signature_length = max(len(sig) for sig in self.MAGIC_BYTES.keys())

    def identify_by_magic_bytes(self, file_path):
        """
        Identify file type by reading magic bytes.
        This is the main detection method - it actually opens the file
        and reads the first few bytes to see what it really is.
        """
        try:
            with open(file_path, 'rb') as f:  # 'rb' means read in binary mode
                # Read just enough bytes to check all our signatures
                header = f.read(self.max_signature_length)

                # Check all known signatures - basically going through our list
                # and seeing if any of them match the beginning of this file
                for signature, info in self.MAGIC_BYTES.items():
                    if header.startswith(signature):
                        return info['type'], info['ext']

                # If we didn't find a match, maybe it's just plain text?
                if self._is_text_file(header):
                    return 'Text File', ['.txt']

                # Welp, we have no idea what this is
                return 'Unknown', []

        except Exception as e:
            # Something went wrong (file locked, permissions, etc.)
            return f'Error: {str(e)}', []

    def _is_text_file(self, data):
        """
        Check if data appears to be text.
        We try to decode it as UTF-8 and check if it contains normal characters.
        This helps us identify plain text files like code, logs, etc.
        """
        try:
            data.decode('utf-8')  # Try to decode as text
            # These are the normal printable characters plus tab, newline, and carriage return
            text_chars = set(range(32, 127)) | {9, 10, 13}
            # Check the first 1024 bytes - if they're all normal characters, it's probably text
            return all(byte in text_chars or byte > 127 for byte in data[:1024])
        except:
            # If decoding fails, it's definitely not text
            return False

    def identify_by_extension(self, file_path):
        """
        Identify file type by extension.
        This is the "trust the file name" approach - less reliable but good for context.
        """
        ext = Path(file_path).suffix.lower()  # Get the extension and make it lowercase

        # Big ol' dictionary of common file extensions
        # Feel free to add more if you work with other file types!
        extension_types = {
            # Programming languages - for the developers out there
            '.py': 'Python Script',
            '.js': 'JavaScript',
            '.java': 'Java Source',
            '.cpp': 'C++ Source',
            '.c': 'C Source',
            '.h': 'C/C++ Header',
            '.html': 'HTML',
            '.css': 'CSS',
            '.json': 'JSON',
            '.xml': 'XML',
            '.sql': 'SQL',
            '.sh': 'Shell Script',
            '.bat': 'Batch File',

            # Documents and text files
            '.txt': 'Text File',
            '.md': 'Markdown',
            '.csv': 'CSV',
            '.log': 'Log File',

            # Image formats
            '.jpg': 'JPEG Image',
            '.jpeg': 'JPEG Image',
            '.png': 'PNG Image',
            '.gif': 'GIF Image',
            '.svg': 'SVG Image',

            # Archive formats
            '.zip': 'ZIP Archive',
            '.tar': 'TAR Archive',
            '.gz': 'GZIP Archive',
            '.rar': 'RAR Archive',

            # Video formats
            '.mp4': 'MP4 Video',
            '.avi': 'AVI Video',
            '.mkv': 'MKV Video',
            '.mov': 'QuickTime Video',
        }

        return extension_types.get(ext, f'Unknown ({ext})')

    def analyze_file(self, file_path):
        """
        Perform complete file analysis.
        This brings everything together - checks magic bytes, extension,
        file size, and looks for any red flags.
        """
        # First, make sure the file actually exists
        if not os.path.exists(file_path):
            return {'error': 'File does not exist'}

        # Get file info
        file_size = os.path.getsize(file_path)
        magic_type, expected_exts = self.identify_by_magic_bytes(file_path)
        ext_type = self.identify_by_extension(file_path)
        actual_ext = Path(file_path).suffix.lower()

        # Package everything up nicely
        result = {
            'file_path': file_path,
            'file_name': os.path.basename(file_path),
            'file_size': file_size,
            'file_size_human': self._format_size(file_size),
            'actual_extension': actual_ext if actual_ext else 'None',
            'type_by_magic': magic_type,
            'type_by_extension': ext_type,
            'expected_extensions': expected_exts,
        }

        # This is the important part - if the extension doesn't match what
        # the magic bytes say, we warn the user. This could be a renamed file!
        if actual_ext and expected_exts:
            if actual_ext not in expected_exts:
                result['warning'] = f'Extension mismatch! File appears to be {magic_type} but has {actual_ext} extension'

        return result

    def _format_size(self, size):
        """
        Format file size in human-readable form.
        Nobody wants to read "45823749 bytes" - we convert to KB, MB, etc.
        """
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024.0:
                return f"{size:.2f} {unit}"
            size /= 1024.0
        return f"{size:.2f} PB"  # If we get here, that's a HUGE file!


def print_analysis(result):
    """
    Print the analysis result in a formatted way.
    Makes the output look nice and professional.
    """
    if 'error' in result:
        print(f"❌ Error: {result['error']}")
        return

    print("=" * 60)
    print(f"File Analysis Report")
    print("=" * 60)
    print(f"File Name:           {result['file_name']}")
    print(f"File Path:           {result['file_path']}")
    print(f"File Size:           {result['file_size_human']} ({result['file_size']} bytes)")
    print(f"Actual Extension:    {result['actual_extension']}")
    print(f"Type (by magic):     {result['type_by_magic']}")
    print(f"Type (by extension): {result['type_by_extension']}")

    if result['expected_extensions']:
        print(f"Expected Extensions: {', '.join(result['expected_extensions'])}")

    # This is where we show the warning if something looks fishy
    if 'warning' in result:
        print(f"\n⚠️  WARNING: {result['warning']}")

    print("=" * 60)


def print_help():
    """
    Print helpful usage instructions.
    This shows up when someone runs the tool without arguments
    or asks for help.
    """
    print("\n" + "=" * 70)
    print(" " * 20 + "FILE TYPE IDENTIFIER")
    print("=" * 70)
    print("\nThis tool identifies file types by reading their magic bytes")
    print("and checking their extensions.\n")

    print("HOW TO USE:")
    print("-" * 70)
    print("1. Run with file path(s):")
    print("   python file_type_identifier.py myfile.pdf")
    print("   python file_type_identifier.py image.jpg video.mp4 document.docx")
    print()
    print("2. Check all files in a folder:")
    print("   python file_type_identifier.py /path/to/folder/*")
    print()
    print("3. Interactive mode (no arguments):")
    print("   python file_type_identifier.py")
    print("   Then enter file paths when prompted")
    print()
    print("EXAMPLES:")
    print("-" * 70)
    print("• Check a suspicious file:")
    print("  python file_type_identifier.py suspicious_download.exe")
    print()
    print("• Verify multiple images:")
    print("  python file_type_identifier.py *.jpg *.png")
    print()
    print("• Check files in Downloads folder:")
    print("  python file_type_identifier.py ~/Downloads/*")
    print("=" * 70 + "\n")


def interactive_mode():
    """
    Run the tool in interactive mode.
    This is user-friendly mode where we guide people through
    selecting files to check. Perfect for beginners!
    """
    identifier = FileTypeIdentifier()

    print("\n" + "=" * 70)
    print(" " * 25 + "INTERACTIVE MODE")
    print("=" * 70)
    print("\nEnter file paths to analyze (one per line)")
    print("Type 'done' when finished, or 'quit' to exit")
    print("Tip: You can drag & drop files here on most terminals!\n")
    print("-" * 70)

    files_to_check = []

    # Keep asking for files until the user says they're done
    while True:
        try:
            file_path = input("\nFile path (or 'done'/'quit'): ").strip()

            # Clean up the path - remove quotes that might be added by drag & drop
            file_path = file_path.strip('"').strip("'")

            # Check what the user entered
            if file_path.lower() in ['done', 'd']:
                if not files_to_check:
                    print("\n⚠️  No files entered. Exiting...")
                    return
                break  # Time to analyze!
            elif file_path.lower() in ['quit', 'q', 'exit']:
                print("\n👋 Goodbye!")
                return
            elif file_path == '':
                continue  # They just hit enter, skip it
            elif not os.path.exists(file_path):
                # Oops, file doesn't exist
                print(f"❌ File not found: {file_path}")
                retry = input("   Try again? (y/n): ").strip().lower()
                if retry != 'y':
                    continue
            else:
                # Good to go! Add it to the list
                files_to_check.append(file_path)
                print(f"✓ Added: {os.path.basename(file_path)}")

        except KeyboardInterrupt:
            # User pressed Ctrl+C
            print("\n\n👋 Interrupted. Goodbye!")
            return
        except EOFError:
            # End of input
            break

    # Now analyze all the files they gave us
    print("\n" + "=" * 70)
    print(" " * 25 + "ANALYSIS RESULTS")
    print("=" * 70 + "\n")

    for file_path in files_to_check:
        result = identifier.analyze_file(file_path)
        print_analysis(result)
        if len(files_to_check) > 1:
            print()  # Add spacing between multiple results


def main():
    """
    Main function to run the file type identifier.
    This is the entry point - it figures out what mode to run in
    based on how the user started the program.
    """

    # No arguments? Show help and offer interactive mode
    if len(sys.argv) == 1:
        print_help()

        choice = input("Start interactive mode? (y/n): ").strip().lower()
        if choice in ['y', 'yes', '']:
            interactive_mode()
        else:
            print("\n👋 Run again with file paths as arguments. See examples above!")
        return

    # User asked for help
    if sys.argv[1] in ['-h', '--help', 'help', '?']:
        print_help()
        return

    # Command line mode - analyze files from arguments
    identifier = FileTypeIdentifier()

    print("\n" + "=" * 70)
    print(" " * 25 + "ANALYSIS RESULTS")
    print("=" * 70 + "\n")

    # Go through each file they specified
    for file_path in sys.argv[1:]:
        # Make sure the file exists before trying to analyze it
        if not os.path.exists(file_path):
            print(f"❌ File not found: {file_path}\n")
            continue

        result = identifier.analyze_file(file_path)
        print_analysis(result)
        if len(sys.argv) > 2:  # Add spacing if analyzing multiple files
            print()


# This is Python's way of saying "only run this if we're running the script directly"
# (not if we're importing it as a module)
if __name__ == "__main__":
    main()
