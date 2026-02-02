#!/usr/bin/env python3
"""
File Type Identifier
Identifies file types based on magic bytes (file signatures) and extensions.
"""

import os
import sys
from pathlib import Path


class FileTypeIdentifier:
    """Identifies file types using magic bytes and file extensions."""

    # Dictionary of file signatures (magic bytes)
    MAGIC_BYTES = {
        # Images
        b'\xFF\xD8\xFF': {'type': 'JPEG', 'ext': ['.jpg', '.jpeg']},
        b'\x89PNG\r\n\x1a\n': {'type': 'PNG', 'ext': ['.png']},
        b'GIF87a': {'type': 'GIF', 'ext': ['.gif']},
        b'GIF89a': {'type': 'GIF', 'ext': ['.gif']},
        b'BM': {'type': 'BMP', 'ext': ['.bmp']},
        b'II*\x00': {'type': 'TIFF', 'ext': ['.tif', '.tiff']},
        b'MM\x00*': {'type': 'TIFF', 'ext': ['.tif', '.tiff']},
        b'RIFF': {'type': 'WEBP/AVI', 'ext': ['.webp', '.avi']},  # Need to check further

        # Documents
        b'%PDF': {'type': 'PDF', 'ext': ['.pdf']},
        b'PK\x03\x04': {'type': 'ZIP/DOCX/XLSX/JAR', 'ext': ['.zip', '.docx', '.xlsx', '.jar', '.apk']},
        b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1': {'type': 'MS Office (old)', 'ext': ['.doc', '.xls', '.ppt']},

        # Archives
        b'\x1f\x8b': {'type': 'GZIP', 'ext': ['.gz']},
        b'Rar!\x1a\x07': {'type': 'RAR', 'ext': ['.rar']},
        b'7z\xBC\xAF\x27\x1C': {'type': '7-Zip', 'ext': ['.7z']},

        # Executables
        b'MZ': {'type': 'Windows Executable', 'ext': ['.exe', '.dll']},
        b'\x7fELF': {'type': 'Linux Executable (ELF)', 'ext': ['']},

        # Media
        b'\x00\x00\x00\x18ftypmp42': {'type': 'MP4', 'ext': ['.mp4']},
        b'\x00\x00\x00\x1cftypmp42': {'type': 'MP4', 'ext': ['.mp4']},
        b'\x00\x00\x00\x20ftypmp42': {'type': 'MP4', 'ext': ['.mp4']},
        b'ID3': {'type': 'MP3', 'ext': ['.mp3']},
        b'\xFF\xFB': {'type': 'MP3', 'ext': ['.mp3']},
        b'\xFF\xF3': {'type': 'MP3', 'ext': ['.mp3']},
        b'\xFF\xF2': {'type': 'MP3', 'ext': ['.mp3']},
        b'ftyp': {'type': 'MP4/M4V/MOV', 'ext': ['.mp4', '.m4v', '.mov']},

        # Text/Code (UTF-8 BOM)
        b'\xEF\xBB\xBF': {'type': 'UTF-8 with BOM', 'ext': ['.txt', '.xml', '.html']},
    }

    def __init__(self):
        self.max_signature_length = max(len(sig) for sig in self.MAGIC_BYTES.keys())

    def identify_by_magic_bytes(self, file_path):
        """Identify file type by reading magic bytes."""
        try:
            with open(file_path, 'rb') as f:
                header = f.read(self.max_signature_length)

                # Check all known signatures
                for signature, info in self.MAGIC_BYTES.items():
                    if header.startswith(signature):
                        return info['type'], info['ext']

                # Check if it's plain text
                if self._is_text_file(header):
                    return 'Text File', ['.txt']

                return 'Unknown', []

        except Exception as e:
            return f'Error: {str(e)}', []

    def _is_text_file(self, data):
        """Check if data appears to be text."""
        try:
            data.decode('utf-8')
            # Check for common text characters
            text_chars = set(range(32, 127)) | {9, 10, 13}  # Printable + tab, newline, return
            return all(byte in text_chars or byte > 127 for byte in data[:1024])
        except:
            return False

    def identify_by_extension(self, file_path):
        """Identify file type by extension."""
        ext = Path(file_path).suffix.lower()

        extension_types = {
            # Programming
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

            # Documents
            '.txt': 'Text File',
            '.md': 'Markdown',
            '.csv': 'CSV',
            '.log': 'Log File',

            # Images
            '.jpg': 'JPEG Image',
            '.jpeg': 'JPEG Image',
            '.png': 'PNG Image',
            '.gif': 'GIF Image',
            '.svg': 'SVG Image',

            # Archives
            '.zip': 'ZIP Archive',
            '.tar': 'TAR Archive',
            '.gz': 'GZIP Archive',
            '.rar': 'RAR Archive',

            # Video
            '.mp4': 'MP4 Video',
            '.avi': 'AVI Video',
            '.mkv': 'MKV Video',
            '.mov': 'QuickTime Video',
        }

        return extension_types.get(ext, f'Unknown ({ext})')

    def analyze_file(self, file_path):
        """Perform complete file analysis."""
        if not os.path.exists(file_path):
            return {'error': 'File does not exist'}

        file_size = os.path.getsize(file_path)
        magic_type, expected_exts = self.identify_by_magic_bytes(file_path)
        ext_type = self.identify_by_extension(file_path)
        actual_ext = Path(file_path).suffix.lower()

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

        # Check for mismatch
        if actual_ext and expected_exts:
            if actual_ext not in expected_exts:
                result[
                    'warning'] = f'Extension mismatch! File appears to be {magic_type} but has {actual_ext} extension'

        return result

    def _format_size(self, size):
        """Format file size in human-readable form."""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024.0:
                return f"{size:.2f} {unit}"
            size /= 1024.0
        return f"{size:.2f} PB"


def print_analysis(result):
    """Print the analysis result in a formatted way."""
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

    if 'warning' in result:
        print(f"\n⚠️  WARNING: {result['warning']}")

    print("=" * 60)


def print_help():
    """Print helpful usage instructions."""
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
    """Run the tool in interactive mode."""
    identifier = FileTypeIdentifier()

    print("\n" + "=" * 70)
    print(" " * 25 + "INTERACTIVE MODE")
    print("=" * 70)
    print("\nEnter file paths to analyze (one per line)")
    print("Type 'done' when finished, or 'quit' to exit")
    print("Tip: You can drag & drop files here on most terminals!\n")
    print("-" * 70)

    files_to_check = []

    while True:
        try:
            file_path = input("\nFile path (or 'done'/'quit'): ").strip()

            # Remove quotes if user dragged and dropped
            file_path = file_path.strip('"').strip("'")

            if file_path.lower() in ['done', 'd']:
                if not files_to_check:
                    print("\n⚠️  No files entered. Exiting...")
                    return
                break
            elif file_path.lower() in ['quit', 'q', 'exit']:
                print("\n👋 Goodbye!")
                return
            elif file_path == '':
                continue
            elif not os.path.exists(file_path):
                print(f"❌ File not found: {file_path}")
                retry = input("   Try again? (y/n): ").strip().lower()
                if retry != 'y':
                    continue
            else:
                files_to_check.append(file_path)
                print(f"✓ Added: {os.path.basename(file_path)}")

        except KeyboardInterrupt:
            print("\n\n👋 Interrupted. Goodbye!")
            return
        except EOFError:
            break

    # Analyze all files
    print("\n" + "=" * 70)
    print(" " * 25 + "ANALYSIS RESULTS")
    print("=" * 70 + "\n")

    for file_path in files_to_check:
        result = identifier.analyze_file(file_path)
        print_analysis(result)
        if len(files_to_check) > 1:
            print()


def main():
    """Main function to run the file type identifier."""

    # No arguments - show help and enter interactive mode
    if len(sys.argv) == 1:
        print_help()

        choice = input("Start interactive mode? (y/n): ").strip().lower()
        if choice in ['y', 'yes', '']:
            interactive_mode()
        else:
            print("\n👋 Run again with file paths as arguments. See examples above!")
        return

    # Help flag
    if sys.argv[1] in ['-h', '--help', 'help', '?']:
        print_help()
        return

    # Analyze files from command line arguments
    identifier = FileTypeIdentifier()

    print("\n" + "=" * 70)
    print(" " * 25 + "ANALYSIS RESULTS")
    print("=" * 70 + "\n")

    for file_path in sys.argv[1:]:
        # Handle wildcards and expand paths
        if not os.path.exists(file_path):
            print(f"❌ File not found: {file_path}\n")
            continue

        result = identifier.analyze_file(file_path)
        print_analysis(result)
        if len(sys.argv) > 2:  # Multiple files
            print()


if __name__ == "__main__":
    main()
