#!/usr/bin/env python3
"""
File Type Identifier
Identifies file types based on magic bytes (file signatures) and extensions.

Author: Your friendly neighborhood developer
Purpose: Prevent misleading file extensions by checking real file signatures.
"""

import os
import sys 
from pathlib import Path


class FileTypeIdentifier:
    """Identifies file types using magic bytes and file extensions."""

    MAGIC_BYTES = {
        # Images
        b'\xFF\xD8\xFF': {'type': 'JPEG', 'ext': ['.jpg', '.jpeg']},
        b'\x89PNG\r\n\x1a\n': {'type': 'PNG', 'ext': ['.png']},
        b'GIF87a': {'type': 'GIF', 'ext': ['.gif']},
        b'GIF89a': {'type': 'GIF', 'ext': ['.gif']},
        b'BM': {'type': 'BMP', 'ext': ['.bmp']},
        b'II*\x00': {'type': 'TIFF', 'ext': ['.tif', '.tiff']},
        b'MM\x00*': {'type': 'TIFF', 'ext': ['.tif', '.tiff']},

        # Documents
        b'%PDF': {'type': 'PDF', 'ext': ['.pdf']},
        b'PK\x03\x04': {
            'type': 'ZIP-based format',
            'ext': ['.zip', '.docx', '.xlsx', '.pptx', '.jar', '.apk']
        },
        b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1': {
            'type': 'Legacy MS Office',
            'ext': ['.doc', '.xls', '.ppt']
        },

        # Archives
        b'\x1f\x8b': {'type': 'GZIP', 'ext': ['.gz']},
        b'Rar!\x1a\x07': {'type': 'RAR', 'ext': ['.rar']},
        b'7z\xBC\xAF\x27\x1C': {'type': '7-Zip', 'ext': ['.7z']},

        # Executables
        b'MZ': {'type': 'Windows Executable', 'ext': ['.exe', '.dll']},
        b'\x7fELF': {'type': 'Linux Executable (ELF)', 'ext': ['']},

        # Media
        b'ID3': {'type': 'MP3 Audio', 'ext': ['.mp3']},
        b'\xFF\xFB': {'type': 'MP3 Audio', 'ext': ['.mp3']},
        b'\xFF\xF3': {'type': 'MP3 Audio', 'ext': ['.mp3']},
        b'\xFF\xF2': {'type': 'MP3 Audio', 'ext': ['.mp3']},
        b'ftyp': {'type': 'MP4-family Container', 'ext': ['.mp4', '.m4v', '.mov']},

        # Text with BOM
        b'\xEF\xBB\xBF': {'type': 'UTF-8 Text with BOM', 'ext': ['.txt', '.xml', '.html']},
    }

    def __init__(self):
        self.max_signature_length = max(len(sig) for sig in self.MAGIC_BYTES)

    def identify_by_magic_bytes(self, file_path):
        try:
            with open(file_path, 'rb') as f:
                header = f.read(self.max_signature_length)

                # Handle RIFF formats explicitly
                if header.startswith(b'RIFF') and len(header) >= 12:
                    riff_type = header[8:12]
                    if riff_type == b'AVI ':
                        return 'AVI Video', ['.avi']
                    if riff_type == b'WEBP':
                        return 'WEBP Image', ['.webp']
                    if riff_type == b'WAVE':
                        return 'WAV Audio', ['.wav']

                for signature, info in self.MAGIC_BYTES.items():
                    if header.startswith(signature):
                        return info['type'], info['ext']

                if self._is_text_file(header):
                    return 'Text File', ['.txt']

                return 'Unknown', []

        except Exception as e:
            return f'Error: {str(e)}', []

    def _is_text_file(self, data):
        """
        Determines whether a file is likely text.
        Presence of a null byte strongly indicates binary data.
        """
        if b'\x00' in data:
            return False
        try:
            data.decode('utf-8')
            return True
        except UnicodeDecodeError:
            return False

    def identify_by_extension(self, file_path):
        ext = Path(file_path).suffix.lower()

        extension_types = {
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
            '.txt': 'Text File',
            '.md': 'Markdown',
            '.csv': 'CSV',
            '.log': 'Log File',
            '.jpg': 'JPEG Image',
            '.jpeg': 'JPEG Image',
            '.png': 'PNG Image',
            '.gif': 'GIF Image',
            '.svg': 'SVG Image',
            '.zip': 'ZIP Archive',
            '.tar': 'TAR Archive',
            '.gz': 'GZIP Archive',
            '.rar': 'RAR Archive',
            '.mp4': 'MP4 Video',
            '.avi': 'AVI Video',
            '.mkv': 'MKV Video',
            '.mov': 'QuickTime Video',
            '.wav': 'WAV Audio',
        }

        return extension_types.get(ext, f'Unknown ({ext})')

    def analyze_file(self, file_path):
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

        if actual_ext and expected_exts and actual_ext not in expected_exts:
            result['warning'] = (
                f'Extension mismatch. Detected {magic_type} '
                f'but file uses {actual_ext}'
            )

        return result

    def _format_size(self, size):
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024:
                return f"{size:.2f} {unit}"
            size /= 1024
        return f"{size:.2f} PB"


def print_analysis(result):
    if 'error' in result:
        print(f"Error: {result['error']}")
        return

    print("=" * 60)
    print("File Analysis Report")
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
        print(f"\nWARNING: {result['warning']}")

    print("=" * 60)


def print_help():
    print("\n" + "=" * 70)
    print("FILE TYPE IDENTIFIER")
    print("=" * 70)
    print("\nIdentifies file types using real file signatures.\n")
    print("Usage:")
    print("  python file_type_identifier.py file1 file2")
    print("  python file_type_identifier.py /path/to/folder/*")
    print("  python file_type_identifier.py  (interactive mode)")
    print("=" * 70 + "\n")


def interactive_mode():
    identifier = FileTypeIdentifier()
    files = []

    print("\nEnter file paths one at a time.")
    print("Type 'done' to analyze or 'quit' to exit.\n")

    while True:
        try:
            path = input("File path: ").strip().strip('"').strip("'")
            if path.lower() in ['quit', 'q', 'exit']:
                return
            if path.lower() in ['done', 'd']:
                break
            if not os.path.exists(path):
                print("File not found.")
                continue
            files.append(path)
            print("Added.")
        except (KeyboardInterrupt, EOFError):
            return

    for f in files:
        print_analysis(identifier.analyze_file(f))
        if len(files) > 1:
            print()


def main():
    if len(sys.argv) == 1:
        print_help()
        choice = input("Start interactive mode? (y/n): ").strip().lower()
        if choice in ['y', 'yes', '']:
            interactive_mode()
        return

    if sys.argv[1] in ['-h', '--help', 'help', '?']:
        print_help()
        return

    identifier = FileTypeIdentifier()
    for path in sys.argv[1:]:
        if not os.path.exists(path):
            print(f"File not found: {path}")
            continue
        print_analysis(identifier.analyze_file(path))
        if len(sys.argv) > 2:
            print()


if __name__ == "__main__":
    main()
