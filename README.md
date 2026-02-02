# File Type Identifier (UNDER IMPROVEMENT)
This is simple Python tool that figures out what type of file you're actually looking at. It checks both the file's actual content (magic bytes) and its extension to catch files that have been renamed or mislabeled. 

## What It Does

Reads Magic Bytes - Looks at the actual file signature to identify the real file type
Checks Extensions - Compares the file extension with what it should be
Catches Fakes - Warns you when something's off (like a .txt file that's actually a .png)
Handles Tons of Formats - Works with images (JPEG, PNG, GIF, etc.), documents (PDF, Word, Excel), archives (ZIP, RAR, 7Z), executables, videos, music files, and code files

## Why You'd Want This
Ever downloaded a file that wouldn't open? Or wondered if that "image.jpg" is actually an image? This tool helps with:

Security stuff - Catch files pretending to be something they're not
Organizing files - Make sure everything has the right extension
Fixing corrupted downloads - Figure out what a mystery file actually is
Validating uploads - Check that users are uploading what they say they are

## How It Works
Pretty straightforward - it reads the first few bytes of your file (every file type has a unique "fingerprint"), checks what extension the file has, and lets you know if something doesn't match up. If a file claims to be a .docx but the actual bytes say it's a .jpg, you'll get a warning.

## Requirements
Just Python 3.6 or newer. No pip installs, no dependencies - it only uses Python's built-in stuff, so it works right out of the box.
