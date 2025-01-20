# AES-GCM File Encryptor

A Python-based command-line tool that encrypts or decrypts files and directories using the AES-GCM mode. It supports multi-threading to process multiple files simultaneously and provides real-time progress updates.

---

## Features

- **AES-GCM Encryption/Decryption**: Ensures data integrity and confidentiality.
- **Multi-threaded**: Encrypt/Decrypt multiple files in parallel for faster processing.
- **Progress Tracking**: Displays per-file and overall completion percentage.
- **Skip Logic**:
  - Automatically skips files that are already encrypted (when encrypting).
  - Skips files that are not encrypted (when decrypting).
  - Skips the script itself if located within the target folder.
- **Custom Key Support**: Use your own 16-byte key (`-key`), or fall back to the default key provided in the script.
- **Colorized Output**: Makes it easy to identify different log messages (skip, error, progress, etc.).

---

## Requirements

- **Python 3.6+**
- **PyCryptodome**  
  Install via:  
  ```bash
  pip install pycryptodome
termcolor
Install via:
bash
Copy
pip install termcolor
Installation
Clone or download this repository.
Install the required libraries:
bash
Copy
pip install pycryptodome termcolor
Usage
Navigate to the folder containing the script:
bash
Copy
cd /path/to/script
Run the script with the desired options:
bash
Copy
python aes_gcm_file_encryptor.py [path] [options]
Required Parameters
path: File or folder path to encrypt or decrypt.
Mode of Operation
-enc: Encrypt the target.
-dec: Decrypt the target.
You must specify either -enc or -dec.

Optional Parameters
-key: Provide a 16-byte string as a custom key for AES encryption/decryption.
Example: -key "mycustom16bytek"
--threads: Specify the number of worker threads for parallel processing (default: 10).
Example: --threads 20
Examples
Encrypting a Folder (with default key, 10 threads)

bash
Copy
python aes_gcm_file_encryptor.py /path/to/folder -enc
Decrypting a File (with custom key, 4 threads)

bash
Copy
python aes_gcm_file_encryptor.py /path/to/file.enc -dec -key "mycustom16bytek" --threads 4
Encrypting a File (with custom key, 20 threads)

bash
Copy
python aes_gcm_file_encryptor.py /path/to/file -enc -key "another16bytkey" --threads 20
Security Notice
Default Key: The script provides a default 16-byte key (DEFAULT_KEY) as an example. It is strongly recommended to generate and use your own secure 16-byte key for production.
Key Handling: Store and manage your keys securely. Exposing your key in source code or logs can compromise data security.
License
This project is licensed under the MIT License.

Contributing
Fork the repo.
Create your feature branch (git checkout -b feature/awesome-feature).
Commit your changes (git commit -am 'Add new feature').
Push to the branch (git push origin feature/awesome-feature).
Create a new Pull Request.
Contributions and bug reports are welcome! Feel free to open an issue for any problem you encounter.

File Name: aes_gcm_file_encryptor.py

Copy the script into your project, ensure dependencies are installed, and then run it with the appropriate command-line arguments for encryption or decryption tasks.
