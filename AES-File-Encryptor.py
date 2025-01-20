import os
import argparse
import threading
from termcolor import colored
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from concurrent.futures import ThreadPoolExecutor
import sys
from threading import Lock

DEFAULT_KEY = b'your_secret_key_16_bytes'  # Replace with a secure 16-byte key
CHUNK_SIZE = 64 * 1024  # 64 KB for large files
output_lock = Lock()

completed_files = []  # Stores messages about processed files
progress = {"processed": 0, "total": 0}  # Tracks overall progress


def is_within_boundary(base_path, target_path):
    """Checks if the target path is within the boundary of the base path."""
    base_path = os.path.abspath(base_path)
    target_path = os.path.abspath(target_path)
    return os.path.commonpath([base_path]) == os.path.commonpath([base_path, target_path])


def is_encrypted(file_path):
    """Checks if a file is considered encrypted by its .enc extension."""
    return file_path.endswith('.enc')


def should_skip_file(file_path):
    """Checks if this script file itself should be skipped."""
    script_path = os.path.abspath(__file__)
    return os.path.abspath(file_path) == script_path


def process_file(file_path, mode, key):
    """Encrypts or decrypts a single file using AES-GCM with live progress."""
    global progress

    # Skip if it's the running script file
    if should_skip_file(file_path):
        with output_lock:
            print(colored(f"[SKIP] Script file (self): {file_path}", 'yellow'))
        return

    # Skip if file is already encrypted (for encryption mode)
    if mode == 'encrypt' and is_encrypted(file_path):
        with output_lock:
            print(colored(f"[SKIP] Already encrypted: {file_path}", 'yellow'))
        completed_files.append(f"Already Encrypted: {file_path}")
        return

    # Skip if file is not encrypted (for decryption mode)
    if mode == 'decrypt' and not is_encrypted(file_path):
        with output_lock:
            print(colored(f"[SKIP] Not encrypted: {file_path}", 'yellow'))
        completed_files.append(f"Not Encrypted: {file_path}")
        return

    try:
        # Prepare cipher objects and output paths
        if mode == 'encrypt':
            cipher = AES.new(key, AES.MODE_GCM)
            output_path = file_path + '.enc'
        else:  # decrypt mode
            with open(file_path, 'rb') as f_in:
                nonce = f_in.read(16)
                tag = f_in.read(16)
                cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            output_path = file_path[:-4]  # remove '.enc'

        with open(file_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
            # Write nonce if encrypting
            if mode == 'encrypt':
                f_out.write(cipher.nonce)

            # Process file in chunks
            while chunk := f_in.read(CHUNK_SIZE):
                if mode == 'encrypt':
                    processed_chunk = cipher.encrypt(chunk)
                else:  # decrypt
                    processed_chunk = cipher.decrypt(chunk)
                f_out.write(processed_chunk)

            # Write tag if encrypting
            if mode == 'encrypt':
                tag = cipher.digest()
                f_out.write(tag)

        # Remove the original file
        os.remove(file_path)

        # Update overall progress
        with output_lock:
            action_done = "Encrypted" if mode == 'encrypt' else "Decrypted"
            completed_files.append(f"{action_done}: {file_path}")
            progress["processed"] += 1
            overall_progress = (progress["processed"] / progress["total"]) * 100
            print(
                colored(
                    f"[{action_done}] {file_path} [100%] | Overall: {overall_progress:.2f}%",
                    'green'
                )
            )
    except Exception as e:
        with output_lock:
            print(colored(f"[ERROR] Could not process file: {file_path}\nReason: {e}", 'red'))


def process_folder(folder_path, mode, key, max_threads=10):
    """
    Recursively processes all files in the specified folder 
    using a ThreadPoolExecutor with a configurable number of worker threads.
    """
    global progress

    base_path = os.path.abspath(folder_path)
    all_files = []

    for root, _, files in os.walk(folder_path):
        for file in files:
            file_path = os.path.join(root, file)
            if not is_within_boundary(base_path, file_path):
                # Skip out-of-bound files
                with output_lock:
                    print(colored(f"[SKIP] Out-of-bound file: {file_path}", 'yellow'))
                continue
            all_files.append(file_path)

    # Set total files for progress tracking
    progress["total"] = len(all_files)

    # Use multi-threading for parallel file encryption/decryption
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = [
            executor.submit(process_file, file_path, mode, key)
            for file_path in all_files
        ]
        for future in futures:
            future.result()  # wait for all threads to complete


def main():
    parser = argparse.ArgumentParser(
        description="Encrypt or decrypt files/folders recursively using AES-GCM."
    )
    parser.add_argument('path', type=str, help="Path to a file or folder.")
    parser.add_argument('-enc', action='store_true', help="Encrypt the target.")
    parser.add_argument('-dec', action='store_true', help="Decrypt the target.")
    parser.add_argument('-key', type=str, default=None,
                        help="Custom 16-byte key for encryption/decryption.")
    parser.add_argument('--threads', type=int, default=10,
                        help="Number of threads to use for parallel processing.")

    args = parser.parse_args()

    if not os.path.exists(args.path):
        print(colored("[ERROR] The specified path does not exist.", 'red'))
        return

    # Use provided key if valid, otherwise default
    if args.key:
        if len(args.key) != 16:
            print(colored("[ERROR] Key must be exactly 16 bytes.", 'red'))
            return
        key = args.key.encode()
    else:
        key = DEFAULT_KEY

    # Determine mode (encrypt or decrypt)
    mode = 'encrypt' if args.enc else 'decrypt' if args.dec else None
    if not mode:
        print(colored("[INFO] Please specify -enc to encrypt or -dec to decrypt.", 'yellow'))
        return

    # Process single file or entire folder
    if os.path.isfile(args.path):
        print(colored(f"[START] Processing file: {args.path}", 'blue'))
        if is_within_boundary(args.path, args.path):
            progress["total"] = 1
            process_file(args.path, mode, key)
        else:
            print(colored("[ERROR] The file is outside the allowed boundary.", 'red'))
    else:
        print(colored(f"[START] Processing folder: {args.path}", 'blue'))
        process_folder(args.path, mode, key, max_threads=args.threads)

    # Print summary of all processed files
    print(colored("\n[SUMMARY] Processing results:", 'blue'))
    with output_lock:
        for entry in completed_files:
            # Highlight "Not Encrypted:" or "Already Encrypted:" in yellow,
            # otherwise keep encrypted/decrypted lines in green.
            if "Not Encrypted:" in entry or "Already Encrypted:" in entry:
                print(colored(entry, 'yellow'))
            else:
                print(colored(entry, 'green'))


if __name__ == "__main__":
    main()
