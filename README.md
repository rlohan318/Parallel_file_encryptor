
# 🔐 Parallel File Encryptor (C++)

A high-performance **AES-based file encryption and decryption tool** built in **C++**.  
This project leverages **multithreading** to encrypt large files efficiently, ensuring strong data protection and faster execution through parallel processing.

---

## 🚀 Features

- **AES Encryption (OpenSSL):** Protects sensitive files using industry-standard encryption.  
- **Parallel Processing:** Utilizes multiple CPU threads to accelerate encryption/decryption.  
- **Cross-Platform Compatibility:** Works with all file types and sizes.  
- **Secure Password-Based Key Derivation:** Prevents unauthorized access.  
- **Optimized for Performance:** Efficient memory management and I/O handling.  
- **Robust Error Handling:** Graceful management of file, memory, and thread errors.  

---

## 🧠 How It Works

The program:
1. Splits large files into chunks.
2. Assigns each chunk to a thread for parallel encryption/decryption.
3. Merges all chunks into the final output file once processing is complete.

---

## ⚙️ Build Instructions

### 🧩 Requirements
- C++17 or later  
- OpenSSL library  
- pthread (for multithreading)

### 🛠️ Installation (macOS / Linux)

```bash
# Install OpenSSL if not already installed
brew install openssl

# Compile the program
g++ -std=c++17 parallel_file_encryptor.cpp -lcrypto -pthread -O2 -o pfe
````

If you get an OpenSSL header error (`openssl/evp.h not found`), use:

```bash
g++ -std=c++17 parallel_file_encryptor.cpp \
  -I$(brew --prefix openssl)/include \
  -L$(brew --prefix openssl)/lib \
  -lcrypto -pthread -O2 -o pfe
```

---

## 🔧 Usage

### 🛡️ Encryption

```bash
./pfe encrypt <input_file> <output_file> <password> [threads] [chunk-size-bytes]
```

**Example:**

```bash
./pfe encrypt main.txt main.txt.pfe MyStrongPass 4 4194304
```

### 🔓 Decryption

```bash
./pfe decrypt <input_file> <output_file> <password> [threads]
```

**Example:**

```bash
./pfe decrypt main.txt.pfe decrypted.txt MyStrongPass 4
```

---

## 📈 Example Workflow

```bash
# Encrypt file
./pfe encrypt main.txt main.txt.pfe "StrongPassword123"

# Decrypt file
./pfe decrypt main.txt.pfe decrypted.txt "StrongPassword123"

# Compare checksum
shasum -a 256 main.txt decrypted.txt
```

If both hashes match → ✅ encryption/decryption successful.

---

## 🧰 Parameters Explained

| Parameter          | Description                                                  |
| ------------------ | ------------------------------------------------------------ |
| `input_file`       | File to encrypt/decrypt                                      |
| `output_file`      | Destination file                                             |
| `password`         | User-defined encryption password                             |
| `threads`          | Number of parallel threads (optional; defaults to CPU cores) |
| `chunk-size-bytes` | Size of chunks for processing (optional; default: 4 MB)      |

---

## 🧱 Design Highlights

* **Thread Synchronization:** Mutexes and atomic operations prevent race conditions.
* **Memory Optimization:** Each thread processes its chunk independently to minimize buffer duplication.
* **Error Safety:** Clean error messages and safe resource cleanup.
* **Secure AES Mode:** AES-256-CBC ensures robust symmetric encryption.

---

## ⚠️ Security Notes

* Avoid passing passwords directly in the command line — they may appear in shell history or process lists.
* Use a strong password, e.g., generated via:

  ```bash
  openssl rand -base64 32
  ```
* For production, consider modifying the program to prompt for passwords interactively.

---

## 🧪 Example Output

```bash
Encrypting main.txt → main.txt.pfe using 4 threads...
Encryption complete. Output saved to main.txt.pfe
```

---

## 👤 Author

**Rishu**
💡 Student & Developer passionate about performance-oriented system tools.

---
