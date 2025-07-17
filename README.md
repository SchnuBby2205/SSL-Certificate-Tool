# SchnuBbySSL

**SchnuBbySSL** is a lightweight, interactive ACME client written in Python to automate the process of requesting and signing Let's Encrypt SSL certificates using OpenSSL.  
It handles everything from key parsing to domain validation and certificate issuance.

> ⚠️ This tool is designed for advanced users who are comfortable managing Apache servers and SSL certificates manually.

---

## 📦 Features

- Uses Let's Encrypt's ACME v2 API
- Parses RSA account keys and CSRs
- Handles HTTP-01 domain ownership validation
- Signs and retrieves SSL certificates
- Interactive terminal steps for Apache configuration

---

## 🧰 Requirements

- Python 3.6+
- [OpenSSL](https://www.openssl.org/) (Tested with OpenSSL for Windows)
- An Apache web server
- A registered domain name with access to configure `.well-known/acme-challenge`

---

## 📁 Files

- `account.key` – Your ACME account private RSA key
- `domain.csr` – Certificate Signing Request (CSR) for your domain
- `domain.crt` – Signed domain certificate (output)
- `intermediate.pem` – Intermediate certificate from Let's Encrypt (output)

---

## ⚙️ Setup

1. **Install OpenSSL**  
   Ensure OpenSSL is installed and available on your system. Update the script path to match your OpenSSL binary location.

2. **Generate Account Key**
   ```bash
   openssl genrsa 4096 > account.key
   ```
3. **Generate Domain Key**
   ```bash
   openssl genrsa 4096 > domain.key
   ```
4. **Generate Certificate signing Request**
   ```bash
   openssl req -new -sha256 -key domain.key
   ```

5. Copy the Output ...BEGIN CERTIFICATE... to ...END CERTIFICATE... to a File called domain.csr

6. Run the Script
   ```bash
   python SSLTool.py <path/to/the/openssl.exe> <email associated with the account>
   ```
   
All the above Steps must be done in the /bin/ Directory of OpenSSL. Then copy the Script to /bin/ or copy the account.key, domain.key and domain.csr in the same Directory the Script is located.
