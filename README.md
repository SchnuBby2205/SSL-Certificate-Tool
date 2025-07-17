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
