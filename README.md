# Secure-File-Encryptor

This program implements file encryption and decryption with RSA and AES algorithms, as well as a quantum resilience check for RSA keys. 
It uses a command-line interface (CLI) to interact with users. 

-----------------------------------------------------------------------------------------------------------------------------------------------

The encryption process uses AES for fast encryption of file data and RSA to secure the AES key. 
AES encryption is fast and secure for encrypting large amounts of data, while RSA encryption is used to securely store the AES key. HMAC ensures the file's integrity during transmission.
The decryption process follows the reverse process of encryption, ensuring the security of the original data. HMAC verification ensures the file has not been tampered with.

-----------------------------------------------------------------------------------------------------------------------------------------------

The quantum resilience check ensure RSA keys are resistant to potential quantum computing threats, contributing to long-term security.
Quantum computers can break RSA encryption much faster than classical computers, so using larger key sizes (e.g., RSA 2048 and above) is essential for quantum resilience. 
This check helps users identify keys that may need to be updated to avoid potential future vulnerabilities.

Source:
https://learn.microsoft.com/en-us/dotnet/standard/security/cryptography-model
