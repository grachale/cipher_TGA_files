# Cipher files with OpenSSL
 Implementation of functions for a program that can encrypt and decrypt a TGA image file.

## Task Description:
For our task, we will consider a simplified form of an image represented in the TGA format.

### Mandatory Header: 
18 bytes - we will not modify these bytes in any way, only copy them to the encrypted image.
### Optional Header Part: 
The size is calculated from the mandatory header part - we will treat this header part as image data, meaning we will encrypt it together with the image data without any changes.
### Image Data: 
The rest of the data.

## Parameters of Implemented Functions:

bool encrypt_data (const string & in_filename, const string & out_filename, crypto_config & config)

in_filename: Input file name.

out_filename: Output file name.

config: Data structure crypto_config described below.

The return value is true in case of success, false otherwise. Failure occurs if the file is somehow invalid (missing mandatory header, unable to open, read, write, etc.) or if the invalid crypto_config cannot be repaired.

The function decrypt_data utilizes the same interface but performs the inverse operation with respect to encryption. It will copy the mandatory header, which is not encrypted, and then decrypt the rest of the file in the same way as encryption. In this case, valid decryption key and IV (if required) are expected to be passed. If these parameters are not provided, data cannot be decrypted, and the program should report an error (return false).

The data structure crypto_config contains:

The chosen block cipher specified by its name.

Secret encryption key and its size.

Initialization Vector (IV) and its size.

During encryption, the following problem may arise: if the encryption key (or IV) is insufficient (i.e., its length is not at least as large as required by the chosen block cipher or completely missing), it must be safely generated. If the specified block cipher does not need an IV (and therefore may not be provided to you), do not generate a new IV! Remember to save any generated keys and IVs in the passed config structure!
