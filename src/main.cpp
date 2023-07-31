#ifndef __PROGTEST__
#include <cstdlib>
#include <cstdio>
#include <cctype>
#include <climits>
#include <cstdint>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <unistd.h>
#include <string>
#include <memory>
#include <vector>
#include <fstream>
#include <cassert>
#include <cstring>

#include <openssl/evp.h>
#include <openssl/rand.h>



using namespace std;

struct crypto_config
{
    const char * m_crypto_function;
    std::unique_ptr<uint8_t[]> m_key;
    std::unique_ptr<uint8_t[]> m_IV;
    size_t m_key_len;
    size_t m_IV_len;
};

#endif /* _PROGTEST_ */

#define HEADER_SIZE 18
#define BUFFER_SIZE 1024

void cipher_ctx_deleter(EVP_CIPHER_CTX* ctx) {
    EVP_CIPHER_CTX_free(ctx);
}

// encrypt data if bool encrypt variable is true, otherwise decrypt
// return true if everything is ok, otherwise false
bool cipherData ( ifstream & inputFile, ofstream & outputFile, crypto_config & config, bool encrypt )
{
    // copy the header (18 bytes)
    char header [HEADER_SIZE];
    inputFile . read(header, HEADER_SIZE);
    if ( inputFile . gcount() != HEADER_SIZE || !inputFile . is_open() )
        return false;

    outputFile . write(header, HEADER_SIZE);
    if ( !outputFile . is_open() )
        return false;


    OpenSSL_add_all_algorithms();

    const EVP_CIPHER * cipher = EVP_get_cipherbyname(config.m_crypto_function);
    if (!cipher)
        return false;

    std::shared_ptr<EVP_CIPHER_CTX> ctx(EVP_CIPHER_CTX_new(), cipher_ctx_deleter);
    if (!ctx . get ())
        return false;

    // In case of insufficient or absence of key or iv, create new ones
    uint8_t             key[EVP_MAX_KEY_LENGTH];
    uint8_t             iv[EVP_MAX_IV_LENGTH];
    size_t keyLen          = EVP_CIPHER_key_length(cipher);
    size_t ivLen           = EVP_CIPHER_iv_length(cipher);

    if ( ( config . m_key && config . m_key_len >= keyLen ) || keyLen == 0 )
    {
        memcpy (key, config . m_key . get (), keyLen);
    } else
    {
        if ( !encrypt )
            return false;

        if ( !RAND_bytes(key, keyLen) )
            return false;
        config . m_key = make_unique<uint8_t []>(keyLen);
        memcpy ( config . m_key . get (), key, keyLen );
        config . m_key_len = keyLen;
    }

    if ( ( config . m_IV && config . m_IV_len >= ivLen ) || ivLen == 0 )
    {
        memcpy (iv, config . m_IV . get (), ivLen);
    } else
    {
        if ( !encrypt )
            return false;
        if ( !RAND_bytes(iv, ivLen) )
            return false;
        config . m_IV = make_unique<uint8_t []>(ivLen);
        memcpy ( config . m_IV . get (), iv, ivLen );
        config . m_IV_len = ivLen;
    }

    if ( !EVP_CipherInit_ex(ctx . get (), cipher, NULL, key, iv, encrypt ) )
        return false;

    uint8_t buffer          [BUFFER_SIZE];
    uint8_t encryptedBuffer [BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];
    int readSize;
    int outLength;
    while ( true )
    {
        inputFile . read (reinterpret_cast<char *>(buffer), BUFFER_SIZE );

        if ( inputFile . fail () && inputFile . eof() )
            break;

        if ( inputFile . fail () && !inputFile. eof()  )
            return false;

        readSize = inputFile . gcount();

        if ( !EVP_CipherUpdate(ctx . get (), encryptedBuffer, &outLength, buffer, readSize) )
            return false;

        outputFile . write(reinterpret_cast<const char *>(encryptedBuffer), outLength);
        if ( !outputFile . good() )
            return false;
    }
    readSize = inputFile . gcount();
    if ( readSize > 0 ) {
        if (!EVP_CipherUpdate(ctx.get(), encryptedBuffer, &outLength, buffer, readSize))
            return false;
        outputFile . write(reinterpret_cast<const char *>(encryptedBuffer), outLength);
        if ( !outputFile . good() )
            return false;
    }

    if ( !EVP_CipherFinal(ctx . get (), encryptedBuffer, &outLength) )
        return false;

    outputFile . write(reinterpret_cast<const char *>(encryptedBuffer), outLength);
    if ( !outputFile . good() )
        return false;

    return true;
}


bool encrypt_data ( const std::string & in_filename, const std::string & out_filename, crypto_config & config )
{
    ifstream inputFile (in_filename);
    if ( !inputFile . is_open() )
        return false;

    ofstream outputFile ( out_filename);
    if ( !outputFile . is_open() )
    {
        inputFile . close ();
        return false;
    }

    if ( !cipherData(inputFile, outputFile, config, true) )
    {
        inputFile . close ();
        outputFile . close ();
        return false;
    }
    inputFile . close ();
    outputFile . close ();
    return true;
}

bool decrypt_data ( const std::string & in_filename, const std::string & out_filename, crypto_config & config )
{
    ifstream inputFile (in_filename);
    if ( !inputFile . is_open() )
        return false;

    ofstream outputFile ( out_filename);
    if ( !outputFile . is_open() )
    {
        inputFile . close ();
        return false;
    }

    if ( !cipherData(inputFile, outputFile, config, false) )
    {
        inputFile . close ();
        outputFile . close ();
        return false;
    }
    inputFile . close ();
    outputFile . close ();
    return true;
}

#ifndef __PROGTEST__

bool compare_files ( const char * name1, const char * name2 )
{
    int i = 0;
    ifstream file1 (name1);
    ifstream file2 (name2);

    if (!file1 || !file2)
        return false;

    string line1, line2;
    while (getline(file1, line1) && getline(file2, line2))
    {
        if ( line1 != line2 )
        {
            cout << i << endl;
            cout << "line1 . size() - " << line1 . size() << endl;
            cout << "line1 - " << line1 << endl;
            cout << "--------------------------------" << endl;
            cout << "line2 . size() - " << line2 . size() << endl;
            cout << "line2 - " << line2 << endl;
            return false;
        }
       i++;
    }

    return (file1.eof() && file2 . eof() );
}



int main ( void )
{
    crypto_config config {nullptr, nullptr, nullptr, 0, 0};

    config.m_crypto_function = "AES-128-ECB";
    config.m_key = std::make_unique<uint8_t[]>(16);
    memset(config.m_key.get(), 0, 16);
    config.m_key_len = 16;

    encrypt_data  ("homer-simpson.TGA", "out_file.TGA", config);


//    config.m_crypto_function = "AES-128-CBC";
//    config.m_IV = std::make_unique<uint8_t[]>(16);
//    config.m_IV_len = 16;
//    memset(config.m_IV.get(), 0, 16);
//
//    encrypt_data  ("homer-simpson.TGA", "out_file.TGA", config);


/*
    // ECB mode
    config.m_crypto_function = "AES-128-ECB";
    config.m_key = std::make_unique<uint8_t[]>(16);
    memset(config.m_key.get(), 0, 16);
    config.m_key_len = 16;


    assert( encrypt_data  ("homer-simpson.TGA", "out_file.TGA", config) &&
            compare_files ("out_file.TGA", "homer-simpson_enc_ecb.TGA") );

    assert( decrypt_data  ("homer-simpson_enc_ecb.TGA", "out_file.TGA", config) &&
            compare_files ("out_file.TGA", "homer-simpson.TGA") );

    assert( encrypt_data  ("UCM8.TGA", "out_file.TGA", config) &&
            compare_files ("out_file.TGA", "UCM8_enc_ecb.TGA") );

    assert( decrypt_data  ("UCM8_enc_ecb.TGA", "out_file.TGA", config) &&
            compare_files ("out_file.TGA", "UCM8.TGA") );

    assert( encrypt_data  ("image_1.TGA", "out_file.TGA", config) &&
            compare_files ("out_file.TGA", "ref_1_enc_ecb.TGA") );

    assert( encrypt_data  ("image_2.TGA", "out_file.TGA", config) &&
            compare_files ("out_file.TGA", "ref_2_enc_ecb.TGA") );

    assert( decrypt_data ("image_3_enc_ecb.TGA", "out_file.TGA", config)  &&
            compare_files("out_file.TGA", "ref_3_dec_ecb.TGA") );

    assert( decrypt_data ("image_4_enc_ecb.TGA", "out_file.TGA", config)  &&
            compare_files("out_file.TGA", "ref_4_dec_ecb.TGA") );

    // CBC mode
    config.m_crypto_function = "AES-128-CBC";
    config.m_IV = std::make_unique<uint8_t[]>(16);
    config.m_IV_len = 16;
    memset(config.m_IV.get(), 0, 16);

    assert( encrypt_data  ("UCM8.TGA", "out_file.TGA", config) &&
            compare_files ("out_file.TGA", "UCM8_enc_cbc.TGA") );

    assert( decrypt_data  ("UCM8_enc_cbc.TGA", "out_file.TGA", config) &&
            compare_files ("out_file.TGA", "UCM8.TGA") );

    assert( encrypt_data  ("homer-simpson.TGA", "out_file.TGA", config) &&
            compare_files ("out_file.TGA", "homer-simpson_enc_cbc.TGA") );

    assert( decrypt_data  ("homer-simpson_enc_cbc.TGA", "out_file.TGA", config) &&
            compare_files ("out_file.TGA", "homer-simpson.TGA") );

    assert( encrypt_data  ("image_1.TGA", "out_file.TGA", config) &&
            compare_files ("out_file.TGA", "ref_5_enc_cbc.TGA") );

    assert( encrypt_data  ("image_2.TGA", "out_file.TGA", config) &&
            compare_files ("out_file.TGA", "ref_6_enc_cbc.TGA") );

    assert( decrypt_data ("image_7_enc_cbc.TGA", "out_file.TGA", config)  &&
            compare_files("out_file.TGA", "ref_7_dec_cbc.TGA") );

    assert( decrypt_data ("image_8_enc_cbc.TGA", "out_file.TGA", config)  &&
            compare_files("out_file.TGA", "ref_8_dec_cbc.TGA") );

    compare_files("out_5171953.bin", "ref_5171953.bin");

*/

    return 0;
}

#endif /* _PROGTEST_ */
