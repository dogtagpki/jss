/*
 * NistSP800_108KDF.cpp - Implements the new Key Diversification Function (KDF) as required
 *                        by the latest Department of Defense SIPRnet token interface
 *                        specification.  The functions in this file are internally called
 *                        by other functions in the Symkey library.  We have made patches
 *                        to these other Symkey functions to trigger this new KDF routine
 *                        at the appropriate times.
 *
 *                        Also provides a utility function for adding DES key parity.
 */

//*******************************************************************************

#include "NistSP800_108KDF.h"

//*******************************************************************************

#include <cstring>    // memset()
#include <sstream>    // std::ostringstream

#ifdef NISTSP800_108_KDF_DEBUG
#include <iostream>
#endif

#include "pk11pub.h"

//*******************************************************************************

namespace NistSP800_108KDF{

//*******************************************************************************
// Generates three PK11SymKey objects using the KDF_CM_SHA256HMAC_L384() function for key data.
// After calling KDF_CM_SHA256HMAC_L384, the function splits up the output, sets DES parity,
//   and imports the keys into the token.
//
// Careful:  This function currently generates the key data **IN RAM** using calls to NSS sha256.
//           The key data is then "unwrapped" (imported) to the NSS token and then erased from RAM.
//           (This means that a malicious actor on the box could steal the key data.)
//
// Note: Returned key material from the KDF is converted into keys according to the following:
//   * Bytes 0  - 15 : enc/auth key
//   * Bytes 16 - 31 : mac key
//   * Bytes 32 - 47 : kek key
//   We chose this order to conform with the key order used by the PUT KEY command.
//
//*******************************************************************************
void ComputeCardKeys(  PK11SymKey* masterKey,               // Key Derivation Key
                       const BYTE* context,                 // unique data passed to the kdf (kdd)
                       const size_t context_length,         // length of context
                       PK11SymKey** encKey,                 // output parameter: generated enc/auth key
                       PK11SymKey** macKey,                 // output parameter: generated mac key
                       PK11SymKey** kekKey)                 // output parameter: generated kek key
{

    // sanity check input parameters
    if (masterKey == NULL){
        throw std::runtime_error("Input parameter \"masterKey\" was NULL.");
    }
    if (context == NULL){
        throw std::runtime_error("Input parameter \"context\" was NULL.");
    }

    // sanity check output parameters
    if (*encKey != NULL){
        throw std::runtime_error("Output parameter \"encKey\" wasn't initialized to NULL. Overwriting may result in a memory leak.");
    }
    if (*macKey != NULL){
        throw std::runtime_error("Output parameter \"macKey\" wasn't initialized to NULL. Overwriting may result in a memory leak.");
    }
    if (*kekKey != NULL){
        throw std::runtime_error("Output parameter \"kekKey\" wasn't initialized to NULL. Overwriting may result in a memory leak.");
    }

    // allocate space for KDF output
    BYTE kdf_output[KDF_OUTPUT_SIZE_BYTES];

    try{
        // generate 384 bits of key data from the master key
        KDF_CM_SHA256HMAC_L384(masterKey, context, context_length, KDF_LABEL, kdf_output, KDF_OUTPUT_SIZE_BYTES);
    }catch(std::runtime_error& ex){
        std::ostringstream msg;
        msg << "Exception invoking NistSP800_108KDF::KDF_CM_SHA256HMAC_L384: ";
        if (ex.what() == NULL){
            msg << "NULL";
        }else{
            msg << ex.what();
        }
        throw std::runtime_error(msg.str());
    }catch(...){
        throw std::runtime_error("Unknown exception invoking NistSP800_108KDF::KDF_CM_SHA256HMAC_L384.");
    }

    try{
        // get slot from master key
        //   (we need the slot to be able to generate our temp key and unwrap our generated bytes
        PK11SlotInfo* slot = PK11_GetSlotFromKey(masterKey);
        if (slot == NULL){
            throw std::runtime_error("Failed to get slot from masterKey.");
        }
        try{
            // generate a temp key to import the key data with
            PK11SymKey* tmpKey = PK11_TokenKeyGenWithFlags(slot,               // slot handle
                                                           CKM_DES3_KEY_GEN,   // mechanism type
                                                           NULL,               // pointer to params (SECItem structure)
                                                           0,                  // keySize (per documentation in pk11skey.c, must be 0 for fixed key length algorithms)
                                                           0,                  // pointer to keyid (SECItem structure)
                                                           CKF_WRAP | CKF_UNWRAP | CKF_ENCRYPT | CKF_DECRYPT, // opFlags
                                                           PK11_ATTR_PRIVATE | PK11_ATTR_UNEXTRACTABLE | PK11_ATTR_SENSITIVE, // attrFlags (AC: this is my "best guess" as to what flags should be set)
                                                           NULL);              // pointer to wincx (AC: also my "best guess" - per pkix_sample_modules.h line 265, this should always be NULL on non-Windows)
            if (tmpKey == NULL) {
                throw std::runtime_error("Unable to create temp key (for use with importing the key data).");
            }
            try{

                // set parity on each of the 3 generated **16 byte** keys
                set_des_parity(kdf_output + (0 * KEY_DATA_SIZE_BYTES), KEY_DATA_SIZE_BYTES);
                set_des_parity(kdf_output + (1 * KEY_DATA_SIZE_BYTES), KEY_DATA_SIZE_BYTES);
                set_des_parity(kdf_output + (2 * KEY_DATA_SIZE_BYTES), KEY_DATA_SIZE_BYTES);

                try{
                    // copy byte array information into 2-key 3DES PK11 keys on token
                    *encKey = Copy2Key3DESKeyDataToToken(slot, tmpKey, kdf_output + (0 * KEY_DATA_SIZE_BYTES), KEY_DATA_SIZE_BYTES);
                    *macKey = Copy2Key3DESKeyDataToToken(slot, tmpKey, kdf_output + (1 * KEY_DATA_SIZE_BYTES), KEY_DATA_SIZE_BYTES);
                    *kekKey = Copy2Key3DESKeyDataToToken(slot, tmpKey, kdf_output + (2 * KEY_DATA_SIZE_BYTES), KEY_DATA_SIZE_BYTES);
                }catch(...){
                    // free any keys we created before rethrowing
                    if (*encKey != NULL){
                        PK11_FreeSymKey(*encKey);
                        *encKey = NULL;
                    }
                    if (*macKey != NULL){
                        PK11_FreeSymKey(*macKey);
                        *macKey = NULL;
                    }
                    if (*kekKey != NULL){
                        PK11_FreeSymKey(*kekKey);
                        *kekKey = NULL;
                    }

                    throw;
                }

                // clean up
                PK11_FreeSymKey(tmpKey);
                tmpKey = NULL;
            }catch(...){
                // clean up
                PK11_FreeSymKey(tmpKey);
                tmpKey = NULL;

                throw;
            }
            // clean up
            PK11_FreeSlot(slot);
            slot = NULL;
        }catch(...){
            // clean up
            PK11_FreeSlot(slot);
            slot = NULL;

            throw;
        }

        // erase key data from RAM
        memset(kdf_output, 0, KDF_OUTPUT_SIZE_BYTES);
    }catch(...){
        // erase key data from RAM before rethrowing
        memset(kdf_output, 0, KDF_OUTPUT_SIZE_BYTES);

        throw;
    }
}

// uses the specified temporary key to encrypt and then unwrap (decrypt) the specified binary data onto the specified token
// this has the net effect of copying the raw key data to the token
PK11SymKey* Copy2Key3DESKeyDataToToken( PK11SlotInfo* slot,      // slot to unwrap key onto
                                        PK11SymKey* tmpKey,      // temporary key to use (must already be on the slot)
                                        const BYTE* const data,  // pointer to array containing the key data to encrypt and then unwrap (decrypt) on the token
                                        const size_t data_len)   // length of data in above array
{

    // ensure expected input data size
    if (data_len != KEY_DATA_SIZE_BYTES){
        throw std::runtime_error("Invalid data length value (should be 16) (Copy2Key3DESKeyDataToToken).");
    }

    // create encryption context
    SECItem noParams = { siBuffer, NULL, 0 };
    PK11Context* context = PK11_CreateContextBySymKey(CKM_DES3_ECB,   // mechanism type
                                                      CKA_ENCRYPT,    // operation type
                                                      tmpKey,         // symKey to operate on
                                                      &noParams);     // pointer to param (SECItem structure)
    if (context == NULL) {
        throw std::runtime_error("Unable to create context (Copy2Key3DESKeyDataToToken).");
    }
    try{
        BYTE encryptedData[KEY_DATA_SIZE_BYTES + 8];
        BYTE unencryptedData[KEY_DATA_SIZE_BYTES + 8];

        // copy the key data to a new (larger) buffer
        memcpy(unencryptedData, data, KEY_DATA_SIZE_BYTES);

        // copy first DES key (of the two) into the end of the buffer
        //  (key1-key2-key1)
        memcpy(unencryptedData + KEY_DATA_SIZE_BYTES, data, 8);

        try{

            // encrypt key data with the temp key
            int encryptedData_result_len = -1;
            SECStatus result = PK11_CipherOp( context,                      // [in] pointer to PK11Context object
                                              encryptedData,                // [out] pointer to output buffer for encrypted data
                                              &encryptedData_result_len,    // [out] pointer to output buffer length
                                              KEY_DATA_SIZE_BYTES + 8,      // [in] size of output buffer
                                              unencryptedData,              // [in] pointer to input buffer for unencrypted data
                                              KEY_DATA_SIZE_BYTES + 8);     // [in] size of input buffer
            if (result != SECSuccess){
                throw std::runtime_error("Unable to encrypt plaintext key data with temporary key (Copy2Key3DESKeyDataToToken).");
            }
            if (encryptedData_result_len != KEY_DATA_SIZE_BYTES + 8){
                throw std::runtime_error("Invalid output encrypting plaintext key data with temporary key (Copy2Key3DESKeyDataToToken).");
            }

            // now "unwrap" the encrypted key data onto the token with the temporary key
            SECItem wrappeditem;
            wrappeditem.type = siBuffer;
            wrappeditem.data = encryptedData;
            wrappeditem.len = encryptedData_result_len;
            noParams.type = siBuffer;
            noParams.data = NULL;
            noParams.len = 0;
            PK11SymKey* const resultingKey = PK11_UnwrapSymKeyWithFlags(tmpKey,                      // pointer to wrappingKey (PK11SymKey)
                                                                        CKM_DES3_ECB,                // wrapType (CK_MECHANISM_TYPE)
                                                                        &noParams,                   // pointer to param (SECItem struct)
                                                                        &wrappeditem,                // pointer to wrappedKey data (SECItem struct)
                                                                        CKM_DES3_KEY_GEN,            // target (CK_MECHANISM_TYPE)
                                                                        CKA_DECRYPT,                 // operation (CK_ATTRIBUTE_TYPE)
                                                                        KEY_DATA_SIZE_BYTES + 8,     // keySize (int)
                                                                        CKF_SIGN | CKF_WRAP | CKF_UNWRAP | CKF_ENCRYPT | CKF_DECRYPT); // flags (CK_FLAGS)
            if (resultingKey == NULL){
                throw std::runtime_error("Unable to unwrap key onto token (Copy2Key3DESKeyDataToToken).");
            }

            // zeroize unencrypted key data before returning
            memset(unencryptedData, 0, KEY_DATA_SIZE_BYTES + 8);

            // clean up
            PK11_DestroyContext(context, PR_TRUE);

            return resultingKey;
        }catch(...){
            // zeroize unencrypted key data before rethrowing
            memset(unencryptedData, 0, KEY_DATA_SIZE_BYTES + 8);

            throw;
        }

    }catch(...){
        // clean up
        PK11_DestroyContext(context, PR_TRUE);

        throw;
    }
}

//*******************************************************************************
// Key Derivation Function in Counter Mode using PRF = SHA256HMAC (NIST SP 800-108)
//   Calculates 384 bits of diversified output from the provided master key (K_I)
//*******************************************************************************
void KDF_CM_SHA256HMAC_L384(  PK11SymKey* K_I,                     // Key Derivation Key
                              const BYTE* context,                 // unique data passed to the kdf (kdd)
                              const size_t context_length,         // length of context
                              const BYTE label,                    // one BYTE label parameter
                              BYTE* const output,                  // output is a L-bit array of BYTEs
                              const size_t output_length)          // output length must be at least 48 bytes
{
    //unsigned int h_bits = SHA256_LENGTH * 8;      // SHA256_HMAC output size = 256 bits
    //unsigned int h_bytes = SHA256_LENGTH;         // SHA256_HMAC output size = 32 bytes
    //const unsigned int r_bits = 8;                // The counter will be representable in 8 bits
    //unsigned int n = L / h_bits;                  // Number of iterations of the PRF
    //unsigned int L_BYTE_array_length = (int)ceil(L/256.0);

    const BYTE n = 2;                               // ceil(384 / (SHA256LENGTH * 8)) == 2
    const size_t L_BYTE_array_length = 2;           // 384 = 0x0180 hex; 2 byte long representation

    // sanity check that output buffer is large enough to contain 384 bits
    if (output_length < KDF_OUTPUT_SIZE_BYTES){
        throw std::runtime_error("Array \"output\" must be at least 48 bytes in size.");
    }

    // calculate size of temporary buffer
    size_t HMAC_DATA_INPUT_SIZE = context_length + 3 + L_BYTE_array_length; // Don't change without reviewing code below.
    // prevent integer overflow
    if (HMAC_DATA_INPUT_SIZE < context_length){
        throw std::runtime_error("Input parameter \"context_length\" too large.");
    }
    BYTE* hmac_data_input = new BYTE[HMAC_DATA_INPUT_SIZE];                 // Hash Input = context + 5 BYTES

    BYTE K[n * SHA256_LENGTH];                                              // BYTE K[n * h_bytes]; - Buffer to store PRF output
    try{
        const BYTE L_BYTE_array[L_BYTE_array_length] = {0x01, 0x80};        // Array to store L in BYTES

        /* Establish HMAC Input */
        memset(hmac_data_input, 0, HMAC_DATA_INPUT_SIZE);
        hmac_data_input[1] = label;
        hmac_data_input[2] = 0x00;
        memcpy(&hmac_data_input[3], context, context_length);
        memcpy(&hmac_data_input[context_length+3], L_BYTE_array, 2);

        for(BYTE i = 1; i <= n; i++){
            // hmac_data_input = i || label || 0x00 || context || L
            hmac_data_input[0] = i;

#ifdef NISTSP800_108_KDF_DEBUG
            std::cout << "hmac_data_input:\n";
            print_BYTE_array(hmac_data_input, HMAC_DATA_INPUT_SIZE); // 5 bytes added to context
#endif

            SHA256HMAC(K_I, hmac_data_input, HMAC_DATA_INPUT_SIZE, &K[(i - 1) * SHA256_LENGTH]);
        }

        // clean up
        delete[] hmac_data_input;
        hmac_data_input = NULL;

    // upon exception, clean up before rethrowing
    }catch(...){
        // clean up
        delete[] hmac_data_input;
        hmac_data_input = NULL;

        throw;
    }

#ifdef NISTSP800_108_KDF_DEBUG
    std::cout << "KDF Output (untrimmed):\n";
    print_BYTE_array(K, n * SHA256_LENGTH);
#endif

    // copy result to output buffer, trimming it to 384 bits
    memcpy(output, K, KDF_OUTPUT_SIZE_BYTES);

    // clear K before returning
    memset(K, 0, n * SHA256_LENGTH);
}

//*******************************************************************************

void SHA256HMAC(     PK11SymKey* key,                  // HMAC Secret Key (K_I)
                     const BYTE* input,                // HMAC Input (i||04||00||context||0180)
                     const size_t input_length,        // Input Length
                     BYTE* const output)               // Output Buffer (32 BYTES written)
{
    unsigned int len = 32;
    PK11Context *context = 0;
    SECStatus s;
    SECItem noParams;
    noParams.type = siBuffer;
    noParams.data = 0;
    noParams.len = 0;

    context = PK11_CreateContextBySymKey(CKM_SHA256_HMAC, CKA_SIGN, key, &noParams);
    if (!context) {
        throw std::runtime_error("CreateContextBySymKey failed");
    }
    try{

        s = PK11_DigestBegin(context);
        if (s != SECSuccess) {
            throw std::runtime_error("DigestBegin failed");
        }

        s = PK11_DigestOp(context, input, input_length);
        if (s != SECSuccess) {
            throw std::runtime_error("DigestOp failed");
        }

        s = PK11_DigestFinal(context, output, &len, 32);
        if (s != SECSuccess) {
            throw std::runtime_error("DigestFinal failed");
        }

/* Debug Output */
#ifdef NISTSP800_108_KDF_DEBUG
        std::cout << "********************SHA256HMAC_NSS********************\n";
        std::cout << "\nInput Data:\n";
        print_BYTE_array(input, input_length);
        std::cout << "\nSHA256HMAC_NSS output:\n";
        print_BYTE_array(output, SHA256_LENGTH);
#endif

        PK11_DestroyContext(context, PR_TRUE);
    }catch(...){
        PK11_DestroyContext(context, PR_TRUE);
        throw;
    }
}

//*******************************************************************************
//    DES Parity Functions
//*******************************************************************************

/* DES KEY Parity conversion table. Takes each byte >> 1 as an index, returns
 * that byte with the proper parity bit set*/
const unsigned char parityTable[256] =
  {
  /* Even...0x00,0x02,0x04,0x06,0x08,0x0a,0x0c,0x0e */
  /* E */0x01, 0x02, 0x04, 0x07, 0x08, 0x0b, 0x0d, 0x0e,
  /* Odd....0x10,0x12,0x14,0x16,0x18,0x1a,0x1c,0x1e */
  /* O */0x10, 0x13, 0x15, 0x16, 0x19, 0x1a, 0x1c, 0x1f,
  /* Odd....0x20,0x22,0x24,0x26,0x28,0x2a,0x2c,0x2e */
  /* O */0x20, 0x23, 0x25, 0x26, 0x29, 0x2a, 0x2c, 0x2f,
  /* Even...0x30,0x32,0x34,0x36,0x38,0x3a,0x3c,0x3e */
  /* E */0x31, 0x32, 0x34, 0x37, 0x38, 0x3b, 0x3d, 0x3e,
  /* Odd....0x40,0x42,0x44,0x46,0x48,0x4a,0x4c,0x4e */
  /* O */0x40, 0x43, 0x45, 0x46, 0x49, 0x4a, 0x4c, 0x4f,
  /* Even...0x50,0x52,0x54,0x56,0x58,0x5a,0x5c,0x5e */
  /* E */0x51, 0x52, 0x54, 0x57, 0x58, 0x5b, 0x5d, 0x5e,
  /* Even...0x60,0x62,0x64,0x66,0x68,0x6a,0x6c,0x6e */
  /* E */0x61, 0x62, 0x64, 0x67, 0x68, 0x6b, 0x6d, 0x6e,
  /* Odd....0x70,0x72,0x74,0x76,0x78,0x7a,0x7c,0x7e */
  /* O */0x70, 0x73, 0x75, 0x76, 0x79, 0x7a, 0x7c, 0x7f,
  /* Odd....0x80,0x82,0x84,0x86,0x88,0x8a,0x8c,0x8e */
  /* O */0x80, 0x83, 0x85, 0x86, 0x89, 0x8a, 0x8c, 0x8f,
  /* Even...0x90,0x92,0x94,0x96,0x98,0x9a,0x9c,0x9e */
  /* E */0x91, 0x92, 0x94, 0x97, 0x98, 0x9b, 0x9d, 0x9e,
  /* Even...0xa0,0xa2,0xa4,0xa6,0xa8,0xaa,0xac,0xae */
  /* E */0xa1, 0xa2, 0xa4, 0xa7, 0xa8, 0xab, 0xad, 0xae,
  /* Odd....0xb0,0xb2,0xb4,0xb6,0xb8,0xba,0xbc,0xbe */
  /* O */0xb0, 0xb3, 0xb5, 0xb6, 0xb9, 0xba, 0xbc, 0xbf,
  /* Even...0xc0,0xc2,0xc4,0xc6,0xc8,0xca,0xcc,0xce */
  /* E */0xc1, 0xc2, 0xc4, 0xc7, 0xc8, 0xcb, 0xcd, 0xce,
  /* Odd....0xd0,0xd2,0xd4,0xd6,0xd8,0xda,0xdc,0xde */
  /* O */0xd0, 0xd3, 0xd5, 0xd6, 0xd9, 0xda, 0xdc, 0xdf,
  /* Odd....0xe0,0xe2,0xe4,0xe6,0xe8,0xea,0xec,0xee */
  /* O */0xe0, 0xe3, 0xe5, 0xe6, 0xe9, 0xea, 0xec, 0xef,
  /* Even...0xf0,0xf2,0xf4,0xf6,0xf8,0xfa,0xfc,0xfe */
  /* E */0xf1, 0xf2, 0xf4, 0xf7, 0xf8, 0xfb, 0xfd, 0xfe, };

void set_des_parity(BYTE* const key, const size_t length)
{
    if(length != 2*8){
        throw std::runtime_error("set_des_parity failed: wrong key size");
    }

    for (size_t i=0; i < length; i++)
    {
        key[i] = parityTable[key[i]>>1];
    }
}

//*******************************************************************************
//   BYTE Array Management Functions
//*******************************************************************************
#ifdef NISTSP800_108_KDF_DEBUG
void print_BYTE_array(const BYTE *array2, const size_t length)
{
    for (size_t i = 0; i < length; i++){
        printf("%02x ", array2[i]);
        if((i+1)%16 == 0)
            printf("\n");
    }
    std::cout << std::endl;
}
#endif

//*******************************************************************************
// NistSP800_108KDF Decision-Making Functions
//*******************************************************************************
// Returns true if the new KDF should be used, otherwise false.
bool useNistSP800_108KDF(BYTE nistSP800_108KDFonKeyVersion, BYTE requestedKeyVersion){
    return (requestedKeyVersion >= nistSP800_108KDFonKeyVersion);
}

//*******************************************************************************

} // end namespace NistSP800_108KDF

//*******************************************************************************
