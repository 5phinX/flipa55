#include "aes-cipher-core.h"
#include "aes-cfb128.h"
#include <string.h>

#ifdef AES_CFB128_DEBUG
  #include <stdio.h>
#endif

/**
 * @brief Performs CFB128 encryption
 *
 * @param key Pointer to the key
 * @param input Input data. Input must start with an IV
 * @param output Output data
 * @param dataBlocks Number of input data blocks. This does not include IV.
 * @param keySize size of the key. Either 128 or 256
 *
 * @returns number of blocks of output
 */
unsigned int encrypt_cfb128(const unsigned char *key, const unsigned char *input, unsigned char *output, unsigned int dataBlocks, int keySize)
{
  unsigned char cipher_input[32];
  unsigned char cipher_output[32];
  unsigned int i;
  int j;

  // Copy IV to the output
  memcpy(output, input, 16);

  // Copy IV to internal variable
  memcpy(cipher_input, input, 16);

  // i denotes data blocks
  for ( i = 0; i < dataBlocks; i++ )
  {
    // Encrypt cipher input block
    cipher(key, cipher_input, cipher_output, keySize);
    #ifdef AES_CFB128_DEBUG
    printf("Segment #%d\n", i+1);
    printf("Input Block     ");
    for ( j = 0; j < 16; j++ )
    {
      printf("%.2x", cipher_input[j]);
    }
    printf("\n");
    printf("Output Block    ");
    for ( j = 0; j < 16; j++ )
    {
      printf("%.2x", cipher_output[j]);
    }
    printf("\n");
    printf("Plaintext       ");
    for ( j = 0; j < 16; j++ )
    {
      printf("%.2x", input[(i+1)*16+j]);
    }
    printf("\n");
    #endif
    // XOR plaintext
    for ( j = 0; j < 16; j++ )
    {
      cipher_input[j] = cipher_output[j] ^ input[(i+1)*16+j];
    }
    memcpy(&output[(i+1)*16], cipher_input, 16);
    #ifdef AES_CFB128_DEBUG
    printf("Ciphertext      ");
    for ( j = 0; j < 16; j++ )
    {
      printf("%.2x", output[(i+1)*16+j]);
    }
    printf("\n");
    #endif
  }

  return i;
}

/**
 * @brief Performs CFB128 decryption
 *
 * @param key Pointer to the key
 * @param input Input data. Input must start with an IV
 * @param output Output data
 * @param dataBlocks Number of input data blocks. This does not include IV.
 * @param keySize size of the key. Either 128 or 256
 *
 * @returns number of blocks of output
 */
unsigned int decrypt_cfb128(const unsigned char *key, const unsigned char *input, unsigned char *output, unsigned int dataBlocks, int keySize)
{
  unsigned char cipher_input[32];
  unsigned char cipher_output[32];
  unsigned int i;
  int j;

  // Copy IV to internal variable
  memcpy(cipher_input, input, 16);

  // i denotes data blocks
  for ( i = 0; i < dataBlocks; i++ )
  {
    // Encrypt cipher input block
    cipher(key, cipher_input, cipher_output, keySize);
    #ifdef AES_CFB128_DEBUG
    printf("Segment #%d\n", i+1);
    printf("Input Block     ");
    for ( j = 0; j < 16; j++ )
    {
      printf("%.2x", cipher_input[j]);
    }
    printf("\n");
    printf("Output Block    ");
    for ( j = 0; j < 16; j++ )
    {
      printf("%.2x", cipher_output[j]);
    }
    printf("\n");
    printf("Ciphertext      ");
    for ( j = 0; j < 16; j++ )
    {
      printf("%.2x", input[(i+1)*16+j]);
    }
    printf("\n");
    #endif
    // XOR plaintext
    for ( j = 0; j < 16; j++ )
    {
      output[(i*16)+j] = cipher_output[j] ^ input[(i+1)*16+j];
    }
    memcpy(cipher_input, &input[(i+1)*16], 16); // Next block to cipher is this ciphertext
    #ifdef AES_CFB128_DEBUG
    printf("Plaintext       ");
    for ( j = 0; j < 16; j++ )
    {
      printf("%.2x", output[i*16+j]);
    }
    printf("\n");
    #endif
  }

  return i-1;
}
