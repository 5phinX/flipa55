#include "aes-cipher-sw.h"
#include "aes-cipher-core.h"
#include <stdio.h>
#include <string.h>
#include <malloc.h>

//#define CIPHER_DEBUG
//#define KEYSCHED_DEBUG

static const unsigned char inv_sbox[256] = {
      0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
      0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
      0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
      0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
      0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
      0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
      0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
      0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
      0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
      0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
      0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
      0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
      0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
      0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
      0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
      0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
    };
static const unsigned char sbox[256] = {
      /*        0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F */
      /* 0 */ 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
      /* 1 */ 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
      /* 2 */ 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
      /* 3 */ 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
      /* 4 */ 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
      /* 5 */ 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
      /* 6 */ 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
      /* 7 */ 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
      /* 8 */ 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
      /* 9 */ 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
      /* A */ 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
      /* B */ 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
      /* C */ 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
      /* D */ 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
      /* E */ 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
      /* F */ 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    };

/**
 * @brief Performs SubBytes operation
 *
 * @param input input data block (16 bytes)
 *
 * @param output output data block (16 bytes)
 */
void SubBytes(const unsigned char *input, unsigned char *output)
{
  int i;
  for ( i = 0; i < 16; i++ )
  {
    output[i] = sbox[input[i]];
  }
}

/**
 * @brief Performs Inverse SubBytes operation
 *
 * @param input input data block (16 bytes)
 *
 * @param output output data block (16 bytes)
 */
void InvSubBytes(const unsigned char *input, unsigned char *output)
{
  int i;
  for ( i = 0; i < 16; i++ )
  {
    output[i] = inv_sbox[input[i]];
  }
}

/**
 * @brief Performs ShiftRows operation
 *
 * @param input input data block
 *
 * @param output output data block
 */
void ShiftRows(const unsigned char *input, unsigned char *output)
{
  // Shift first row by zero
  output[0] = input[0];
  output[4] = input[4];
  output[8] = input[8];
  output[12] = input[12];

  // Shift second row by one
  output[1] = input[5];
  output[5] = input[9];
  output[9] = input[13];
  output[13] = input[1];

  // Shift third row by two
  output[2] = input[10];
  output[6] = input[14];
  output[10] = input[2];
  output[14] = input[6];

  // Shift fourth row by three
  output[3] = input[15];
  output[7] = input[3];
  output[11] = input[7];
  output[15] = input[11];
}

/**
 * @brief Performs Inverse ShiftRows operation
 *
 * @param input input data block
 *
 * @param output output data block
 */
void InvShiftRows(const unsigned char *input, unsigned char *output)
{
  // Shift first row by zero
  output[0] = input[0];
  output[4] = input[4];
  output[8] = input[8];
  output[12] = input[12];

  // Shift second row by one
  output[1] = input[13];
  output[5] = input[1];
  output[9] = input[5];
  output[13] = input[9];

  // Shift third row by two
  output[2] = input[10];
  output[6] = input[14];
  output[10] = input[2];
  output[14] = input[6];

  // Shift fourth row by three
  output[3] = input[7];
  output[7] = input[11];
  output[11] = input[15];
  output[15] = input[3];
}

/**
 * @brief Performs MixColumns operation
 *
 * @param input input data block
 * @param output output data block
 */
void MixColumns(const unsigned char *input, unsigned char *output)
{
  int i;
  for ( i = 0; i < 16; i+=4 )
  {
    output[0+i]  = multiply(0x02, input[0+i]) ^ multiply(0x03, input[1+i]) ^ input[2+i] ^ input[3+i]; // First element of column i
    output[1+i]  = input[0+i] ^ multiply(0x02, input[1+i]) ^ multiply(0x03, input[2+i]) ^ input[3+i]; // Second element of column i
    output[2+i]  = input[0+i] ^ input[1+i] ^ multiply(0x02, input[2+i]) ^ multiply(0x03, input[3+i]); // Third element of column i
    output[3+i] = multiply(0x03, input[0+i]) ^ input[1+i] ^ input[2+i] ^ multiply(0x02, input[3+i]); // Fourth element of column i
  }
}

/**
 * @brief Performs Inverse MixColumns operation
 *
 * @param input input data block
 * @param output output data block
 */
void InvMixColumns(const unsigned char *input, unsigned char *output)
{
  int i;
  for ( i = 0; i < 16; i+=4 )
  {
    output[0+i] = multiply(0x0e, input[0+i]) ^ multiply(0x0b, input[1+i]) ^ multiply(0x0d, input[2+i]) ^ multiply(0x09, input[3+i]); // First element of column i
    output[1+i] = multiply(0x09, input[0+i]) ^ multiply(0x0e, input[1+i]) ^ multiply(0x0b, input[2+i]) ^ multiply(0x0d, input[3+i]); // Second element of column i
    output[2+i] = multiply(0x0d, input[0+i]) ^ multiply(0x09, input[1+i]) ^ multiply(0x0e, input[2+i]) ^ multiply(0x0b, input[3+i]); // Third element of column i
    output[3+i] = multiply(0x0b, input[0+i]) ^ multiply(0x0d, input[1+i]) ^ multiply(0x09, input[2+i]) ^ multiply(0x0e, input[3+i]); // Fourth element of column i
  }
}

/**
 * @brief Performs AddRoundKey operation
 *
 * @param key round key
 * @param input input data block
 * @param output data block
 */
void AddRoundKey(unsigned char *key, const unsigned char *input, unsigned char *output)
{
  int i;
  for ( i = 0; i < 16; i++ )
  {
    output[i] = input[i] ^ key[i];
  }
}

/**
 * @brief Computes next round key
 *
 * Computes one round key when keysize is 128 bits and two round keys when keysize is 256 bits.
 * When using 256-bit key, the round index is expected to be incremented every second round.
 *
 * @param key Current round key
 * @param round Current round index
 */
void AESKeySchedule(unsigned char *key, int round, int keySize)
{
  unsigned char rcon[10] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};
  unsigned char prev_key[32];
  unsigned char temp[4];
  int i,j;

  memcpy(prev_key, key, keySize/8);

  // Key expansion for 128-bit key
  temp[0] = key[(keySize/8)-3];
  temp[1] = key[(keySize/8)-2];
  temp[2] = key[(keySize/8)-1];
  temp[3] = key[(keySize/8)-4]; // Last 4 bytes of previous key after RotWord operation

#ifdef KEYSCHED_DEBUG
  if ( keySize == 128 )
    printf("i = %d\n", (round+1)*4);
  else
    printf("i = %d\n", (round+1)*8);
  printf("After RotWord = %.2x%.2x%.2x%.2x\n", temp[0]&0xff, temp[1]&0xff, temp[2]&0xff, temp[3]&0xff);
#endif

  temp[0] = sbox[temp[0]];
  temp[1] = sbox[temp[1]];
  temp[2] = sbox[temp[2]];
  temp[3] = sbox[temp[3]]; // SubWord
#ifdef KEYSCHED_DEBUG
  printf("After sbox = %.2x%.2x%.2x%.2x\n", temp[0]&0xff, temp[1]&0xff, temp[2]&0xff, temp[3]&0xff);
#endif
  temp[0] = temp[0] ^ rcon[round]; // Rcon

#ifdef KEYSCHED_DEBUG
  printf("Rcon = %.02x\n", rcon[round]);
  printf("After XOR = %.2x%.2x%.2x%.2x\n", temp[0]&0xff, temp[1]&0xff, temp[2]&0xff, temp[3]&0xff);
#endif

  // Computation of four key words
  for ( j=0; j<4; j++ )
  {
    for ( i=0; i<4; i++ )
    {
      temp[i] = temp[i] ^ prev_key[i+j*4];
      key[i+j*4] = temp[i];
    }
#ifdef KEYSCHED_DEBUG
    if ( keySize == 128 )
      printf("i=%d = %.2x%.2x%.2x%.2x\n",(round+1)*4+j, temp[0]&0xff, temp[1]&0xff, temp[2]&0xff, temp[3]&0xff);
    else
      printf("i=%d = %.2x%.2x%.2x%.2x\n",(round+1)*8+j, temp[0]&0xff, temp[1]&0xff, temp[2]&0xff, temp[3]&0xff);
#endif
  }

  // Second key half expansion for 256-bit key
  if ( keySize == 256 )
  {
    temp[0] = sbox[temp[0]];
    temp[1] = sbox[temp[1]];
    temp[2] = sbox[temp[2]];
    temp[3] = sbox[temp[3]]; // SubWord
#ifdef KEYSCHED_DEBUG
    printf("After sbox = %.2x%.2x%.2x%.2x\n", temp[0]&0xff, temp[1]&0xff, temp[2]&0xff, temp[3]&0xff);
#endif
    // Computation of four key words
    for ( j=4; j<8; j++ )
    {
      for ( i=0; i<4; i++ )
      {
        temp[i] = temp[i] ^ prev_key[i+j*4];
        key[i+j*4] = temp[i];
      }
#ifdef KEYSCHED_DEBUG
      printf("i=%d = %.2x%.2x%.2x%.2x\n",(round+1)*8+j, temp[0]&0xff, temp[1]&0xff, temp[2]&0xff, temp[3]&0xff);
#endif
    }
  }
}

/**
 * @brief Cipher core
 *
 * Computes one encryption (10 rounds for 128-bit key and 14 rounds for 256-bit key)
 *
 * @param key cipher key
 * @param input input data block
 * @param output output data block
 */
void cipher(const unsigned char *key, const unsigned char *input, unsigned char *output, int keySize )
{
  unsigned char state1[16];
  unsigned char state2[16];
  unsigned char roundKey[16];
  int i;
#ifdef CIPHER_DEBUG
  int j;
#endif

  unsigned char internal_key[32];
  if ( keySize == 128 )
  {
    memcpy(internal_key, key, 16);
  }
  else
  {
    memcpy(internal_key, key, 32);
  }


#ifdef CIPHER_DEBUG
  printf("round [ 0].input,");
  for ( j=0; j<16;j++)
  {
    printf("%.2x", input[j]&0xff);
  }
  printf("\n");
#endif
  AddRoundKey(internal_key, input, state1);
#ifdef CIPHER_DEBUG
  printf("round[ 0].k_sch,");
  for ( j=0; j<16;j++)
  {
    printf("%.2x", internal_key[j]&0xff);
  }
  printf("\n");
#endif

  if ( keySize == 128 )
  {
    AESKeySchedule(internal_key, 0, keySize);

    for ( i = 1; i < 10; i++ )
    {
#ifdef CIPHER_DEBUG
      printf("round[%d].start,", i);
      for ( j=0; j<16;j++)
      {
        printf("%.2x", state1[j]&0xff);
      }
      printf("\n");
#endif
      SubBytes(state1, state2);
#ifdef CIPHER_DEBUG
      printf("round[%d].s_box,", i);
      for ( j=0; j<16;j++)
      {
        printf("%.2x", state2[j]&0xff);
      }
      printf("\n");
#endif
      ShiftRows(state2, state1);
#ifdef CIPHER_DEBUG
      printf("round[%d].s_row,", i);
      for ( j=0; j<16;j++)
      {
        printf("%.2x", state1[j]&0xff);
      }
      printf("\n");
#endif
      MixColumns(state1, state2);
#ifdef CIPHER_DEBUG
      printf("round[%d].m_col,", i);
      for ( j=0; j<16;j++)
      {
        printf("%.2x", state2[j]&0xff);
      }
      printf("\n");
#endif
      AddRoundKey(internal_key, state2, state1);
#ifdef CIPHER_DEBUG
      printf("round[%d].k_sch,", i);
      for ( j=0; j<16;j++)
      {
        printf("%.2x", internal_key[j]&0xff);
      }
      printf("\n");
#endif
      AESKeySchedule(internal_key, i, keySize);
    }

  }
  else
  {
    // Load next round key
    memcpy(roundKey, &internal_key[16], 16);
    for ( i=1; i<14; i++ )
    {
#ifdef CIPHER_DEBUG
      printf("round[%d].start,", i);
      for ( j=0; j<16;j++)
      {
        printf("%.2x", state1[j]&0xff);
      }
      printf("\n");
#endif
      SubBytes(state1, state2);
#ifdef CIPHER_DEBUG
      printf("round[%d].s_box,",i);
      for ( j=0; j<16;j++)
      {
        printf("%.2x", state2[j]&0xff);
      }
      printf("\n");
#endif
      ShiftRows(state2, state1);
#ifdef CIPHER_DEBUG
      printf("round[%d].s_row,",i);
      for ( j=0; j<16;j++)
      {
        printf("%.2x", state1[j]&0xff);
      }
      printf("\n");
#endif
      MixColumns(state1, state2);
#ifdef CIPHER_DEBUG
      printf("round[%d].m_col,",i);
      for ( j=0; j<16;j++)
      {
        printf("%.2x", state2[j]&0xff);
      }
      printf("\n");
#endif
      AddRoundKey(roundKey, state2, state1);
#ifdef CIPHER_DEBUG
      printf("round[%d].k_sch,", i);
      for ( j=0; j<16;j++)
      {
        printf("%.2x", roundKey[j]&0xff);
      }
      printf("\n");
#endif
      // Compute and load next round key
      if ( i%2 == 1 )
      {
        AESKeySchedule(internal_key, (i-1)/2, keySize);
        memcpy(roundKey, internal_key, 16);
      }
      else
      {
        memcpy(roundKey, &internal_key[16], 16);
      }
    }
  }
#ifdef CIPHER_DEBUG
  printf("round[%d].start,", 10);
  for ( j=0; j<16;j++)
  {
    printf("%.2x", state1[j]&0xff);
  }
  printf("\n");
#endif
  SubBytes(state1, state2);
#ifdef CIPHER_DEBUG
  printf("round[10].s_box,");
  for ( j=0; j<16;j++)
  {
    printf("%.2x", state2[j]&0xff);
  }
  printf("\n");
#endif
  ShiftRows(state2, state1);
#ifdef CIPHER_DEBUG
  printf("round[%d].s_row,", 10);
  for ( j=0; j<16;j++)
  {
    printf("%.2x", state1[j]&0xff);
  }
  printf("\n");
#endif
  AddRoundKey(internal_key, state1, output);
#ifdef CIPHER_DEBUG
  printf("round[%d].k_sch,", 10);
  for ( j=0; j<16;j++)
  {
    printf("%.2x", internal_key[j]&0xff);
  }
  printf("\n");
  printf("round[%d].output,", 10);
  for ( j=0; j<16;j++ )
  {
    printf("%.2x", output[j]);
  }
  printf("\n");
#endif
}

/**
 * @brief Inverse cipher core
 *
 * Computes one decryption (10 rounds for 128-bit key and 14 rounds for 256-bit key)
 *
 * @param key cipher key
 * @param input input data block
 * @param output output data block
 */
void decipher(const unsigned char *key, const unsigned char *input, unsigned char *output, int keySize)
{
  unsigned char state1[16];
  unsigned char state2[16];
  int round;
  unsigned char roundKeys[16][16];
  int i;
#ifdef CIPHER_DEBUG
  int j;
#endif

  // Compute round keys
  if ( keySize == 128 )
  {
    round = 9;
    memcpy(roundKeys[0], key, 16);
    for ( i = 1; i < 11; i++ )
    {
      memcpy(roundKeys[i], roundKeys[i-1], 16);
      AESKeySchedule(roundKeys[i], i-1, keySize);
    }
  }
  else
  {
    unsigned char tmpKey[32];
    round = 13;
    memcpy(roundKeys[0], key, 16);
    memcpy(roundKeys[1], &key[16], 16);
    memcpy(tmpKey, key, 32);
    for ( i = 2; i < 16; i++ )
    {
      if ( i%2 == 1 )
      {
        AESKeySchedule(tmpKey, (i-3)/2, keySize);
        memcpy(roundKeys[i-1], tmpKey, 16);
        memcpy(roundKeys[i], &tmpKey[16], 16);
      }
    }
  }

#ifdef CIPHER_DEBUG
  printf("round [ 0].input,");
  for ( j=0; j<16;j++)
  {
    printf("%.2x", input[j]&0xff);
  }
  printf("\n");
#endif
  AddRoundKey(roundKeys[round+1], input, state1);
#ifdef CIPHER_DEBUG
  printf("round[ 0].k_sch,");
  for ( j=0; j<16;j++)
  {
    printf("%.2x", roundKeys[round+1][j]&0xff);
  }
  printf("\n");
#endif

  for ( ; round > 0; round-- )
  {
#ifdef CIPHER_DEBUG
    printf("round[%d].start,", round);
    for ( j=0; j<16;j++)
    {
      printf("%.2x", state1[j]&0xff);
    }
    printf("\n");
#endif
    InvShiftRows(state1, state2);
#ifdef CIPHER_DEBUG
    printf("round[%d].s_row,", round);
    for ( j=0; j<16;j++)
    {
      printf("%.2x", state2[j]&0xff);
    }
    printf("\n");
#endif
    InvSubBytes(state2, state1);
#ifdef CIPHER_DEBUG
    printf("round[%d].s_box,", round);
    for ( j=0; j<16;j++)
    {
      printf("%.2x", state1[j]&0xff);
    }
    printf("\n");
#endif
    AddRoundKey(roundKeys[round], state1, state2);
#ifdef CIPHER_DEBUG
    printf("round[%d].k_sch,", round);
    for ( j=0; j<16;j++)
    {
      printf("%.2x", roundKeys[round][j]&0xff);
    }
    printf("\n");
#endif
    InvMixColumns(state2, state1);
#ifdef CIPHER_DEBUG
    printf("round[%d].m_col,", round);
    for ( j=0; j<16;j++)
    {
      printf("%.2x", state1[j]&0xff);
    }
    printf("\n");
#endif
  }

#ifdef CIPHER_DEBUG
  printf("round[%d].start,", 10);
  for ( j=0; j<16;j++)
  {
    printf("%.2x", state1[j]&0xff);
  }
  printf("\n");
#endif
  InvShiftRows(state1, state2);
#ifdef CIPHER_DEBUG
  printf("round[%d].s_row,", 10);
  for ( j=0; j<16;j++)
  {
    printf("%.2x", state2[j]&0xff);
  }
  printf("\n");
#endif
  InvSubBytes(state2, state1);
#ifdef CIPHER_DEBUG
  printf("round[10].s_box,");
  for ( j=0; j<16;j++)
  {
    printf("%.2x", state1[j]&0xff);
  }
  printf("\n");
#endif
  AddRoundKey(roundKeys[0], state1, output);
#ifdef CIPHER_DEBUG
  printf("round[%d].k_sch,", 10);
  for ( j=0; j<16;j++)
  {
    printf("%.2x", roundKeys[0][j]&0xff);
  }
  printf("\n");
  printf("round[%d].output,", 10);
  for ( j=0; j<16;j++ )
  {
    printf("%.2x", output[j]);
  }
  printf("\n");
#endif
}

/**
 * @brief Multiplies two bytes in GF(2^n)
 *
 * @param a first operand
 * @param b second operand
 * @returns result of modular multiplication of @a a and @a b
 */
unsigned char multiply(unsigned char a, unsigned char b)
{
  char times[8];
  int i;
  char output = 0;
  volatile char dummy = 0;
  char bits = b;

  times[0] = a;
  times[1] = xtime(a);
  times[2] = xtime(times[1]);
  times[3] = xtime(times[2]);
  times[4] = xtime(times[3]);
  times[5] = xtime(times[4]);
  times[6] = xtime(times[5]);
  times[7] = xtime(times[6]);

  for ( i = 0; i < 8; i++ )
  {
    if ( 1 == (bits & 0x1) )
    {
      output = output ^ times[i];
    }
    else
    {
      dummy = dummy ^ times[i];
    }
    bits = bits >> 1;
  }
  return output;
}
