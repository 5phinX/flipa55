#ifndef __AES_CIPHER_SW_H__
#define __AES_CIPHER_SW_H__

#if defined(__cplusplus)
  extern "C" {
#endif

/**
 * @brief AES cipher core software implementation
 */

void AESKeySchedule(unsigned char *key, int round, int keySize);
void SubBytes(const unsigned char *input, unsigned char *output);
void ShiftRows(const unsigned char *input, unsigned char *output);
void MixColumns(const unsigned char *input, unsigned char *output);
void InvSubBytes(const unsigned char *input, unsigned char *output);
void InvShiftRows(const unsigned char *input, unsigned char *output);
void InvMixColumns(const unsigned char *input, unsigned char *output);
void AddRoundKey(unsigned char *key, const unsigned char *input, unsigned char *output);
static inline unsigned char xtime(unsigned char a) { return ( (a<<1) ^ (((a>>7) & 1) * 0x1b) ); };
unsigned char multiply(unsigned char a, unsigned char b);

#if defined(__cplusplus)
  } //extern
#endif

#endif /* __AES_CIPHER_SW_H__ */
