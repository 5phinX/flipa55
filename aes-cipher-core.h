#ifndef __AES_CIPHER_CORE_H__
#define __AES_CIPHER_CORE_H__

#if defined(__cplusplus)
  extern "C" {
#endif

void cipher(const unsigned char *key, const unsigned char *input, unsigned char *output, int keySize);
void decipher(const unsigned char *key, const unsigned char *input, unsigned char *output, int keySize);

#if defined(__cplusplus)
  } //extern
#endif

#endif /* __AES_CIPHER_CORE_H__ */
