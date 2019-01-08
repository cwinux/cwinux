
#include "CwxAes.h"

CWINUX_BEGIN_NAMESPACE
// 初始化, bits为128、192、256。
// 返回值：true： 成功；false： 密钥长度不是128，192，256；
bool CwxAesEncrypt::init(unsigned char const* key, unsigned char const* iv, int bits) {
  if (!isvalid_bits(bits)) {
    snprintf(err_, 1023, "key's length must be 128 or 192 or 256 bits. it's [%d]", bits);
    return false;
  }
  memcpy(key_, key, bits/8);
  memcpy(src_iv_, iv, bits/8);
  memcpy(iv_, iv, bits/8);
  bits_ = bits;
  AES_set_encrypt_key(key_, bits_, &aes_);
  return true;
}
// encrypt。false：len%16<>0
bool CwxAesEncrypt::encrypt(unsigned char const *from, unsigned char *to, int len) {
  if (len%AES_BLOCK_SIZE) {
    snprintf(err_, 1023, "encrypted string must be [n * AES_BLOCK_SIZE], AES_BLOCK_SIZE:%d, it's %d.", AES_BLOCK_SIZE, len);
    return false;
  }
  AES_cbc_encrypt(from, to, len, &aes_, iv_, AES_ENCRYPT);
  return true;
}

// 初始化, bits为128、192、256。
// 返回值：true： 成功；false： 密钥长度不是128，192，256；
bool CwxAesDecrypt::init(unsigned char const* key, unsigned char const* iv, int bits) {
  if (!isvalid_bits(bits)) {
    snprintf(err_, 1023, "key's length must be 128 or 192 or 256 bits. it's [%d]", bits);
    return false;
  }
  memcpy(key_, key, bits / 8);
  memcpy(src_iv_, iv, bits / 8);
  memcpy(iv_, iv, bits / 8);
  bits_ = bits;
  AES_set_decrypt_key(key_, bits_, &aes_);
  return true;
}
// decrypt。false：len%16<>0
bool CwxAesDecrypt::decrypt(unsigned char const *from, unsigned char *to, int len) {
  if (len%AES_BLOCK_SIZE) {
    snprintf(err_, 1023, "decrypted string must be [n * AES_BLOCK_SIZE], AES_BLOCK_SIZE:%d, it's %d.", AES_BLOCK_SIZE, len);
    return false;
  }
  AES_cbc_encrypt(from, to, len, &aes_, iv_, AES_DECRYPT);
  return true;
}

CWINUX_END_NAMESPACE

