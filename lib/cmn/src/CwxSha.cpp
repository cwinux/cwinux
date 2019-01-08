/*
 */

#include "CwxSha.h"

CWINUX_BEGIN_NAMESPACE
/// 形成签名
void CwxSha::update(unsigned char const *szBuf, uint32_t uiLen) {
  hex_[0] = 0x00;
  SHA1_Update(&ctx_, szBuf, uiLen);
}
/**
*@brief  输出签名的内容
*@param [out] digest 输出内容的签名.
*@return void.
*/
void CwxSha::final(unsigned char digest[SHA_DIGEST_LENGTH]) {
  SHA1_Final(digest_, &ctx_);
  memcpy(digest, digest_, SHA_DIGEST_LENGTH);
  OPENSSL_cleanse(&ctx_, sizeof(ctx_));
}
/**
*@brief  输出签名的HEX
*@param [out] digest 输出内容的签名HEX.
*@return void.
**/
char const* CwxSha::to_hex() {
  if (!hex_[0]) {
    uint32_t len = SHA_DIGEST_LENGTH * 2 + 1;
    CwxCommon::toHex(digest_, SHA_DIGEST_LENGTH, hex_, len);
  }
  return hex_;
}

/// 形成签名
void CwxSha224::update(unsigned char const *szBuf, uint32_t uiLen) {
  hex_[0] = 0x00;
  SHA224_Update(&ctx_, szBuf, uiLen);
}
/**
*@brief  输出签名的内容
*@param [out] digest 输出内容的签名.
*@return void.
*/
void CwxSha224::final(unsigned char digest[SHA224_DIGEST_LENGTH]) {
  SHA224_Final(digest_, &ctx_);
  memcpy(digest, digest_, SHA224_DIGEST_LENGTH);
  OPENSSL_cleanse(&ctx_, sizeof(ctx_));
}
/**
*@brief  输出签名的HEX
*@param [out] digest 输出内容的签名HEX.
*@return void.
**/
char const* CwxSha224::to_hex() {
  if (!hex_[0]) {
    uint32_t len = SHA224_DIGEST_LENGTH * 2 + 1;
    CwxCommon::toHex(digest_, SHA224_DIGEST_LENGTH, hex_, len);
  }
  return hex_;
}

/// 形成签名
void CwxSha256::update(unsigned char const *szBuf, uint32_t uiLen) {
  hex_[0] = 0x00;
  SHA256_Update(&ctx_, szBuf, uiLen);
}
/**
*@brief  输出签名的内容
*@param [out] digest 输出内容的签名.
*@return void.
*/
void CwxSha256::final(unsigned char digest[SHA256_DIGEST_LENGTH]) {
  SHA256_Final(digest_, &ctx_);
  memcpy(digest, digest_, SHA256_DIGEST_LENGTH);
  OPENSSL_cleanse(&ctx_, sizeof(ctx_));
}
/**
*@brief  输出签名的HEX
*@param [out] digest 输出内容的签名HEX.
*@return void.
**/
char const* CwxSha256::to_hex() {
  if (!hex_[0]) {
    uint32_t len = SHA256_DIGEST_LENGTH * 2 + 1;
    CwxCommon::toHex(digest_, SHA256_DIGEST_LENGTH, hex_, len);
  }
  return hex_;
}

/// 形成签名
void CwxSha384::update(unsigned char const *szBuf, uint32_t uiLen) {
  hex_[0] = 0x00;
  SHA384_Update(&ctx_, szBuf, uiLen);
}
/**
*@brief  输出签名的内容
*@param [out] digest 输出内容的签名.
*@return void.
*/
void CwxSha384::final(unsigned char digest[SHA384_DIGEST_LENGTH]) {
  SHA384_Final(digest_, &ctx_);
  memcpy(digest, digest_, SHA384_DIGEST_LENGTH);
  OPENSSL_cleanse(&ctx_, sizeof(ctx_));
}
/**
*@brief  输出签名的HEX
*@param [out] digest 输出内容的签名HEX.
*@return void.
**/
char const* CwxSha384::to_hex() {
  if (!hex_[0]) {
    uint32_t len = SHA384_DIGEST_LENGTH * 2 + 1;
    CwxCommon::toHex(digest_, SHA384_DIGEST_LENGTH, hex_, len);
  }
  return hex_;
}
/// 形成签名
void CwxSha512::update(unsigned char const *szBuf, uint32_t uiLen) {
  hex_[0] = 0x00;
  SHA512_Update(&ctx_, szBuf, uiLen);
}
/**
*@brief  输出签名的内容
*@param [out] digest 输出内容的签名.
*@return void.
*/
void CwxSha512::final(unsigned char digest[SHA512_DIGEST_LENGTH]) {
  SHA512_Final(digest_, &ctx_);
  memcpy(digest, digest_, SHA512_DIGEST_LENGTH);
  OPENSSL_cleanse(&ctx_, sizeof(ctx_));
}
/**
*@brief  输出签名的HEX
*@param [out] digest 输出内容的签名HEX.
*@return void.
**/
char const* CwxSha512::to_hex() {
  if (!hex_[0]) {
    uint32_t len = SHA512_DIGEST_LENGTH * 2 + 1;
    CwxCommon::toHex(digest_, SHA512_DIGEST_LENGTH, hex_, len);
  }
  return hex_;
}

CWINUX_END_NAMESPACE

