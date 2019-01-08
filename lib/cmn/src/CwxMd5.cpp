
#include "CwxMd5.h"

CWINUX_BEGIN_NAMESPACE
/// 形成签名
void CwxMd5::update(unsigned char const *szBuf, uint32_t uiLen) {
  hex_[0] = 0x00;
  MD5_Update(&ctx_, szBuf, uiLen);
}
/**
*@brief  输出签名的内容
*@param [out] digest 输出内容的签名.
*@return void.
*/
void CwxMd5::final(unsigned char digest[16]) {
  MD5_Final(digest_, &ctx_);
  memcpy(digest, digest_, 16);
  OPENSSL_cleanse(&ctx_, sizeof(ctx_));
}
/**
*@brief  输出签名的HEX
*@param [out] digest 输出内容的签名HEX.
*@return void.
**/
char const* CwxMd5::to_hex() {
  if (!hex_[0]) {
    uint32_t len = 33;
    CwxCommon::toHex(digest_, 16, hex_, len);
  }
  return hex_;
}

CWINUX_END_NAMESPACE

