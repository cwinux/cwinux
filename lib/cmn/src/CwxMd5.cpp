
#include "CwxMd5.h"

CWINUX_BEGIN_NAMESPACE
/// �γ�ǩ��
void CwxMd5::update(unsigned char const *szBuf, uint32_t uiLen) {
  hex_[0] = 0x00;
  MD5_Update(&ctx_, szBuf, uiLen);
}
/**
*@brief  ���ǩ��������
*@param [out] digest ������ݵ�ǩ��.
*@return void.
*/
void CwxMd5::final(unsigned char digest[16]) {
  MD5_Final(digest_, &ctx_);
  memcpy(digest, digest_, 16);
  OPENSSL_cleanse(&ctx_, sizeof(ctx_));
}
/**
*@brief  ���ǩ����HEX
*@param [out] digest ������ݵ�ǩ��HEX.
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

