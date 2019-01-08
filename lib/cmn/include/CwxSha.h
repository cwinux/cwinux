#ifndef __CWX_SHA_H__
#define __CWX_SHA_H__
/*
版权声明：
    本软件遵循GNU LGPL (Lesser General Public License)（http://www.gnu.org/licenses/gpl.html），
    联系方式：email:cwinux@gmail.com；微博:http://weibo.com/cwinux
*/


/**
*@file  CwxSha256.h
*@brief  
*@author cwinux@gmail.com
*@version 0.1
*@date    2017-12-16
*@warning 无
*@bug   
*/

#include "CwxPre.h"
#include "CwxGlobalMacro.h"
#include "CwxType.h"
#include <iostream>
#include <string>
#include <string.h>
#include "openssl/md5.h"
#include "openssl/sha.h"
#include "openssl/des.h"
#include "openssl/rsa.h"
#include "openssl/pem.h"
#include "CwxCommon.h"
CWINUX_BEGIN_NAMESPACE
/**
*@class  CwxSha
*@brief  Sha签名对象。此对象多线程不安全，在多线程环境下，
        每个线程需要自己的一个对象实例。
*/

class CwxSha {
public:
    ///构造函数
    CwxSha(){
      SHA1_Init(&ctx_);
      memset(digest_, 0x00, SHA_DIGEST_LENGTH);
      memset(hex_, 0x00, SHA_DIGEST_LENGTH * 2 + 1);
    }
    ///析构函数
    ~CwxSha() { }
public:
    /**
    *@brief  根据buf的内容，对Sha签名进行更新
    *@param [in] szBuf 签名的内容.
    *@param [in] uiLen 内容的长度.
    *@return void.
    */
    void update(unsigned char const *szBuf, uint32_t uiLen);
    /**
    *@brief  输出签名的内容
    *@param [out] digest 输出内容的签名.
    *@return void.
    */
    void final(unsigned char digest[SHA_DIGEST_LENGTH]);
    /**
    *@brief  输出签名的HEX
    *@param [out] digest 输出内容的签名HEX.
    *@return void.
    **/
    char const* to_hex();
    /**
    ** HEX 长度
    **/
    uint32_t hex_len() const { return SHA_DIGEST_LENGTH * 2; }
public:
private:
  unsigned char          digest_[SHA_DIGEST_LENGTH];
  char                   hex_[SHA_DIGEST_LENGTH*2 + 1];
  SHA_CTX                ctx_;
};

class CwxSha224 {
public:
  ///构造函数
  CwxSha224() {
    SHA224_Init(&ctx_);
    memset(digest_, 0x00, SHA224_DIGEST_LENGTH);
    memset(hex_, 0x00, SHA224_DIGEST_LENGTH * 2 + 1);
  }
  ///析构函数
  ~CwxSha224() { }
public:
  /**
  *@brief  根据buf的内容，对Sha签名进行更新
  *@param [in] szBuf 签名的内容.
  *@param [in] uiLen 内容的长度.
  *@return void.
  */
  void update(unsigned char const *szBuf, uint32_t uiLen);
  /**
  *@brief  输出签名的内容
  *@param [out] digest 输出内容的签名.
  *@return void.
  */
  void final(unsigned char digest[SHA224_DIGEST_LENGTH]);
  /**
  *@brief  输出签名的HEX
  *@param [out] digest 输出内容的签名HEX.
  *@return void.
  **/
  char const* to_hex();
  /**
  ** HEX 长度
  **/
  uint32_t hex_len() const { return SHA224_DIGEST_LENGTH * 2; }
public:
private:
  unsigned char          digest_[SHA224_DIGEST_LENGTH];
  char                   hex_[SHA224_DIGEST_LENGTH * 2 + 1];
  SHA256_CTX             ctx_;
};

class CwxSha256 {
public:
  ///构造函数
  CwxSha256() {
    SHA256_Init(&ctx_);
    memset(digest_, 0x00, SHA256_DIGEST_LENGTH);
    memset(hex_, 0x00, SHA256_DIGEST_LENGTH * 2 + 1);
  }
  ///析构函数
  ~CwxSha256() { }
public:
  /**
  *@brief  根据buf的内容，对Sha签名进行更新
  *@param [in] szBuf 签名的内容.
  *@param [in] uiLen 内容的长度.
  *@return void.
  */
  void update(unsigned char const *szBuf, uint32_t uiLen);
  /**
  *@brief  输出签名的内容
  *@param [out] digest 输出内容的签名.
  *@return void.
  */
  void final(unsigned char digest[SHA256_DIGEST_LENGTH]);
  /**
  *@brief  输出签名的HEX
  *@param [out] digest 输出内容的签名HEX.
  *@return void.
  **/
  char const* to_hex();
  /**
  ** HEX 长度
  **/
  uint32_t hex_len() const { return SHA256_DIGEST_LENGTH * 2; }
public:
private:
  unsigned char          digest_[SHA256_DIGEST_LENGTH];
  char                   hex_[SHA256_DIGEST_LENGTH * 2 + 1];
  SHA256_CTX             ctx_;
};

class CwxSha384 {
public:
  ///构造函数
  CwxSha384() {
    SHA384_Init(&ctx_);
    memset(digest_, 0x00, SHA384_DIGEST_LENGTH);
    memset(hex_, 0x00, SHA384_DIGEST_LENGTH * 2 + 1);
  }
  ///析构函数
  ~CwxSha384() { }
public:
  /**
  *@brief  根据buf的内容，对Sha签名进行更新
  *@param [in] szBuf 签名的内容.
  *@param [in] uiLen 内容的长度.
  *@return void.
  */
  void update(unsigned char const *szBuf, uint32_t uiLen);
  /**
  *@brief  输出签名的内容
  *@param [out] digest 输出内容的签名.
  *@return void.
  */
  void final(unsigned char digest[SHA384_DIGEST_LENGTH]);
  /**
  *@brief  输出签名的HEX
  *@param [out] digest 输出内容的签名HEX.
  *@return void.
  **/
  char const* to_hex();
  /**
  ** HEX 长度
  **/
  uint32_t hex_len() const { return SHA384_DIGEST_LENGTH * 2; }
public:
private:
  unsigned char          digest_[SHA384_DIGEST_LENGTH];
  char                   hex_[SHA384_DIGEST_LENGTH * 2 + 1];
  SHA512_CTX             ctx_;
};

class CwxSha512 {
public:
  ///构造函数
  CwxSha512() {
    SHA512_Init(&ctx_);
    memset(digest_, 0x00, SHA512_DIGEST_LENGTH);
    memset(hex_, 0x00, SHA512_DIGEST_LENGTH * 2 + 1);
  }
  ///析构函数
  ~CwxSha512() { }
public:
  /**
  *@brief  根据buf的内容，对Sha签名进行更新
  *@param [in] szBuf 签名的内容.
  *@param [in] uiLen 内容的长度.
  *@return void.
  */
  void update(unsigned char const *szBuf, uint32_t uiLen);
  /**
  *@brief  输出签名的内容
  *@param [out] digest 输出内容的签名.
  *@return void.
  */
  void final(unsigned char digest[SHA512_DIGEST_LENGTH]);
  /**
  *@brief  输出签名的HEX
  *@param [out] digest 输出内容的签名HEX.
  *@return void.
  **/
  char const* to_hex();
  /**
  ** HEX 长度
  **/
  uint32_t hex_len() const { return SHA512_DIGEST_LENGTH * 2; }
public:
private:
  unsigned char          digest_[SHA512_DIGEST_LENGTH];
  char                   hex_[SHA512_DIGEST_LENGTH * 2 + 1];
  SHA512_CTX             ctx_;
};

CWINUX_END_NAMESPACE

#include "CwxPost.h"

#endif
