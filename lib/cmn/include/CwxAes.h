#ifndef __CWX_AES_H__
#define __CWX_AES_H__
/*
版权声明：
    本软件遵循GNU LGPL (Lesser General Public License)（http://www.gnu.org/licenses/gpl.html），
    联系方式：email:cwinux@gmail.com；微博:http://weibo.com/cwinux
*/

/**
*@file  CwxAes.h
*@author cwinux@gmail.com
*@version 0.1
*@date    2017-12-21
*@warning 无
*@bug   
*/

#include "CwxPre.h"
#include "CwxGlobalMacro.h"
#include "CwxType.h"
#include <iostream>
#include <string>
#include <string.h>
#include "openssl/aes.h"
#include "CwxCommon.h"
CWINUX_BEGIN_NAMESPACE
/**
*@class  CwxAesEncrypt
*@brief  Aes的CBC对称加密。此对象多线程不安全，在多线程环境下，
        每个线程需要自己的一个对象实例。
*/
class CwxAesEncrypt
{
public:
    ///构造函数
    CwxAesEncrypt() {
      bits_ = 0;
    }
    ///析构函数
    ~CwxAesEncrypt() {
    }
public:
    // 初始化, bits为128、192、256。
    // 返回值：true： 成功；false： 密钥长度不是128，192，256；
    bool init(unsigned char const* key, unsigned char const* iv, int bits);
    // padding 的size
    int padding_size(uint32_t len) const {
      int mod = len%AES_BLOCK_SIZE;
      return mod?(AES_BLOCK_SIZE-mod):0;
    }
    // encrypt。false：len%16<>0
    bool encrypt(unsigned char const *from, unsigned char *to, int len);
    // get errmsg
    char const* errmsg() const { return err_; }
    // 重置加密信息
    inline void reset() {
      memcpy(iv_, src_iv_, bits_ / 8);
      AES_set_encrypt_key(key_, bits_, &aes_);
    }
    // 是否是合法的bits
    static inline bool isvalid_bits(int bits) {
      return (128 == bits) || (192 == bits) || (256 == bits);
    }
private:
    unsigned char           key_[32];
    unsigned char           iv_[32];
    unsigned char           src_iv_[32];
    uint32_t                bits_;
    AES_KEY                 aes_;
    char                    err_[1024];
};

/**
*@class  CwxAesDecrypt
*@brief  Aes的CBC对称解密。此对象多线程不安全，在多线程环境下，
每个线程需要自己的一个对象实例。
*/
class CwxAesDecrypt
{
public:
  ///构造函数
  CwxAesDecrypt() {
    bits_ = 0;
  }
  ///析构函数
  ~CwxAesDecrypt() {
  }
public:
  // 初始化, bits为128、192、256。
  // 返回值：true： 成功；false： 密钥长度不是128，192，256；
  bool init(unsigned char const* key, unsigned char const* iv, int bits);
  // padding 的size
  int padding_size(uint32_t len) const {
    int mod=len%AES_BLOCK_SIZE;
    return mod?(AES_BLOCK_SIZE-mod):0;
  }
  // decrypt。false：len%16<>0
  bool decrypt(unsigned char const *from, unsigned char *to, int len);
  // get errmsg
  char const* errmsg() const { return err_; }
  // 重置加密信息
  inline void reset() {
    memcpy(iv_, src_iv_, bits_ / 8);
    AES_set_decrypt_key(key_, bits_, &aes_);
  }
  // 是否是合法的bits
  static inline bool isvalid_bits(int bits) {
    return (128 == bits) || (192 == bits) || (256 == bits);
  }
private:
  unsigned char           key_[32];
  unsigned char           iv_[32];
  unsigned char           src_iv_[32];
  uint32_t                bits_;
  AES_KEY                 aes_;
  char                    err_[1024];
};

CWINUX_END_NAMESPACE

#include "CwxPost.h"

#endif
