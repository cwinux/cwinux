#ifndef __CWX_RSA_H__
#define __CWX_RSA_H__
/*
版权声明：
    本软件遵循GNU LGPL (Lesser General Public License)（http://www.gnu.org/licenses/gpl.html），
    联系方式：email:cwinux@gmail.com；微博:http://weibo.com/cwinux
*/

/**
*@file  CwxRsa.h
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
#include "openssl/rsa.h"
#include "openssl/pem.h"
#include "openssl/err.h"
#include "CwxCommon.h"
CWINUX_BEGIN_NAMESPACE
/**
*@class  CwxRsaPri
*@brief  Rsa的private非对称加密。此对象多线程不安全，在多线程环境下，
        每个线程需要自己的一个对象实例。
*/
class CwxRsaPri
{
public:
    ///构造函数
    CwxRsaPri() {
      rsa_ =NULL;
    }
    ///析构函数
    ~CwxRsaPri() {
      if (rsa_) RSA_free(rsa_);
    }
public:
    // 初始化。
    bool init(char const* key, int len);
    // encrypt
    bool encrypt(unsigned char *from, int len, string& to);
    // decrypt。false
    bool decrypt(unsigned char *from, int len, string& to);
    // get rsa length
    int rsa_size() const {
      return rsa_?RSA_size(rsa_):0;
    }
    // max encrypt size
    int max_encrypt_size() const {
      return rsa_? RSA_size(rsa_)-11:0;
    }
    // get errmsg
    char const* errmsg() const { return err_.c_str(); }
    // 形成密钥
    void static generate_rsa(string& pri, string& pub, uint32_t len = 2048);
private:
    RSA*                    rsa_;
    string                  pri_key_;
    string                  err_;
    char                    err_buf_[1024];
    unsigned char           buf_[1024];
};

/**
*@class  CwxRsaPub
*@brief  Rsa的public非对称加密。此对象多线程不安全，在多线程环境下，
每个线程需要自己的一个对象实例。
*/
class CwxRsaPub
{
public:
  ///构造函数
  CwxRsaPub() {
    rsa_ = NULL;
  }
  ///析构函数
  ~CwxRsaPub() {
    if (rsa_) RSA_free(rsa_);
  }
public:
  // 初始化。
  bool init(char const* key, int len);
  // encrypt
  bool encrypt(unsigned char *from, int len, string& to);
  // decrypt。false
  bool decrypt(unsigned char *from, int len, string& to);
  // get rsa length
  int rsa_size() const {
    return rsa_ ? RSA_size(rsa_) : 0;
  }
  // max encrypt size
  int max_encrypt_size() const {
    return rsa_ ? RSA_size(rsa_) - 11 : 0;
  }
  // get errmsg
  char const* errmsg() const { return err_.c_str(); }
private:
  RSA*                    rsa_;
  string                  pri_key_;
  string                  err_;
  char                    err_buf_[1024];
  unsigned char           buf_[1024];
};

CWINUX_END_NAMESPACE

#include "CwxPost.h"

#endif
