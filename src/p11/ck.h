/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/*
 * The part of the PKCS #11 interface (OASIS, version 3.2) that noqtis
 * calls, written from the specification: the types, the structures
 * (packed on Windows, as the standard requires), and the numbers.
 * src/p11/p11.c is the caller; tests/p11/tok.c is a token to call.
 */
#ifndef NQCK_H
#define NQCK_H

typedef unsigned long ck;

#ifdef _WIN32
#pragma pack(push, cryptoki, 1)
#endif
typedef struct {
  unsigned char major, minor;
} ckver;
typedef struct {
  unsigned char label[32], maker[32], model[16], serial[16];
  ck flags, maxsess, sess, maxrw, rw, maxpin, minpin, pubmem, freepub,
      privmem, freepriv;
  ckver hw, fw;
  unsigned char time[16];
} cktok;
typedef struct {
  ck type;
  void *val;
  ck len;
} ckattr;
typedef struct {
  ck mech;
  void *par;
  ck len;
} ckmech;
typedef struct {
  void *mk, *md, *ml, *mu;
  ck flags;
  void *rsv;
} ckinit;
typedef struct {
  unsigned char *name;
  void *fl;
  ck flags;
} ckif;
typedef struct {
  ck hedge;
  unsigned char *ctx;
  ck len;
} cksctx; /* CK_SIGN_ADDITIONAL_CONTEXT */
typedef struct {
  unsigned char ph;
  ck len;
  unsigned char *ctx;
} cked; /* CK_EDDSA_PARAMS */
typedef void (*ckfn)(void);
typedef struct {
  ckver ver;
  ckfn fn[104];
} ckfl;
#ifdef _WIN32
#pragma pack(pop, cryptoki)
#endif

#define CKR_OK 0x0ul
#define CKR_HOST_MEMORY 0x2ul
#define CKR_CANT_LOCK 0xaul
#define CKR_PIN_INCORRECT 0xa0ul
#define CKR_PIN_INVALID 0xa1ul
#define CKR_PIN_LEN_RANGE 0xa2ul
#define CKR_PIN_EXPIRED 0xa3ul
#define CKR_PIN_LOCKED 0xa4ul
#define CKR_FUNCTION_NOT_SUPPORTED 0x54ul
#define CKR_MECHANISM_INVALID 0x70ul
#define CKR_USER_ALREADY_LOGGED_IN 0x100ul
#define CKR_BUFFER_TOO_SMALL 0x150ul
#define CKR_ALREADY_INITIALIZED 0x191ul
#define CKF_LOGIN_REQUIRED 0x4ul
#define CKF_RW_SESSION 0x2ul
#define CKF_SERIAL_SESSION 0x4ul
#define CKF_OS_LOCKING_OK 0x2ul
#define CKO_PUBLIC_KEY 0x2ul
#define CKO_PRIVATE_KEY 0x3ul
#define CKO_SECRET_KEY 0x4ul
#define CKK_GENERIC_SECRET 0x10ul
#define CKK_EC_EDWARDS 0x40ul
#define CKK_ML_KEM 0x49ul
#define CKK_ML_DSA 0x4aul
#define CKK_SLH_DSA 0x4bul
#define CKA_CLASS 0x0ul
#define CKA_TOKEN 0x1ul
#define CKA_PRIVATE 0x2ul
#define CKA_LABEL 0x3ul
#define CKA_VALUE 0x11ul
#define CKA_KEY_TYPE 0x100ul
#define CKA_ID 0x102ul
#define CKA_SENSITIVE 0x103ul
#define CKA_SIGN 0x108ul
#define CKA_VERIFY 0x10aul
#define CKA_PUBLIC_KEY_INFO 0x129ul
#define CKA_VALUE_LEN 0x161ul
#define CKA_EXTRACTABLE 0x162ul
#define CKA_EC_PARAMS 0x180ul
#define CKA_EC_POINT 0x181ul
#define CKA_PARAMETER_SET 0x61dul
#define CKA_ENCAPSULATE 0x633ul
#define CKA_DECAPSULATE 0x634ul
#define CKM_ML_KEM_KEY_PAIR_GEN 0xful
#define CKM_ML_KEM 0x17ul
#define CKM_ML_DSA_KEY_PAIR_GEN 0x1cul
#define CKM_ML_DSA 0x1dul
#define CKM_SLH_DSA_KEY_PAIR_GEN 0x2dul
#define CKM_SLH_DSA 0x2eul
#define CKM_EC_EDWARDS_KEY_PAIR_GEN 0x1055ul
#define CKM_EDDSA 0x1057ul
#define NOVAL (~0ul) /* CK_UNAVAILABLE_INFORMATION */
#define CKR_ARGUMENTS_BAD 0x7ul
#define CKR_ATTRIBUTE_SENSITIVE 0x11ul
#define CKR_ATTRIBUTE_TYPE_INVALID 0x12ul
#define CKR_DATA_INVALID 0x20ul
#define CKR_KEY_HANDLE_INVALID 0x60ul
#define CKR_KEY_TYPE_INCONSISTENT 0x63ul
#define CKR_OBJECT_HANDLE_INVALID 0x82ul
#define CKR_OPERATION_NOT_INITIALIZED 0x91ul
#define CKR_SESSION_HANDLE_INVALID 0xb3ul
#define CKR_SLOT_ID_INVALID 0x3ul
#define CKR_TEMPLATE_INCOMPLETE 0xd0ul
#define CKR_USER_NOT_LOGGED_IN 0x101ul
#define CKR_NOT_INITIALIZED 0x190ul
#define CKR_ENCRYPTED_DATA_INVALID 0x40ul
#define CKR_DEVICE_MEMORY 0x31ul
#define CKF_TOKEN_INITIALIZED 0x400ul
#define CKF_USER_PIN_INITIALIZED 0x8ul

#endif
