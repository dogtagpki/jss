/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/* These are class names suitable for passing to JSS_nativeThrow or
** JSS_nativeThrowMsg. They are the fully qualified class name of the 
** exception, separated by slashes instead of periods.
*/
#ifndef JSS_EXCEPTIONS_H
#define JSS_EXCEPTIONS_H


PR_BEGIN_EXTERN_C


#define ALREADY_INITIALIZED_EXCEPTION "org/mozilla/jss/crypto/AlreadyInitializedException"

#define ARRAY_INDEX_OUT_OF_BOUNDS_EXCEPTION "java/lang/ArrayIndexOutOfBoundsException"

#define INDEX_OUT_OF_BOUNDS_EXCEPTION "java/lang/IndexOutOfBoundsException"

#define BAD_PADDING_EXCEPTION "org/mozilla/jss/crypto/BadPaddingException"

#define BIND_EXCEPTION "java/net/BindException"

#define CERT_DATABASE_EXCEPTION "org/mozilla/jss/CertDatabaseException"

#define CERTIFICATE_EXCEPTION "java/security/cert/CertificateException"

#define CERTIFICATE_ENCODING_EXCEPTION "java/security/cert/CertificateEncodingException"

#define CRL_IMPORT_EXCEPTION "org/mozilla/jss/CRLImportException"

#define DIGEST_EXCEPTION "java/security/DigestException"

#define GENERAL_SECURITY_EXCEPTION "java/security/GeneralSecurityException"

#define GENERIC_EXCEPTION "java/lang/Exception"

#define GIVE_UP_EXCEPTION "org/mozilla/jss/util/PasswordCallback$GiveUpException"

#define ILLEGAL_ARGUMENT_EXCEPTION "java/lang/IllegalArgumentException"

#define ILLEGAL_BLOCK_SIZE_EXCEPTION "org/mozilla/jss/crypto/IllegalBlockSizeException"

#define INCORRECT_PASSWORD_EXCEPTION "org/mozilla/jss/util/IncorrectPasswordException"

#define INTERRUPTED_IO_EXCEPTION "java/io/InterruptedIOException"

#define INVALID_KEY_FORMAT_EXCEPTION "org/mozilla/jss/crypto/InvalidKeyFormatException"

#define INVALID_PARAMETER_EXCEPTION "java/security/InvalidParameterException"

#define IO_EXCEPTION "java/io/IOException"

#define KEY_DATABASE_EXCEPTION "org/mozilla/jss/KeyDatabaseException"

#define KEY_EXISTS_EXCEPTION "org/mozilla/jss/crypto/KeyAlreadyImportedException"

#define KEYSTORE_EXCEPTION "java/security/KeyStoreException"

#define NICKNAME_CONFLICT_EXCEPTION "org/mozilla/jss/CryptoManager$NicknameConflictException"

#define NO_SUCH_ALG_EXCEPTION "java/security/NoSuchAlgorithmException"

#define NO_SUCH_ITEM_ON_TOKEN_EXCEPTION "org/mozilla/jss/crypto/NoSuchItemOnTokenException"

#define NO_SUCH_TOKEN_EXCEPTION "org/mozilla/jss/NoSuchTokenException"

#define NOT_EXTRACTABLE_EXCEPTION "org/mozilla/jss/crypto/SymmetricKey$NotExtractableException"

#define NULL_POINTER_EXCEPTION "java/lang/NullPointerException"

#define OBJECT_NOT_FOUND_EXCEPTION "org/mozilla/jss/crypto/ObjectNotFoundException"

#define OUT_OF_MEMORY_ERROR "java/lang/OutOfMemoryError"

#define PQG_PARAM_GEN_EXCEPTION "org/mozilla/jss/crypto/PQGParamGenException"

/* This is a RuntimeException */
#define SECURITY_EXCEPTION "java/lang/SecurityException"

#define SIGNATURE_EXCEPTION "java/security/SignatureException"

#define SOCKET_EXCEPTION "java/net/SocketException"

#define SSLSOCKET_EXCEPTION "org/mozilla/jss/ssl/SSLSocketException"

#define SOCKET_TIMEOUT_EXCEPTION "java/net/SocketTimeoutException"

#define TOKEN_EXCEPTION "org/mozilla/jss/crypto/TokenException"

#define TOKEN_NOT_INITIALIZED_EXCEPTION "org/mozilla/jss/pkcs11/PK11Token$NotInitializedException"

#define USER_CERT_CONFLICT_EXCEPTION "org/mozilla/jss/CryptoManager$UserCertConflictException"

PR_END_EXTERN_C

#endif
