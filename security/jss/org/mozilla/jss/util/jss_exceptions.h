/* 
 * The contents of this file are subject to the Mozilla Public
 * License Version 1.1 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of
 * the License at http://www.mozilla.org/MPL/
 * 
 * Software distributed under the License is distributed on an "AS
 * IS" basis, WITHOUT WARRANTY OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * rights and limitations under the License.
 * 
 * The Original Code is the Netscape Security Services for Java.
 * 
 * The Initial Developer of the Original Code is Netscape
 * Communications Corporation.  Portions created by Netscape are 
 * Copyright (C) 1998-2000 Netscape Communications Corporation.  All
 * Rights Reserved.
 * 
 * Contributor(s):
 * 
 * Alternatively, the contents of this file may be used under the
 * terms of the GNU General Public License Version 2 or later (the
 * "GPL"), in which case the provisions of the GPL are applicable 
 * instead of those above.  If you wish to allow use of your 
 * version of this file only under the terms of the GPL and not to
 * allow others to use your version of this file under the MPL,
 * indicate your decision by deleting the provisions above and
 * replace them with the notice and other provisions required by
 * the GPL.  If you do not delete the provisions above, a recipient
 * may use your version of this file under either the MPL or the
 * GPL.
 */

/* These are class names suitable for passing to JSS_nativeThrow or
** JSS_nativeThrowMsg. They are the fully qualified class name of the 
** exception, separated by slashes instead of periods.
*/
#ifndef JSS_EXCEPTIONS_H
#define JSS_EXCEPTIONS_H


PR_BEGIN_EXTERN_C


#define ALREADY_INITIALIZED_EXCEPTION "org/mozilla/jss/crypto/AlreadyInitializedException"

#define INDEX_OUT_OF_BOUNDS_EXCEPTION "java/lang/IndexOutOfBoundsException"

#define BAD_PADDING_EXCEPTION "org/mozilla/jss/crypto/BadPaddingException"

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

#define INVALID_KEY_FORMAT_EXCEPTION "org/mozilla/jss/crypto/InvalidKeyFormatException"

#define INVALID_PARAMETER_EXCEPTION "java/security/InvalidParameterException"

#define KEY_DATABASE_EXCEPTION "org/mozilla/jss/KeyDatabaseException"

#define KEY_EXISTS_EXCEPTION "org/mozilla/jss/crypto/KeyAlreadyImportedException"

#define NICKNAME_CONFLICT_EXCEPTION "org/mozilla/jss/CryptoManager$NicknameConflictException"

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

#define TOKEN_EXCEPTION "org/mozilla/jss/crypto/TokenException"

#define TOKEN_NOT_INITIALIZED_EXCEPTION "org/mozilla/jss/pkcs11/PK11Token$NotInitializedException"

#define USER_CERT_CONFLICT_EXCEPTION "org/mozilla/jss/CryptoManager$UserCertConflictException"

PR_END_EXTERN_C

#endif
