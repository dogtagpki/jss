/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "_jni/org_mozilla_jss_pkcs11_PK11Module.h"

#include <nspr.h>
#include <plarena.h>
#include <secmodt.h>
#include <secmod.h>
#include <pk11func.h>

#include "pk11util.h"
#include <jssutil.h>
#include <java_ids.h>
#include "jss_exceptions.h"

/***********************************************************************
 * Class:     org_mozilla_jss_pkcs11_PK11Module
 * Method:    getName
 * Signature: ()Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_org_mozilla_jss_pkcs11_PK11Module_getName
  (JNIEnv *env, jobject this)
{
    SECMODModule *module;
    jstring nameString=NULL;

    PR_ASSERT(env!=NULL && this!=NULL);

    if( JSS_PK11_getModulePtr(env, this, &module) != PR_SUCCESS) {
        goto finish;
    }

    PR_ASSERT(module->commonName != NULL);
    nameString = (*env)->NewStringUTF(env, module->commonName);

finish:
    PR_ASSERT( nameString  || (*env)->ExceptionOccurred(env) );
    return nameString;
}

/***********************************************************************
 * Class:     org_mozilla_jss_pkcs11_PK11Module
 * Method:    getLibraryName
 * Signature: ()Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_org_mozilla_jss_pkcs11_PK11Module_getLibraryName
  (JNIEnv *env, jobject this)
{
    SECMODModule *module;
    jstring libName = NULL;

    PR_ASSERT(env!=NULL && this!=NULL);

    if( JSS_PK11_getModulePtr(env, this, &module) != PR_SUCCESS) {
        goto finish;
    }

    PR_ASSERT(module->dllName != NULL);
    libName = (*env)->NewStringUTF(env, module->dllName);

finish:
    PR_ASSERT( libName || (*env)->ExceptionOccurred(env) );
    return libName;
}

/***********************************************************************
 * Class:     org_mozilla_jss_pkcs11_PK11Module
 * Method:    putTokensInVector
 * Signature: (Ljava/util/Vector;)V
 */
JNIEXPORT void JNICALL Java_org_mozilla_jss_pkcs11_PK11Module_putTokensInVector
  (JNIEnv *env, jobject this, jobject vector)
{
    SECMODModule *module;
    jclass vectorClass;
    jmethodID addElement;
    jobject token;
    PK11SlotInfo *slot;
    int i;

    PR_ASSERT(env!=NULL && this!=NULL && vector!=NULL);

    /***************************
     * Get Vector JNI ids
     ***************************/
    vectorClass = (*env)->GetObjectClass(env, vector);
    if(vectorClass==NULL) goto finish;

    addElement = (*env)->GetMethodID(env,   
                                     vectorClass,
                                     VECTOR_ADD_ELEMENT_NAME,
                                     VECTOR_ADD_ELEMENT_SIG);
    if(addElement==NULL) goto finish;

    /***************************
     * Get the PKCS #11 module
     ***************************/
    if( JSS_PK11_getModulePtr(env, this, &module) != PR_SUCCESS) goto finish;

    /**************************
     * Loop over slots
     **************************/
    for(i=0; i < module->slotCount; i++) {

        if (PK11_IsPresent(module->slots[i])) {
            char *tokenname;
            tokenname = PK11_GetTokenName(module->slots[i]);

            /* ignore if the token has no name */
            if( tokenname!=NULL && tokenname[0]!='\0' ) {

                /* turn the slot into a PK11Token */
                slot = PK11_ReferenceSlot(module->slots[i]);
                PR_ASSERT(slot!=NULL);
                token = JSS_PK11_wrapPK11Token(env, &slot);

                /* stick the PK11Token in the Vector */
                (*env)->CallVoidMethod(env, vector, addElement, token);
            }
        }
    }

finish:
    return;
}

/***********************************************************************
 *
 * J S S _ P K 1 1 _ w r a p P K 1 1 M o d u l e
 *
 * Turns a SECMODModule* C structure into a PK11Module Java object.
 *
 * INPUTS
 *      ptr
 *          Address of a SECMODModule *. This pointer will be copied 
 *          into the new Java object, then set to NULL.
 * RETURNS
 *      A new Java PK11Module object, or NULL if an exception was thrown.
 *      In any case, the ptr parameter is eaten.
 */
jobject
JSS_PK11_wrapPK11Module(JNIEnv *env, SECMODModule **module)
{
    jclass moduleClass;
    jmethodID constructor;
    jobject newModule=NULL;
    jbyteArray pointer;

    PR_ASSERT(env!=NULL && module!=NULL && *module!=NULL);

    pointer = JSS_ptrToByteArray(env, (void*)*module);

    /*
     * Lookup the class and constructor
     */
    moduleClass = (*env)->FindClass(env, PK11MODULE_CLASS_NAME);
    if(moduleClass == NULL) {
        ASSERT_OUTOFMEM(env);
        goto finish;
    }

    constructor = (*env)->GetMethodID(
                                env,
                                moduleClass,
                                PLAIN_CONSTRUCTOR,
                                PK11MODULE_CONSTRUCTOR_SIG);
    if(constructor == NULL) {
        ASSERT_OUTOFMEM(env);
        goto finish;
    }

    /*
     * Call the constructor
     */
    newModule = (*env)->NewObject(env, moduleClass, constructor, pointer);

finish:
    if(newModule==NULL) {
        SECMOD_DestroyModule(*module);
    }
    *module = NULL;
    return newModule;
}


/***********************************************************************
 *
 * J S S _ P K 1 1 _ g e t M o d u l e P t r
 *
 * Retrieve the SECMODModule pointer of the given PK11Module.
 *
 * INPUTS
 *      module
 *          A reference to a Java PK11Module.
 *      ptr
 *          Address of a SECMODModule * that will be loaded with the
 *          SECMODModule pointer of the given PK11Module.
 * RETURNS
 *      PR_FAILURE if an exception was thrown, or PR_SUCCESS if the
 *      peration succeeded.
 */
PRStatus
JSS_PK11_getModulePtr(JNIEnv *env, jobject module, SECMODModule **ptr)
{
    PR_ASSERT(env!=NULL && module!=NULL && ptr!=NULL);

    return JSS_getPtrFromProxyOwner(env,
                                    module,
                                    PK11MODULE_PROXY_FIELD,
                                    PK11MODULE_PROXY_SIG,
                                    (void**)ptr);
}

/**********************************************************************
 * ModuleProxy.releaseNativeResources
 */
JNIEXPORT void JNICALL
Java_org_mozilla_jss_pkcs11_ModuleProxy_releaseNativeResources
    (JNIEnv *env, jobject this)
{
    SECMODModule *module;

    if (JSS_getPtrFromProxy(env, this, (void **)&module) != PR_SUCCESS) {
        ASSERT_OUTOFMEM(env);
        goto finish;
    }
    PR_ASSERT(module != NULL);

    SECMOD_DestroyModule(module);

finish:
    return;
}
