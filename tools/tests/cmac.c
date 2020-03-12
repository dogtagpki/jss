#include "nspr.h"
#include "nss.h"
#include "pkcs11t.h"

int main() {
    int test = (CKM_AES_CMAC == 0x0000108AULL);
    test = test && (CKM_AES_CMAC_GENERAL == 0x0000108BULL);

    return test ? 0 : 1;
}
