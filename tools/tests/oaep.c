#include "nspr.h"
#include "nss.h"
#include "pkcs11t.h"
#include "pk11pub.h"

int main() {
    PK11_PubWrapSymKeyWithMechanism(NULL, 0, NULL, NULL, NULL);
    PK11_PubUnwrapSymKeyWithMechanism(NULL, 0, NULL, NULL, 0, 0, 0);
    return 0;
}
