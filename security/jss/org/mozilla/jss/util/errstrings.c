/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
#include "nspr.h"

struct tuple_str {
    PRErrorCode         errNum;
    const char * errString;
};

typedef struct tuple_str tuple_str;

#define ER2(a,b)   {a, b},
#define ER3(a,b,c) {a, c},

#include "secerr.h"
#include "sslerr.h"

static const tuple_str errStrings[] = {

/* keep this list in ascending order of error numbers */
#include "SSLerrs.h"
#include "SECerrs.h"
#include "NSPRerrs.h"

};

static const PRInt32 numStrings = sizeof(errStrings) / sizeof(tuple_str);

/* Returns a UTF-8 encoded constant error string for "errNum".
 * Returns NULL of errNum is unknown.
 */
const char *
JSS_strerror(PRErrorCode errNum) {
    PRInt32 low  = 0;
    PRInt32 high = numStrings - 1;
    PRInt32 i;
    PRErrorCode num;
    static int initDone;

    /* make sure table is in ascending order.
     * binary search depends on it.
     */
    if (!initDone) {
        PRErrorCode lastNum = 0x80000000;
        for (i = low; i <= high; ++i) {
            num = errStrings[i].errNum;
            if (num <= lastNum) {
                    fprintf(stderr, 
"sequence error in error strings at item %d\n"
"error %d (%s)\n"
"should come after \n"
"error %d (%s)\n",
                        i, lastNum, errStrings[i-1].errString, 
                        num, errStrings[i].errString);
            }
            lastNum = num;
        }
        initDone = 1;
    }

    /* Do binary search of table. */
    while (low + 1 < high) {
        i = (low + high) / 2;
        num = errStrings[i].errNum;
        if (errNum == num) 
            return errStrings[i].errString;
        if (errNum < num)
            high = i;
        else 
            low = i;
    }
    if (errNum == errStrings[low].errNum)
            return errStrings[low].errString;
    if (errNum == errStrings[high].errNum)
            return errStrings[high].errString;
    return NULL;
}
