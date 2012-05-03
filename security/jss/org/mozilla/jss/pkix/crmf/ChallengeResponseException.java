/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
package org.mozilla.jss.pkix.crmf;

/**
 * An exception thrown when challenge response pop is requested.
 */
public class ChallengeResponseException extends java.lang.Exception {

    private ChallengeResponseException child=null;

    public ChallengeResponseException(String mesg) {
        super(mesg);
    }

    public ChallengeResponseException(ChallengeResponseException e, String mesg) {
        super(mesg);
        child = e;
    }

    /**
     * Prints out the exception class and error message, including
     * all the nested exceptions.
     */
    public String toString() {
        if(child != null) {
            return (super.toString()+ " >> " + child.toStringNested());
        } else {
            return super.toString();
        }
    }

    /**
     * Prints out the error message of this exception, including all the
     * nested exceptions.
     */
    public String toStringNested() {
        if(child != null) {
            return ( getMessage() + " >> " + child.toStringNested());
        } else {
            return getMessage();
        }
    }
}
