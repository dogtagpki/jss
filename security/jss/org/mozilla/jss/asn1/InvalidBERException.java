/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
package org.mozilla.jss.asn1;

import java.util.Vector;

/**
 * An exception thrown when BER decoding fails.
 */
public class InvalidBERException extends java.lang.Exception {

    private InvalidBERException child=null;
    private Vector mesgList = new Vector();

    public InvalidBERException(String mesg) {
        super(mesg);
    }

    public void append(String mesg) {
        mesgList.addElement(mesg);
    }

    public InvalidBERException(InvalidBERException e, String mesg) {
        super(mesg);
        child = e;
    }

    /**
     * Prints out the exception class and error message, including
     * all the nested exceptions.
     */
    private void appendMessages(StringBuffer sb) {
        int numMessages = mesgList.size();
        for( int i=numMessages-1; i >= 0; --i ) {
            sb.append(mesgList.elementAt(i));
            sb.append(" >> ");
        }
        sb.append(getMessage());
    }

    public String toString() {
        StringBuffer sb = new StringBuffer();
        sb.append( this.getClass().getName() );
        sb.append(": ");
        appendMessages(sb);
        return sb.toString();
    }

    public String toStringNested() {
        StringBuffer sb = new StringBuffer();
        appendMessages(sb);
        if( child != null ) {
            sb.append(" >> ");
            sb.append( child.toStringNested() );
        }
        return sb.toString();
    }
        
    public static class EOF extends InvalidBERException {
        public EOF() {
            super("Unexpected end-of-file encountered");
        }
    }

	public static class InvalidChar extends InvalidBERException {
		public InvalidChar(byte b, int offset) {
			super("Invalid character ("+b+") encountered at offset "+offset);
		}
		public InvalidChar(char c, int offset) {
			super("Invalid character ("+c+") encountered at offset"+offset);
		}
	}
}
