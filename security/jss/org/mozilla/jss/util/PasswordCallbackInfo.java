/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.util;

/**
 * An object of this class is passed to a PasswordCallback to give it
 * information about the token that is being logged into.
 */
public class PasswordCallbackInfo {

    /**
     * @param name The name of the file or token that is being logged into.
     * @param type The type of object (<code>FILE</code> or
     *      <code>TOKEN</code>) that is being logged into.
     */
	public PasswordCallbackInfo(String name, int type) {
		Assert._assert(type==FILE || type==TOKEN);
		this.name = name;
		this.type = type;
	}

	/**
	 * The name of the file or token that is being logged into.
	 */
	public String getName() {
		return name;
	}

	/**
	 * The type of object that is being logged into, <code>FILE</code>
     *  or <code>TOKEN</code>.
	 */
	public int getType() {
		return type;
	}

    protected String name;
    protected int type;

    /**
     * Logging into a file.
     */
    static public final int FILE = 0;

    /**
     * Logging into a PKCS #11 token.
     */
    static public final int TOKEN = 1;
}
