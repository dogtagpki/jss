/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
package org.mozilla.jss.util;

import org.mozilla.jss.util.*;

/**
 * C-style assertions in Java.
 * These methods are only active in debug mode
 * (org.mozilla.jss.Debug.DEBUG==true).
 *
 * @see org.mozilla.jss.util.Debug
 * @see org.mozilla.jss.util.AssertionException
 * @version $Revision$ $Date$
 */
public class Assert {
    /**
     * Assert that a condition is true.  If it is not true, abort by
     * throwing an AssertionException.
     *
     * @param cond The condition that is being tested.
     */
    public static void _assert(boolean cond) {
        if(Debug.DEBUG && !cond) {
            throw new org.mozilla.jss.util.AssertionException(
                "assertion failure!");
        }
    }

    /**
     * Assert that a condition is true. If it is not true, abort by throwing
     * an AssertionException.
     *
     * @param cond The condition that is being tested.
     * @param msg A message describing what is wrong if the condition is false.
     */
	public static void _assert(boolean cond, String msg) {
		if(Debug.DEBUG && !cond) {
			throw new org.mozilla.jss.util.AssertionException(msg);
		}
	}

    /**
     * Throw an AssertionException if this statement is reached.
     *
     * @param msg A message describing what was reached.
     */
    public static void notReached(String msg) {
        if(Debug.DEBUG) {
            throw new AssertionException("should not be reached: " + msg);
        }
    }

    /**
     * Throw an AssertionException if this statement is reached.
     */
    public static void notReached() {
        if(Debug.DEBUG) {
            throw new AssertionException();
        }
    }

    /**
     * Throw an AssertionException because functionality is not yet implemented.
     *
     * @param msg A message describing what is not implemented.
     */
    public static void notYetImplemented(String msg) {
        if(Debug.DEBUG) {
            throw new AssertionException("not yet implemented: " + msg);
        }
    }
}
