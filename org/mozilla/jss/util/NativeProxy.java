/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.util;

import java.util.HashSet;

import java.lang.AutoCloseable;
import java.lang.Thread;
import java.util.Arrays;

import org.mozilla.jss.CryptoManager;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * NativeProxy, a superclass for Java classes that mirror C data structures.
 *
 * It contains some code to help make sure that native memory is getting
 * freed properly.
 *
 * @author nicolson
 * @version $Revision$ $Date$
 */
public abstract class NativeProxy implements AutoCloseable
{
    public static Logger logger = LoggerFactory.getLogger(NativeProxy.class);
    private static final boolean saveStacktraces = assertsEnabled() && CryptoManager.JSS_DEBUG;

    /**
     * Create a NativeProxy from a byte array representing a C pointer.
     * This is the only way to create a NativeProxy, it should be called
     * from the constructor of your subclass.
     *
     * @param pointer A byte array, created with JSS_ptrToByteArray, that
     * contains a pointer pointing to a native data structure.  The
     * NativeProxy instance acts as a proxy for that native data structure.
     */
    public NativeProxy(byte[] pointer) {
		assert(pointer!=null);
        mPointer = pointer;
        registry.add(this);

        if (saveStacktraces) {
            mTrace = Arrays.toString(Thread.currentThread().getStackTrace());
        }
    }

    /**
     * Deep comparison operator.
     * @return true if <code>obj</code> has the same underlying native
     *      pointer. false if the <code>obj</code> is null or has
     *      a different underlying native pointer.
     */
    public boolean equals(Object obj) {
        if(obj==null) {
            return false;
        }
        if( ! (obj instanceof NativeProxy) ) {
            return false;
        }
        if (((NativeProxy)obj).mPointer == null) {
            /* If mPointer is null, we have no way to compare the values
             * of the pointers, so assume they're unequal. */
            return false;
        }
        return Arrays.equals(((NativeProxy)obj).mPointer, mPointer);
    }

    /**
     * Release the native resources used by this proxy.
     * Subclasses of NativeProxy must define this method to clean up
     * data structures in C code that are referenced by this proxy.
     * releaseNativeResources() will usually be implemented as a native method.
     * <p>You don't call this method; NativeProxy.finalize() or close() calls
     * it for you.</p>
     *
     * If you free these resources explicitly, call clear(); instead.
     */
    protected abstract void releaseNativeResources();

    /**
     * Finalize this NativeProxy by releasing its native resources.
     * The finalizer calls releaseNativeResources() so you don't have to.
     * This finalizer should be called from the finalize() method of all
     * subclasses:
     * class MyProxy extends NativeProxy {
     *      [...]
     *      protected void finalize() throws Throwable {
     *          // do any object-specific finalization other than
     *          // releasing native resources
     *          [...]
     *          super.finalize();
     *      }
     * }
     *
     * @deprecated finalize() in Object has been deprecated. Use close(...)
     * from the AutoCloseable interface instead.
     */
    @Deprecated
    protected void finalize() throws Throwable {
        close();
    }

    /**
     * Close this NativeProxy by releasing its native resources if they
     * haven't otherwise been freed.
     *
     * See comment in finalize.
     */
    public final void close() throws Exception {
        try {
            if (registry.remove(this)) {
                releaseNativeResources();
            }
        } finally {
            mPointer = null;
        }
    }

    /**
     * Call clear(...) to clear the value of the pointer, setting it to null.
     *
     * This should be used when the pointer has been freed by another means.
     * Similar to finalize(...) or close(...), except that it doesn't call
     * releaseNativeResources(...).
     *
     * See also: JSS_clearPtrFromProxy(...) in jssutil.h
     */
    public final void clear() {
        this.mPointer = null;
        registry.remove(this);
    }

    /**
     * Byte array containing native pointer bytes.
     */
    private byte mPointer[];

    /**
     * String containing backtrace of pointer generation.
     */
    private String mTrace;

    /**
     * <p><b>Native Proxy Registry</b>
     * <p>In debug mode, we keep track of all NativeProxy objects in a
     * static registry.  Whenever a NativeProxy is constructed, it
     * registers.  Whenever it finalizes, it unregisters.  At the end of
     * the game, we should be able to garbage collect and then assert that
     * the registry is empty. This could be done, for example, in the
     * jssjava JVM after main() completes.
     *
     * This registration process verifies that people are calling
     * NativeProxy.finalize() from their subclasses of NativeProxy, so that
     * releaseNativeResources() gets called.
     */
    static HashSet<NativeProxy> registry = new HashSet<NativeProxy>();

    /**
     * Internal helper to check whether or not assertions are enabled in the
     * JVM.
     *
     * See: https://docs.oracle.com/javase/8/docs/technotes/guides/language/assert.html
     */
    private static boolean assertsEnabled() {
        boolean enabled = false;
        assert enabled = true;
        return enabled;
    }

    /**
     * Assert that the Registry is empty.  Only works in debug mode; in
     * ship mode, it is a no-op.  If the Registry is not empty when this
     * is called, an assertion (org.mozilla.jss.util.AssertionException)
     * is thrown.
     */
    public synchronized static void assertRegistryEmpty() {
        if (!registry.isEmpty()) {
            logger.warn(registry.size() + " NativeProxys are still registered.");

            if (saveStacktraces) {
                for (NativeProxy proxy : registry) {
                    logger.warn("\t" + Arrays.toString(proxy.mPointer) + " ::: " + proxy.mTrace);
                }
            }
        } else {
            logger.debug("NativeProxy registry is empty");
        }
    }
}
