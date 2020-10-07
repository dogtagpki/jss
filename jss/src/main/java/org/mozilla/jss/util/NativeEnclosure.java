package org.mozilla.jss.util;

/**
 * Classes extending NativeEnclsoure wrap a single NativeProxy instance,
 * allowing it to be accessed from the JNI layer but be allocated and scoped
 * from the Java layer.
 *
 * Because this class implements AutoCloseable, it is suggested to add
 * constructors to derived classes which call open; this'll allow a single
 * try-with-resources block to scope the lifetime of this object:
 *
 * <pre>
 * try (NEC obj = new NEC(...)) {
 *      // ... do something with obj ...
 * }
 * </pre>
 *
 * Extending classes implement acquireNativeResources() and
 * releaseNativeResources(). Before this instance is passed to the JNI layer,
 * open() should be called, allocating all necessary resources. After making
 * all necessary JNI calls, close() should be called to free resources.
 * Ideally, open() and close() should be called close to the JNI calls,
 * wrapped by the developer to limit accidental memory leaks.
 */
public abstract class NativeEnclosure implements AutoCloseable {
    /**
     * Enclosed NativeProxy reference.
     */
    public NativeProxy mPointer;

    /**
     * Size of enclosed mPointer.
     */
    public long        mPointerSize;

    /**
     * Allocate and initialize mPointer with its enclosed value.
     *
     * Note that this method prevents you from accidentally leaking memory;
     * to call open() twice, call close() first.
     */
    public final void open() throws Exception {
        if (mPointer == null) {
            acquireNativeResources();
        }
    }

    @Deprecated
    protected void finalize() throws Throwable {
        close();
    }

    /**
     * Deinitialize and free mPointer.
     *
     * Must be called to prevent memory leaks.
     */
    public final void close() throws Exception {
        if (mPointer != null) {
            releaseNativeResources();
            mPointer.close();
        }

        mPointer = null;
        mPointerSize = 0;
    }

    /**
     * Allocate native resources, setting mPointer and mPointerSize as
     * appropriate.
     */
    protected abstract void acquireNativeResources() throws Exception;

    /**
     * Called to deallocate native resources; note that mPointer.close()
     * is called afterwards.
     *
     * If mPointer.close() should be a no-op, extend from StaticVoidRef and
     * do any required cleanup here.
     */
    protected abstract void releaseNativeResources() throws Exception;
}
