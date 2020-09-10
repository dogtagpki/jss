# `CryptoManager`

## Design

### `CryptoManager`, `JSSProvider`, and `JSSLoader` interactions

`CryptoManager` is the central singleton of JSS. It controls access to the
NSS database and an instance (available to developers via the
`CryptoManager.getInstance()` call) signals that both JSS and NSS are properly
initialized. The existing relationship between `CryptoManager` and
`JSSProvider` is that a single `CryptoManager` instance has a single
`JSSProvider` instance, and moreso that the reverse is also true: the
`JSSProvider` instance has a single `CryptoManager` instance. Currently the
code assumes that there is only ever one `CryptoManager` instance, making
both singletons.

_Aside:_

> Future work could be done to enable either multiple `CryptoManager` instances
> with separate NSS DBs, or to enable multiple `JSSProvider` instances to
> reference one or more `CryptoManager` instances during normal operation.
> This currently will require significant restructuring as many internal
> provider methods (such as `Cipher`, `Signature` and others) get the global
> singleton instance directly (via `CryptoManager.getInstance()`).
>
> Additionally, NSS provides the option to load multiple NSS DBs into the
> current instance, which might satisfy the use case of multiple
> `CryptoManager` instances as well.

---

However, the existence of `JSSLoader` and subsequently allowing JSS to load
via the standard provider `java.security` file has complicated this slightly,
to enable new use cases for JSS.

Take the following code snippet for instance:

```java
import org.mozilla.jss.CryptoManager;

public class Example {
  public static void main(String[] args) throws Exception {
    CryptoManager cm = CryptoManager.getInstance();
    // Additional code elided.
  }
}
```

When used with JSS loaded via `java.security` override, the developer would
rightly expect that JSS will load first, allowing `CryptoManager` to return
a valid instance.

In order to facilitate this however, when the internal `instance` field is
`NULL`, JSS must first try to load itself via the Provider interface. That is,
it needs to do something akin to:

```java
java.security.Provider p = Security.getProvider("Mozilla-JSS");
```

in order to force Java to attempt to load JSS. Any equivalent call into the
Java security interface would also suffice (such as
`Signature.getInstance(algo, "Mozilla-JSS")`), but this call limits the size
of the resulting object and makes clear the intent.

_Aside:_

> This becomes a touch tricky though. In particular, `CryptoManager.instance`
> access is usually locked, to prevent modification by one thread while
> another is reading it. This is locked at the class level (via a
> `synchronized (CryptoManager.class)` statement explicitly or implicitly
> in the synchronized `initialize()` method). So, inside `getInstance()`, we
> explicitly acquire the lock to check the value of `instance`, release it for
> the provider call -- in case it loads JSS from the provider interface --
> and then explicitly re-acquire it to return the value. This should help to
> prevent race conditions and returning a partially-initialized
> `CryptoManager` instance before it is fully ready.

Otherwise, the call will fail and we'd require code changes, such as:

```java
import java.security.*;

import org.mozilla.jss.CryptoManager;

public class Example {
  public static void main(String[] args) throws Exception {
    Provider p = Security.getProvider("Mozilla-JSS");
    CryptoManager cm = CryptoManager.getInstance();
    // Additional code elided.
  }
}
```

in order for this to work.

---

`CryptoManager` hasn't historically exposed a check to see if it is currently
initialized. Under earlier `JSSProvider` code, it would use
`CryptoManager.getInstance() != null` as the check for whether or not
`CryptoManager` was initialized. Consider the original code above: this leads
to the interesting recursion:

 - `CryptoManager.getInstance()` sees that `instance` is `NULL`, triggering
   `JSSProvider` to load.
 - `JSSProvider` -- while checking whether it needs to load -- would in turn
   call `CryptoManager.getInstance()` again.
 - Because `CryptoManager.getInstance()` again sees that `instance is `NULL`
   it will try to load `JSSProvider` again. Preventing us from infinite
   recursion though, `Security.getProvider(...)` will return `NULL`, and we'll
   successfully indicate that we need to load `JSSProvider`.

The net result is that we successfully load only a single `JSSProvider`
instance. However, when running with security debug flags (such as
`-Djava.security.debug=all`), the Provider loader would report the recursion
as a stack trace such as:

```java
ProviderConfig: Loading provider: org.mozilla.jss.JSSProvider('/home/ascheel/GitHub/sandbox/jss/build/config/jss.cfg')
ProviderConfig: Recursion loading provider: org.mozilla.jss.JSSProvider('/home/ascheel/GitHub/sandbox/jss/build/config/jss.cfg')
java.lang.Exception: Call trace
    at sun.security.jca.ProviderConfig.getProvider(ProviderConfig.java:180)
    at sun.security.jca.ProviderList.getProvider(ProviderList.java:233)
    at sun.security.jca.ProviderList.getIndex(ProviderList.java:263)
    at sun.security.jca.ProviderList.getProviderConfig(ProviderList.java:247)
    at sun.security.jca.ProviderList.getProvider(ProviderList.java:253)
    at java.security.Security.getProvider(Security.java:503)
    at org.mozilla.jss.CryptoManager.getInstance(CryptoManager.java:368)
    at org.mozilla.jss.JSSLoader.loaded(JSSLoader.java:86)
    at org.mozilla.jss.JSSLoader.init(JSSLoader.java:111)
    at org.mozilla.jss.JSSLoader.init(JSSLoader.java:103)
    at org.mozilla.jss.JSSProvider.configure(JSSProvider.java:68)
    at org.mozilla.jss.JSSProvider.<init>(JSSProvider.java:47)
    at sun.reflect.NativeConstructorAccessorImpl.newInstance0(Native Method)
    at sun.reflect.NativeConstructorAccessorImpl.newInstance(NativeConstructorAccessorImpl.java:62)
    at sun.reflect.DelegatingConstructorAccessorImpl.newInstance(DelegatingConstructorAccessorImpl.java:45)
    at java.lang.reflect.Constructor.newInstance(Constructor.java:423)
    at sun.security.jca.ProviderConfig$2.run(ProviderConfig.java:224)
    at sun.security.jca.ProviderConfig$2.run(ProviderConfig.java:206)
    at java.security.AccessController.doPrivileged(Native Method)
    at sun.security.jca.ProviderConfig.doLoadProvider(ProviderConfig.java:206)
    at sun.security.jca.ProviderConfig.getProvider(ProviderConfig.java:187)
    at sun.security.jca.ProviderList.getProvider(ProviderList.java:233)
    at sun.security.jca.ProviderList.getIndex(ProviderList.java:263)
    at sun.security.jca.ProviderList.getProviderConfig(ProviderList.java:247)
    at sun.security.jca.ProviderList.getProvider(ProviderList.java:253)
    at java.security.Security.getProvider(Security.java:503)
    at org.mozilla.jss.CryptoManager.getInstance(CryptoManager.java:368)
    at org.mozilla.jss.tests.SymKeyGen.<init>(SymKeyGen.java:210)
    at org.mozilla.jss.tests.SymKeyGen.main(SymKeyGen.java:266)
```

By introducing a `isInitialized()` method, we can use a proper check that
doesn't invoke this recursion, namely `instance == null` directly in the
`CryptoManager` instance.
