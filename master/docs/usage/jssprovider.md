# `Mozilla-JSS` Provider

The `Mozilla-JSS` JCA-compatible Provider exposes most of the functionality
of JSS to external packages. This interface is the recommend interface most
developers should build against. However, once the dependencies are satisfied
and JSS's native component is available to the JVM, we still have to load
and initialize JSS.

There are two routes to do this:

 1. Via the `CryptoManager` interface, _and_
 2. Via `java.security`, directly loading the `JSSProvider`.


## Loading JSS via `CryptoManager`

To load JSS from a `CryptoManager`, it is necessary to decide what level of
configuration is necessary. If you're happy with the defaults, it is
sufficient to only specify a NSS DB:

```java
import org.mozilla.jss.CryptoManager;

CryptoManager.initialize("/path/to/nss-db");
```

At this point, JSS will be initialized and can be used. A password might be
required, so see the section below for providing password callback handlers.

Certain default values might not work in all situations. For instance,
Candlepin expects other providers to be default, with the Mozilla-JSS
provider being the least-preferred provider. To do this, they'd construct an
`InitializationValues` instance and pass that to
`CryptoManager.initialize(...)`:

```java
import org.mozilla.jss.InitializationValues;

InitializationValues ivs = new InitializationValues("/path/to/nss-db");
ivs.installJSSProviderFirst = false;

CryptoManager.initialize(ivs);
```

See the section below on other options available to configure.


### `InitializationValues` options

There are two constructors for `InitializationValues`:

 - Taking only a NSS DB directory. This was utilized above.
 - Taking a NSS DB directory, a prefix for the certificate database, a
   prefix for the key database, and the name of the secmod configuration.

The latter is a more advanced use case and few individuals likely need to use
it. For more information, see the corresponding NSS documentation on these
values.

Refer to the javadoc for `InitializationValues` for the supported parameters
and their default values.

### `PasswordCallback` handlers

In order to authenticate against a PKCS#11 token or to the internal
certificate store, it is necessary to select a `PasswordCallback` handler.
By default this is a console-based `PasswordCallback` handler. This prompts
the user for the password via the Console. However, this is not appropriate
in all scenarios.

Developers are expected to extend and implement this as desired by their
application.

For example, to set a static `PasswordCallback` handler:

```java
CryptoManager cm = CryptoManager.getInstance();
cm.setPasswordCallback(new Password("password".toCharArray()));
```

## Loading JSS via `java.security`

You can directly add the `JSSProvider` by adding it to the `java.security`
file:

```properties
security.provider.<n> = org.mozilla.jss.JSSProvider /path/to/jss.cfg
```

There are two ways use this `java.security` file: by directly installing
it to the system or by using `-Djava.security.properties=/path/to/file`.
Note that two equals signs may be used, in which case the system configuration
is ignored and fully overridden by this file.

`JSSProvider` behaves like the `SunPKCS11-NSS` provider, requiring a
configuration file to initialize JSS (and the `CryptoManager` object).

`jss.cfg` takes the same `InitializationValues` parameters, except in a
properties file format.

### JSS Config

| property                           | Mapped To                                        |
|------------------------------------|--------------------------------------------------|
| `jss.fips`                         | `InitializationValues.fipsMode`                  |
| `jss.ocsp.enabled`                 | `InitializationValues.ocspCheckingEnabled`       |
| `jss.ocsp.policy`                  | `CryptoManager.setOCSPPolicy`                    |
| `jss.ocsp.responder.cert_nickname` | `InitializationValues.ocspResponderCertNickname` |
| `jss.ocsp.responder.url`           | `InitializationValues.ocspResponderURL`          |
| `jss.password`                     | `CryptoManager.setPasswordCallback`              |
| `nss.config_dir`                   | `InitializationValues.configDir`                 |
| `nss.cert_prefix`                  | `InitializationValues.certPrefix`                |
| `nss.cooperate`                    | `InitializationValues.cooperate`                 |
| `nss.force_open`                   | `InitializationValues.forceOpen`                 |
| `nss.java_only`                    | `InitializationValues.javaOnly`                  |
| `nss.key_prefix`                   | `InitializationValues.keyPrefix`                 |
| `nss.no_cert_db`                   | `InitializationValues.noCertDB`                  |
| `nss.no_mod_db`                    | `InitializationValues.noModDB`                   |
| `nss.no_pk11_finalize`             | `InitializationValues.noPK11Finalize`            |
| `nss.no_root_init`                 | `InitializationValues.noRootInit`                |
| `nss.optimizeSpace`                | `InitializationValues.optimizeSpace`             |
| `nss.pkix_verify`                  | `InitializationValues.pkixVerify`                |
| `nss.pk11_reload`                  | `InitializationValues.PK11Reload`                |
| `nss.pk11_thread_safe`             | `InitializationValues.PK11ThreadSafe`            |
| `nss.read_only`                    | `InitializationValues.readOnly`                  |
| `nss.secmod_name`                  | `InitializationValues.secmodName`                |

Note that the parameters `installJSSProvider`, `removeSunProvider`, and
`installJSSProviderFirst` are ignored, as they can be controlled by directly
manipulating the `java.security` file.

## Upgrading Old Code

There are two paths to upgrade an older code base to a newer JSS version,
using the JSSProvider interface:

 1. Continue using `CryptoManager.initialize(...)` as before. This gives the
    local application the most control over the NSS DB path. No changes are
    required.
 2. Switch to using `java.security`-based configuration (either via local
    policy with `-Djava.security.properties=/path` specified on the JVM
    command line or via system-wide policy by modifying the
    `$JAVA_HOME/conf/security/java.security` file). You can then remove the
    call to `CryptoManager.initialize(...)`. If this call is necessary for
    backwards-compatibility reasons (to support multiple JSS versions), it
    would be sufficient to check the value of `CryptoManager.getInstance(...)`
    before configuration:

    ```java
    try {
        cm = CryptoManager.getInstance();
    } catch (NotInitializedException nie) {
        // Or throw this exception and provide instructions on how to
        // configure Mozilla-JSS in the java.security provider list.
        CryptoManager.initialize(...);
        cm = CryptoManager.getInstance();
    }
    ```

    This gives the user control over NSS DB path via modifying either of
    those two configuration files (or by providing a local override).

Note that, between `java.security` and `CryptoManager.initialize()`, the
latter takes precedence unless `CryptoManager` has already been initialized.
This would happen if any java Security Provider calls are made or if
`CryptoManager.getInstance()` is called.
