# KBKDF - Documentation

## About KBKDF

KBKDF is defined in [NIST's SP800-108][sp800-108]: Key Based Key Derivation
Functions. These are a collection of three KDFs based on MACing primitives:

 1. Counter Mode in 5.1,
 2. Feedback Mode in 5.2, and
 3. Double Pipeline Mode in 5.3.

These KDFs see usage in GlobalPlatform's Secure Channel Protocol 03, Kerberos,
and other places. This KDF is implemented using [PKCS#11 v3.0][pkcs11-kbkdf];
refer to that document for additional information about using this KDF.

## Using KBKDF

KBKDF usage is available from the `Mozilla-JSS` provider through the javax
[`KeyGenerator`][key-generator] interface. There are two categories of KDF
implementations:

 1. `CKO_SECRET_KEY` keys, which cannot be extracted when the system is
    running in FIPS mode or when the key lives on an HSM, and
 2. `CKO_DATA_OBJECT` keys, which can always be extract.

The latter category is suitable for generating SCP03 challenges, but shouldn't
be used with cryptographic operations. They have the "Data" suffix in the
provider list.

### Constructing a KBKDF `KeyGenerator`

To construct a KBKDF generator, get the instance via the provider interface:

```java
import javax.crypto.KeyGenerator;

KeyGenerator kg = KeyGenerator.getInstance("<name>", "Mozilla-JSS");
```

Where name depends on the choice of KBKDF:

| KeyGenerator Name | Mode     | Data | Parameter Class                              |
|-------------------|----------|------|----------------------------------------------|
| KbkdfCounter      | Counter  | no   | [KBKDFCounterParams][kbkdf-counter-params]   |
| KbkdfCounterData  | Counter  | yes  | [KBKDFCounterParams][kbkdf-counter-params]   |
| KbkdfFeedback     | Feedback | no   | [KBKDFFeedbackParams][kbkdf-feedback-params] |
| KbkdfFeedbackData | Feedback | yes  | [KBKDFFeedbackParams][kbkdf-feedback-params] |
| KbkdfPipeline     | Pipeline | no   | [KBKDFPipelineParams][kbkdf-pipeline-params] |
| KbkdfPipelineData | Pipeline | yes  | [KBKDFPipelineParams][kbkdf-pipeline-params] |

Various aliases for these KeyGenerators also exist; this allows for greater
compatibility with existing systems which implement this KDF. These exist
because the [Java Cryptography Architecture][jca] doesn't specify canonical
names for these KDFs.

### Construct a KBKDF Parameter Specification

Each KBKDF mode has its own parameter specification class, which must be used
with a `KeyGenerator` of only that type. These classes are given in the above
table and exist in the [`org.mozilla.jss.crypto`][jss-crypto] package. Each
parameter spec derives from [`KBKDFParameterSpec`][kbkdf-spec].

These arguments are:

| Name                    | Description                          | Modes    | Setter                                                                                              |
|-------------------------|--------------------------------------|----------|-----------------------------------------------------------------------------------------------------|
| PRF                     | PRF used during KBKDF (HMAC or CMAC) | All      | [`setPRF`][kbkdf-spec-set-prf]                                                                      |
| PRF Key                 | Key used for the PRF                 | All      | [`setPRFKey`][kbkdf-spec-set-prf-key]                                                               |
| Derived Algorithm       | Algorithm of the primary derived key | All      | [`setDerivedKeyAlgorithm`][kbkdf-spec-set-derived-algo]                                             |
| Key Size                | Size of the primary derived key      | All      | [`setKeySize`][kbkdf-spec-set-key-size]                                                             |
| Initial Value           | Initial chaining value               | Feedback | [`setInitialValue`][kbkdf-spec-set-iv]                                                              |
| PRF Data Parameters     | Parameters to control PRF input      | All      | [`setParameters`][kbkdf-spec-set-params] / [`addParameter`][kbkdf-spec-add-param]                  |
| Additional Derived Keys | Additional keys to derive            | All      | [`setAdditionalDerivedKeys`][kbkdf-spec-set-keys] / [`addAdditionalDerivedKey`][kbkdf-spec-add-key] |

Note: the methods and fields inherited from `NativeEnclosure` shouldn't be
called by the KBKDF user during normal usage.

#### Using Algorithms

When using this KBKDF, both the PRF and the derived key's algorithm must be
specified. In both cases, the user has a choice: either use the
[PKCS#11 Constant][jss-pkcs11-constants] for the algorithm, or use the
algorithm as specified in the [PKCS#11 Algorithm][jss-pkcs11-algorithm]
enumeration.

For example, the following are equivalent:

```java
import org.mozilla.jss.pkcs11.PKCS11Constants;

KBKDFCounterParams params = new KBDKFCounterParams();
params.setPRF(PKCS11Constants.CKM_AES_CMAC);
```

and

```java
import org.mozilla.jss.crypto.PKCS11Algorithm;

KBKDFCounterParams params = new KBKDFCounterParams();
params.setPRF(PKCS11Algorithm.CKM_AES_CMAC);
```

The latter gives a little more type safety and ensures that the specified
algorithm is understood and implemented by JSS; otherwise, they're equivalent.

#### Constructing KDF PRF Input Stream (Data) Parameters

The core of PKCS#11's KBKDF implementation allows great flexibility in
crafting the input stream to the underlying PRF invocation. This allows for
a wide range of usages (including in SCP03), assuming some care is taken in
ensuring the resulting KBKDF is secure from length extension attacks. See
NIST S800-108 for more details regarding concerns.

PKCS#11 v3.0 defines four types of input parameters:

| Name                        | Description                                                |
|-----------------------------|------------------------------------------------------------|
| KBKDFByteArrayParam         | A static array of bytes to add to the PRF input stream     |
| KBKDFDKMLengthParam         | A structure for encoding and calculating KDF output length |
| KBKDFIterationVariableParam | Either an incrementing counter or a chaining value         |
| KBKDFOptionalCounterParam   | (In Feedback and Pipeline Modes); an optional counter      |

Please refer to [section 2.42.2 Mechanism Parameters][pkcs11-kbkdf-params]
for more information about correct usage of each parameter, how they correlate
to names in NIST SP800-108, and with which KDF modes each parameter can be
used.

#### Deriving Additional Keys

PKCS#11 v3.0 defines a way of extracting additional keys from the derived key
material. See [section 2.42.6 Deriving Additional Keys][pkcs11-kbkdf-adk] for
a comprehensive reference.

The `CK_DERIVED_KEY` PKCS#11 structure is mirrored in the `KBKDFDerivedKey`
class. Add PKCS#11 Attributes to the derived key, specify it in the KDF
parameter. After `kg.generateKey(...)` has been called, `getKey(...)` will
return the additional key.

### Example KBKDF Usage

Putting this all together, the following is a short example of how to use the
KBKDF to derive a single key for the SCP03 protocol.

```java
public SymmetricKey kbkdfDeriveSCP03Key(SymmetricKey master,
                                        byte[] context,
                                        byte kdfConstant,
                                        int kdfOutputSizeBytes) {
    KeyGenerator kg = KeyGenerator.getInstance("KbkdfCounter", "Mozilla-JSS");
    KBKDFCounterParams kcp = new KBKDFCounterParams();

    kcp.setPRF(PKCS11Algorithm.CKM_AES_CMAC);
    kcp.setPRFKey(master);

    kcp.setKeySize(kdfOutputSizeBytes);

    byte[] label = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, kdfConstant };
    kcp.addParameter(new KBKDFByteArrayParam(label));

    byte[] separator = new byte[] { 0x00 };
    kcp.addParameter(new KBKDFByteArrayParam(separator));

    KBKDFDataParameter length = new KBKDFDKMLengthParam(
        // How to calculate the length, were there multiple derived keys.
        PKCS11Constants.CK_SP800_108_DKM_LENGTH_SUM_OF_SEGMENTS,
        // This length is big endian, so littleEndian == false.
        false,
        // How many bits to encode the length. SCP03 requires two bytes.
        2*8
    );
    kcp.addParameter(length);

    KBKDFDataParameter counter = new KBKDFIterationVariableParam(false, 1*8);
    kcp.addParameter(counter);

    kcp.addParameter(new KBKDFByteArrayParam(context));

    kcp.setDerivedKeyAlgorithm(PKCS11Algorithm.CKM_AES_CBC);

    kg.init(kcp);
    return kg.generateKey();
}
```

## Design of KBKDF

Unlike past key generation mechanisms, the `CKM_SP800_108_*` PKCS#11 mechs
require extensive mechanism parameters. Under Java, these take the form of
[`java.security.spec.AlgorithmParameterSpec`][alg-param-spec] implementations,
but this leaves much to be desired when bridging the JNI gap. Our approach
involved creating new extensions to the [`NativeProxy`][native-proxy] class:
the [`NativeEnclosure`][native-enclosure].

Unlike a `NativeProxy` -- whose scope is implicit, a `NativeEnclosure`
formalizes and specifies the exact scope of a C pointer. In particular, a
`NativeProxy` instance could be created at any time by the JNI code; it is
then given to Java to handle usage and cleanup. Additionally, a `NativeProxy`
instance doesn't exist until it is created by C code.

Contrasting with that, we need our parameter specifications to exist prior
to the creation of the `NativeProxy` instance -- so we can populate them -- but
we still need to capture the creation, use, and destruction of the underlying
`NativeProxy`. This leads to two NativeEnclosure methods:

 - `acquireNativeResources(...)` to trigger an allocation of the
   `NativeProxy`, storing it on the `mPointer` member, and
 - `releaseNativeResources(...)` to trigger freeing it.

These get wrapped in `open(...)` and `close(...)` respective, allowing us to
implement the [`java.lang.AutoCloseable`][auto-close] class.

This lets us use the parameters in the `KeyGenerator` as following: prior
to the call (via JNI) to `PK11_DeriveKey(...)`. We call `open(...)` and
handle any issues creating the `CK_SP800_108_KDF_PARAMS` or
`CK_SP800_108_FEEDBACK_KDF_PARAMS` pointer. We pass this pointer directly to
`PK11_DeriveKey(...)`, and when we're done, call `close(...)` to handle
freeing it.

Thus, we incur only a single allocation and free when we're ready to use
the parameter, and the complexities of handling the JNI translation are
hidden from the programmer wishing to use it.

[alg-param-spec]: https://docs.oracle.com/javase/8/docs/api/java/security/spec/AlgorithmParameterSpec.html "java.security.spec.AlgorithmParameterSpec"
[auto-close]: https://docs.oracle.com/javase/8/docs/api/java/lang/AutoCloseable.html "java.lang.AutoCloseable"
[jca]: https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html "Java Cryptography Architecture Reference Guide"
[jss-crypto]: https://dogtagpki.github.io/jss/master/javadocs/org/mozilla/jss/crypto/package-summary.html "org.mozilla.jss.crypto.*"
[jss-pkcs11-algorithm]: https://dogtagpki.github.io/jss/master/javadocs/org/mozilla/jss/crypto/PKCS11Algorithm.html "org.mozilla.jss.crypto.PKCS11Algorithm"
[jss-pkcs11-constants]: https://dogtagpki.github.io/jss/master/javadocs/org/mozilla/jss/pkcs11/PKCS11Constants.html "org.mozilla.jss.pkcs11.PKCS11Constants"
[kbkdf-counter-params]: https://dogtagpki.github.io/jss/master/javadocs/org/mozilla/jss/crypto/KBKDFCounterParams.html "org.mozilla.jss.crypto.KBKDFCounterParams"
[kbkdf-feedback-params]: https://dogtagpki.github.io/jss/master/javadocs/org/mozilla/jss/crypto/KBKDFFeedbackParams.html "org.mozilla.jss.crypto.KBKDFFeedbackParams"
[kbkdf-pipeline-params]: https://dogtagpki.github.io/jss/master/javadocs/org/mozilla/jss/crypto/KBKDFPipelineParams.html "org.mozilla.jss.crypto.KBKDFPipelineParams"
[kbkdf-spec]: https://dogtagpki.github.io/jss/master/javadocs/org/mozilla/jss/crypto/KBKDFParameterSpec.html "org.mozilla.jss.crypto.KBKDFParameterSpec"
[kbkdf-spec-set-prf]: https://dogtagpki.github.io/jss/master/javadocs/org/mozilla/jss/crypto/KBKDFParameterSpec.html#setPRF-org.mozilla.jss.crypto.PKCS11Algorithm- "org.mozilla.jss.crypto.KBKDFParameterSpec setPRF(...)"
[kbkdf-spec-set-prf-key]: https://dogtagpki.github.io/jss/master/javadocs/org/mozilla/jss/crypto/KBKDFParameterSpec.html#setPRFKey-javax.crypto.SecretKey- "org.mozilla.jss.crypto.KBKDFParameterSpec setPRFKey(...)"
[kbkdf-spec-set-derived-algo]: https://dogtagpki.github.io/jss/master/javadocs/org/mozilla/jss/crypto/KBKDFParameterSpec.html#setDerivedKeyAlgorithm-org.mozilla.jss.crypto.PKCS11Algorithm- "org.mozilla.jss.crypto.KBKDFParameterSpec setDerivedKeyAlgorithm(...)"
[kbkdf-spec-set-key-size]: https://dogtagpki.github.io/jss/master/javadocs/org/mozilla/jss/crypto/KBKDFParameterSpec.html#setKeySize-int- "org.mozilla.jss.crypto.KBKDFParameterSpec setKeySize(...)"
[kbkdf-spec-set-iv]: https://dogtagpki.github.io/jss/master/javadocs/org/mozilla/jss/crypto/KBKDFFeedbackParams.html
[kbkdf-spec-set-params]: https://dogtagpki.github.io/jss/master/javadocs/org/mozilla/jss/crypto/KBKDFParameterSpec.html#setParameters-org.mozilla.jss.crypto.KBKDFDataParameter:A- "org.mozilla.jss.crypto.KBKDFParameterSpec setParameters(...)"
[kbkdf-spec-add-param]: https://dogtagpki.github.io/jss/master/javadocs/org/mozilla/jss/crypto/KBKDFParameterSpec.html#addParameter-org.mozilla.jss.crypto.KBKDFDataParameter- "org.mozilla.jss.crypto.KBKDFParameterSpec addParameter(...)"
[kbkdf-spec-set-keys]: https://dogtagpki.github.io/jss/master/javadocs/org/mozilla/jss/crypto/KBKDFParameterSpec.html#setAdditionalDerivedKeys-org.mozilla.jss.crypto.KBKDFDerivedKey:A- "org.mozilla.jss.crypto.KBKDFParameterSpec setAdditionalDerivedKeys(...)"
[kbkdf-spec-add-key]: https://dogtagpki.github.io/jss/master/javadocs/org/mozilla/jss/crypto/KBKDFParameterSpec.html#addAdditionalDerivedKey-org.mozilla.jss.crypto.KBKDFDerivedKey- "org.mozilla.jss.crypto.KBKDFParameterSpec addAdditionalDerivedKey(...)"
[key-generator]: https://docs.oracle.com/javase/8/docs/api/javax/crypto/KeyGenerator.html "javax.crypto.KeyGenerator"
[native-enclosure]: https://dogtagpki.github.io/jss/master/javadocs/org/mozilla/jss/util/NativeEnclosure.html "org.mozilla.jss.util.NativeEnclosure"
[native-proxy]: https://dogtagpki.github.io/jss/master/javadocs/org/mozilla/jss/util/NativeProxy.html "org.mozilla.jss.util.NativeProxy"
[pkcs11-kbkdf]: https://docs.oasis-open.org/pkcs11/pkcs11-curr/v3.0/csprd01/pkcs11-curr-v3.0-csprd01.html#_Toc437440585 "PKCS#11 v3.0: SP 800-108 Key Derivation"
[pkcs11-kbkdf-params]: https://docs.oasis-open.org/pkcs11/pkcs11-curr/v3.0/csprd01/pkcs11-curr-v3.0-csprd01.html#_Toc8118473 "PKCS#11 v3.0: SP 800-108 Key Derivation: 2.42.2 Mechanism Parameters"
[pkcs11-kbkdf-adk]: https://docs.oasis-open.org/pkcs11/pkcs11-curr/v3.0/csprd01/pkcs11-curr-v3.0-csprd01.html#_Toc8118477 "PKCS#11 v3.0: SP 800-108 Key Derivation: 2.42.6 Deriving Additional Keys"
[sp800-108]: https://csrc.nist.gov/publications/detail/sp/800-108/final "Recommendation for Key Derivation using Pseudorandom Functions (Revised)"
