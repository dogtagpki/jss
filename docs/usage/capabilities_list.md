CapabilitiesList
========================================

Overview
========================================

**CapabilitiesList** is a Java application to list the capabilities
of the "Mozilla-JSS" provider and other installed providers.
It does it in two fashions brief and verbose. 

It lets JSS contributors see what features the JDK implements (at different versions)
and see what else we'd need to add in, to reach compatibility. Since we're 
attempting to be a default crypto provider, it would be nice to ensure we're 
mostly close to what the JDK provides. Hopefully other packages written to the
JDK provider can have similar algorithms available under JSS and behave well. 
Large gaps in coverage are likely an issue such as [#341](https://github.com/dogtagpki/jss/issues/341)
and [#242](https://github.com/dogtagpki/jss/issues/242).

Usage
========================================
First build jss according to the instructions
here [README](../../README.md)
You should see in the build directory tests_jss.jar which is what
contains the application along with the regular tests.
From the `jss/build` directory execute

    ./run_test.sh org.mozilla.jss.tests.CapabilitiesList

and you should see a `listings` directory

Running `tree listings` should produce something like

    listings/
    ├── brief
    │   ├── Capabilities4JdkSASL.txt
    │   ├── Capabilities4Mozilla-JSS.txt
    │   ├── Capabilities4SunJCE.txt
    │   ├── Capabilities4SunJSSE.txt
    │   ├── Capabilities4SunPKCS11.txt
    │   ├── Capabilities4SunRsaSign.txt
    │   └── Capabilities4SUN.txt
    └── verbose
        ├── Capabilities4JdkSASL.txt
        ├── Capabilities4Mozilla-JSS.txt
        ├── Capabilities4SunJCE.txt
        ├── Capabilities4SunJSSE.txt
        ├── Capabilities4SunPKCS11.txt
        ├── Capabilities4SunRsaSign.txt
        └── Capabilities4SUN.txt

Here is a brief clip of Capabilities4Mozilla-JSS.txt

	 AlgorithmParameters : IvAlgorithmParameters
	 AlgorithmParameters : RC2AlgorithmParameters
	 AlgorithmParameters : RSAPSSAlgorithmParameters
	 Cipher : AES
	 Cipher : DES
	 Cipher : DESede
		 Alias: Cipher.DES3
	 Cipher : RC2
	 Cipher : RC4
	 Cipher : RSA
	 KeyFactory : DSA
	 KeyFactory : EC
	 KeyFactory : RSA
	 KeyGenerator : AES
	 KeyGenerator : DES
	 KeyGenerator : DESede
		 Alias: KeyGenerator.DES3
	 KeyGenerator : HmacSHA1
		... ommitted ...
	 KeyGenerator : HmacSHA512
	 KeyGenerator : KbkdfCounter
		 Alias: KeyGenerator.SP800-108-Counter
		... ommitted ...

Notice that the `Alias:` lines have extra indentation which makes it
easier to compare against the other providers.
