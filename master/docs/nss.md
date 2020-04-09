# NSS

## Incompatible NSS/JSS Pairings

The minimum NSS version required by JSS is v3.44. Up to v3.44, NSS didn't
correctly support SECKEY_ConvertToPublicKey, returning NULL in some cases
with an EC private key. This was fixed in v3.44.

### JSS v4.6.3

JSS v4.6.3 doesn't support NSS versions between v3.47 and v3.50, inclusive.
This is because [moz-bz#1570501][moz-bz-1570501] introduced a bug that wasn't
caught and fixed until [moz-bz#1611209][moz-bz-1611209]. NSS versions v3.46
and earlier will work but lack CMAC and KBKDF support, and NSS versions v3.51
and later will work and have CMAC and KBKDF support.

JSS v4.6.4 introduces a check for working CMAC support (see the
[pull request][pr-425] or commit 16c8de46bb8f03a9e6e3489e751114655a31f9bf).

[moz-bz-1570501]: https://bugzilla.mozilla.org/show_bug.cgi?id=1570501 "Add CMAC to FreeBL and PKCS #11 libraries"
[moz-bz-1611209]: https://bugzilla.mozilla.org/show_bug.cgi?id=1611209 "Value of CKM_AES_CMAC and CKM_AES_CMAC_GENERAL are swapped"
[pr-425]: https://github.com/dogtagpki/jss/pull/425
