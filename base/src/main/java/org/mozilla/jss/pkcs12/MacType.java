/* This Source Code Form is subject to the terms of the Mozilla Public
   * License, v. 2.0. If a copy of the MPL was not distributed with this
   * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

  package org.mozilla.jss.pkcs12;

  /**
   * Defines the MAC algorithm type for PKCS#12 integrity protection.
   */
  public enum MacType {
      CLASSIC,
      PBMAC1
  }
