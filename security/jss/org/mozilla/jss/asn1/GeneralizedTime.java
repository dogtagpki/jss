/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
package org.mozilla.jss.asn1;

import java.io.InputStream;
import java.io.OutputStream;
import java.io.IOException;
import java.util.Calendar;
import java.util.Date;
import java.util.TimeZone;
import org.mozilla.jss.util.Assert;

/**
 * The ASN.1 type <code>GeneralizedTime</code>
 */
public class GeneralizedTime extends TimeBase implements ASN1Value {

    public static final Tag TAG = new Tag(Tag.UNIVERSAL, 24);
    public Tag getTag() {
        return TAG;
    }

    /**
     * Creates a <code>GeneralizedTime</code> from a Date.
     */
    public GeneralizedTime(Date date) {
        super(date);
    }

    protected boolean isUTC() {
        return false;
    }

    private static final GeneralizedTime.Template templateInstance =
                                new GeneralizedTime.Template();
    public static GeneralizedTime.Template getTemplate() {
        return templateInstance;
    }

    /**
     * A class for decoding <code>GeneralizedTime</code>s.
     */
    public static class Template extends TimeBase.Template
        implements ASN1Template
    {
        protected Tag getTag() {
            return TAG;
        }

        public boolean tagMatch(Tag tag) {
            return TAG.equals(tag);
        }

        protected boolean isUTC() {
            return false;
        }

        protected TimeBase generateInstance(Date date) {
            return new GeneralizedTime(date);
        }
    }
}
