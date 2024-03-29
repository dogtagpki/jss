/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
package org.mozilla.jss.asn1;

import java.util.Date;

/**
 * The ASN.1 type <code>GeneralizedTime</code>
 */
public class GeneralizedTime extends TimeBase {

    public static final Tag TAG = new Tag(Tag.UNIVERSAL, 24);

    @Override
    public Tag getTag() {
        return TAG;
    }

    /**
     * Creates a <code>GeneralizedTime</code> from a Date.
     *
     * @param date Input date.
     */
    public GeneralizedTime(Date date) {
        super(date);
    }

    @Override
    protected boolean isUTC() {
        return false;
    }

    private static final GeneralizedTime.Template templateInstance = new GeneralizedTime.Template();

    public static GeneralizedTime.Template getTemplate() {
        return templateInstance;
    }

    /**
     * A class for decoding <code>GeneralizedTime</code>s.
     */
    public static class Template extends TimeBase.Template
            implements ASN1Template {
        @Override
        protected Tag getTag() {
            return TAG;
        }

        @Override
        public boolean tagMatch(Tag tag) {
            return TAG.equals(tag);
        }

        @Override
        protected boolean isUTC() {
            return false;
        }

        @Override
        protected TimeBase generateInstance(Date date) {
            return new GeneralizedTime(date);
        }
    }
}
