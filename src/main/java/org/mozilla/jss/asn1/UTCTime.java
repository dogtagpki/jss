/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
package org.mozilla.jss.asn1;

import java.util.Date;

public class UTCTime extends TimeBase implements ASN1Value {

    public static final Tag TAG = new Tag(Tag.UNIVERSAL, 23);

    @Override
    public Tag getTag() {
        return TAG;
    }

    public UTCTime(Date date) {
        super(date);
    }

    @Override
    protected boolean isUTC() {
        return true;
    }

    private static final UTCTime.Template templateInstance = new UTCTime.Template();

    public static UTCTime.Template getTemplate() {
        return templateInstance;
    }

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
            return true;
        }

        @Override
        protected TimeBase generateInstance(Date date) {
            return new UTCTime(date);
        }
    }
}
