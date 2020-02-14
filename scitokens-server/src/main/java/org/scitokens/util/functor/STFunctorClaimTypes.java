package org.scitokens.util.functor;

import edu.uiuc.ncsa.security.util.functor.FunctorType;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/13/18 at  7:41 AM
 */
public enum STFunctorClaimTypes implements FunctorType {
    ACCESS("$access");

    STFunctorClaimTypes(String value) {
        this.value = value;
    }

    String value;

    @Override
    public String getValue() {
        return value;
    }
}
