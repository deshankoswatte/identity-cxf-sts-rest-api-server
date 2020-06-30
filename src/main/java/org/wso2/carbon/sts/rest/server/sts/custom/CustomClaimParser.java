package org.wso2.carbon.sts.rest.server.sts.custom;

import org.apache.cxf.rt.security.claims.Claim;

public class CustomClaimParser {

    /**
     * Extends RequestClaim class to add additional attributes
     */
    public class CustomRequestClaim extends Claim {
        /**
         *
         */
        private static final long serialVersionUID = 7407723714936495457L;
        private String scope;

        public String getScope() {
            return scope;
        }

        public void setScope(String scope) {
            this.scope = scope;
        }
    }

}
