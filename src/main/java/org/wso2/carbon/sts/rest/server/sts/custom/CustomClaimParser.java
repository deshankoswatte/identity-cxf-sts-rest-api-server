package org.wso2.carbon.sts.rest.server.sts.custom;

import java.net.URI;

import org.w3c.dom.Element;

import org.apache.cxf.rt.security.claims.Claim;
import org.apache.cxf.sts.claims.ClaimsParser;

public class CustomClaimParser implements ClaimsParser {

    public static final String CLAIMS_DIALECT = "http://my.custom.org/my/custom/namespace";

    public Claim parse(Element claim) {

        String claimLocalName = claim.getLocalName();
        String claimNS = claim.getNamespaceURI();
        if (CLAIMS_DIALECT.equals(claimNS) && "MyElement".equals(claimLocalName)) {
            String claimTypeUri = claim.getAttributeNS(null, "Uri");
            CustomRequestClaim response = new CustomRequestClaim();
            response.setClaimType(URI.create(claimTypeUri));
            String claimValue = claim.getAttributeNS(null, "value");
            response.addValue(claimValue);
            String scope = claim.getAttributeNS(null, "scope");
            response.setScope(scope);
            return response;
        }
        return null;
    }

    public String getSupportedDialect() {
        return CLAIMS_DIALECT;
    }

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
