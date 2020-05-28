package org.wso2.carbon.sts.rest.server.sts.custom;

import java.security.Principal;
import java.util.ArrayList;
import java.util.List;

import org.apache.cxf.rt.security.claims.Claim;
import org.apache.cxf.rt.security.claims.ClaimCollection;
import org.apache.cxf.sts.claims.ClaimTypes;
import org.apache.cxf.sts.claims.ClaimsHandler;
import org.apache.cxf.sts.claims.ClaimsParameters;
import org.apache.cxf.sts.claims.ProcessedClaim;
import org.apache.cxf.sts.claims.ProcessedClaimCollection;
import org.opensaml.core.xml.XMLObjectBuilder;
import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.schema.XSInteger;
import org.opensaml.saml.saml2.core.AttributeValue;

/**
 * A custom ClaimsHandler implementation for use in the tests.
 */
public class CustomClaimsHandler implements ClaimsHandler {

    public static final String ROLE_CLAIM =
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/role";
    private static List<String> knownURIs = new ArrayList<>();

    static {
        knownURIs.add(ClaimTypes.FIRSTNAME.toString());
        knownURIs.add(ClaimTypes.LASTNAME.toString());
        knownURIs.add(ClaimTypes.EMAILADDRESS.toString());
        knownURIs.add(ClaimTypes.STREETADDRESS.toString());
        knownURIs.add(ClaimTypes.MOBILEPHONE.toString());
        knownURIs.add(ROLE_CLAIM);
    }

    private String role = "DUMMY";

    public List<String> getSupportedClaimTypes() {
        return knownURIs;
    }

    public ProcessedClaimCollection retrieveClaimValues(
            ClaimCollection claims, ClaimsParameters parameters) {

        if (claims != null && !claims.isEmpty()) {
            ProcessedClaimCollection claimCollection = new ProcessedClaimCollection();
            for (Claim requestClaim : claims) {
                ProcessedClaim claim = new ProcessedClaim();
                claim.setClaimType(requestClaim.getClaimType());
                if (ClaimTypes.FIRSTNAME.toString().equals(requestClaim.getClaimType())) {
                    if (requestClaim instanceof CustomClaimParser.CustomRequestClaim) {
                        CustomClaimParser.CustomRequestClaim customClaim = (CustomClaimParser.CustomRequestClaim) requestClaim;
                        String customName = customClaim.getValues().get(0) + "@"
                                + customClaim.getScope();
                        claim.addValue(customName);
                    } else {
                        claim.addValue("alice");
                    }
                } else if (ClaimTypes.LASTNAME.toString().equals(requestClaim.getClaimType())) {
                    claim.addValue("doe");
                } else if (ClaimTypes.EMAILADDRESS.toString().equals(requestClaim.getClaimType())) {
                    claim.addValue("alice@cxf.apache.org");
                } else if (ClaimTypes.STREETADDRESS.toString().equals(requestClaim.getClaimType())) {
                    claim.addValue("1234 1st Street");
                } else if (ClaimTypes.MOBILEPHONE.toString().equals(requestClaim.getClaimType())) {
                    // Test custom (Integer) attribute value
                    XMLObjectBuilderFactory builderFactory =
                            XMLObjectProviderRegistrySupport.getBuilderFactory();

                    @SuppressWarnings("unchecked")
                    XMLObjectBuilder<XSInteger> xsIntegerBuilder =
                            (XMLObjectBuilder<XSInteger>)builderFactory.getBuilder(XSInteger.TYPE_NAME);
                    XSInteger attributeValue =
                            xsIntegerBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSInteger.TYPE_NAME);
                    attributeValue.setValue(185912592);

                    claim.addValue(attributeValue);

                } else if (ROLE_CLAIM.equals(requestClaim.getClaimType())) {
                    if (requestClaim.getValues().size() > 0) {
                        for (Object requestedRole : requestClaim.getValues()) {
                            if (isUserInRole(parameters.getPrincipal(), requestedRole.toString())) {
                                claim.addValue(requestedRole);
                            }
                        }
                        if (claim.getValues().isEmpty()) {
                            continue;
                        }
                    } else {
                        // If no specific role was requested return DUMMY role for user
                        claim.addValue(role);
                    }
                }
                claimCollection.add(claim);
            }
            return claimCollection;
        }

        return null;
    }

    private boolean isUserInRole(Principal principal, String requestedRole) {
        return true;
    }

    public void setRole(String role) {
        this.role = role;
    }
}
