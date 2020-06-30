package org.wso2.carbon.sts.rest.server.saml.custom;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.w3c.dom.Element;

import org.apache.cxf.sts.claims.ClaimsUtils;
import org.apache.cxf.sts.claims.ProcessedClaim;
import org.apache.cxf.sts.claims.ProcessedClaimCollection;
import org.apache.cxf.sts.request.ReceivedToken;
import org.apache.cxf.sts.request.TokenRequirements;
import org.apache.cxf.sts.token.provider.AttributeStatementProvider;
import org.apache.cxf.sts.token.provider.TokenProviderParameters;
import org.apache.cxf.ws.security.sts.provider.STSException;
import org.apache.cxf.ws.security.sts.provider.model.secext.UsernameTokenType;
import org.apache.wss4j.common.WSS4JConstants;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.principal.SAMLTokenPrincipal;
import org.apache.wss4j.common.principal.SAMLTokenPrincipalImpl;
import org.apache.wss4j.common.saml.SamlAssertionWrapper;
import org.apache.wss4j.common.saml.bean.AttributeBean;
import org.apache.wss4j.common.saml.bean.AttributeStatementBean;

/**
 * A custom AttributeStatementProvider implementation for use in the tests.
 */
public class CustomAttributeProvider implements AttributeStatementProvider {

    /**
     * Get an AttributeStatementBean using the given parameters.
     */
    public AttributeStatementBean getStatement(TokenProviderParameters providerParameters) {
        List<AttributeBean> attributeList = new ArrayList<>();

        TokenRequirements tokenRequirements = providerParameters.getTokenRequirements();
        String tokenType = tokenRequirements.getTokenType();

        // Handle Claims
        ProcessedClaimCollection retrievedClaims = ClaimsUtils.processClaims(providerParameters);

        AttributeStatementBean attrBean = new AttributeStatementBean();
        Iterator<ProcessedClaim> claimIterator = retrievedClaims.iterator();
        if (!claimIterator.hasNext()) {
            // If no Claims have been processed then create a default attribute
            AttributeBean attributeBean = createDefaultAttribute(tokenType);
            attributeList.add(attributeBean);
        }

        while (claimIterator.hasNext()) {
            ProcessedClaim claim = claimIterator.next();
            AttributeBean attributeBean = createAttributeFromClaim(claim, tokenType);
            attributeList.add(attributeBean);
        }
//
//        ReceivedToken onBehalfOf = tokenRequirements.getOnBehalfOf();
//        ReceivedToken actAs = tokenRequirements.getActAs();
//        try {
//            if (onBehalfOf != null) {
//                AttributeBean parameterBean =
//                        handleAdditionalParameters(false, onBehalfOf.getToken(), tokenType);
//                if (!parameterBean.getAttributeValues().isEmpty()) {
//                    attributeList.add(parameterBean);
//                }
//            }
//            if (actAs != null) {
//                AttributeBean parameterBean =
//                        handleAdditionalParameters(true, actAs.getToken(), tokenType);
//                if (!parameterBean.getAttributeValues().isEmpty()) {
//                    attributeList.add(parameterBean);
//                }
//            }
//        } catch (WSSecurityException ex) {
//            throw new STSException(ex.getMessage(), ex);
//        }

        attrBean.setSamlAttributes(attributeList);

        return attrBean;
    }

    /**
     * Create a default attribute.
     *
     * @param tokenType Type of the token SAML1.1/SAML2.0.
     * @return Attribute bean containing the default attribute.
     */
    private AttributeBean createDefaultAttribute(String tokenType) {
        AttributeBean attributeBean = new AttributeBean();

        if (WSS4JConstants.WSS_SAML2_TOKEN_TYPE.equals(tokenType)
                || WSS4JConstants.SAML2_NS.equals(tokenType)) {
            attributeBean.setQualifiedName("http://wso2.org/claims/username");
            attributeBean.setNameFormat("http://wso2.org/claims/username");
        } else {
            attributeBean.setSimpleName("username");
            attributeBean.setQualifiedName("http://wso2.org/claims/username");
        }

        attributeBean.addAttributeValue("admin");

        return attributeBean;
    }

//    /**
//     * Handle ActAs or OnBehalfOf elements.
//     */
//    private AttributeBean handleAdditionalParameters(
//            boolean actAs,
//            Object parameter,
//            String tokenType
//    ) throws WSSecurityException {
//        AttributeBean parameterBean = new AttributeBean();
//
//        String claimType = actAs ? "CustomActAs" : "CustomOnBehalfOf";
//        if (WSS4JConstants.WSS_SAML2_TOKEN_TYPE.equals(tokenType) || WSS4JConstants.SAML2_NS.equals(tokenType)) {
//            parameterBean.setQualifiedName(claimType);
//            parameterBean.setNameFormat("http://cxf.apache.org/sts/custom/" + claimType);
//        } else {
//            parameterBean.setSimpleName(claimType);
//            parameterBean.setQualifiedName("http://cxf.apache.org/sts/custom/" + claimType);
//        }
//        if (parameter instanceof UsernameTokenType) {
//            parameterBean.addAttributeValue(
//                    ((UsernameTokenType)parameter).getUsername().getValue()
//            );
//        } else if (parameter instanceof Element) {
//            SamlAssertionWrapper wrapper = new SamlAssertionWrapper((Element)parameter);
//            SAMLTokenPrincipal principal = new SAMLTokenPrincipalImpl(wrapper);
//            parameterBean.addAttributeValue(principal.getName());
//        }
//
//        return parameterBean;
//    }

    /**
     * Create an Attribute from a claim.
     */
    private AttributeBean createAttributeFromClaim(ProcessedClaim claim, String tokenType) {
        AttributeBean attributeBean = new AttributeBean();
        if (WSS4JConstants.WSS_SAML2_TOKEN_TYPE.equals(tokenType)
                || WSS4JConstants.SAML2_NS.equals(tokenType)) {
            attributeBean.setQualifiedName(claim.getClaimType());
        } else {
            attributeBean.setSimpleName(claim.getClaimType());
        }
        attributeBean.setAttributeValues(claim.getValues());

        return attributeBean;
    }

}
