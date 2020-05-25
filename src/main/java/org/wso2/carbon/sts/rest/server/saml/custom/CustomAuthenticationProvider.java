package org.wso2.carbon.sts.rest.server.saml.custom;

import org.apache.cxf.sts.token.provider.AuthenticationStatementProvider;
import org.apache.cxf.sts.token.provider.TokenProviderParameters;
import org.apache.wss4j.common.WSS4JConstants;
import org.apache.wss4j.common.saml.bean.AuthenticationStatementBean;
import org.apache.wss4j.common.saml.builder.SAML1Constants;
import org.apache.wss4j.common.saml.builder.SAML2Constants;

/**
 * A custom AuthenticationStatementProvider implementation for use in the tests.
 */
public class CustomAuthenticationProvider implements AuthenticationStatementProvider {

    /**
     * Get an AuthenticationStatementBean using the given parameters.
     */
    public AuthenticationStatementBean getStatement(TokenProviderParameters providerParameters) {
        AuthenticationStatementBean authBean = new AuthenticationStatementBean();

//        SubjectLocalityBean subjectLocality = new SubjectLocalityBean();
//        subjectLocality.setIpAddress("127.0.0.1");
//        authBean.setSubjectLocality(subjectLocality);

        if (WSS4JConstants.WSS_SAML_TOKEN_TYPE.equals(
                providerParameters.getTokenRequirements().getTokenType())) {
            authBean.setAuthenticationMethod(SAML1Constants.AUTH_METHOD_PASSWORD);
        } else {
            authBean.setAuthenticationMethod(SAML2Constants.AUTH_CONTEXT_CLASS_REF_PASSWORD);
        }
        return authBean;
    }

}
