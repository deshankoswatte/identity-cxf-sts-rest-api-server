package org.wso2.carbon.sts.rest.server;

import org.wso2.carbon.sts.rest.server.saml.util.SAMLUtil;
import org.wso2.carbon.sts.rest.server.sts.util.STSUtil;

public class Test {

    public static void main(String[] args) throws Exception {
        System.out.println("SAML1 Assertion: ");
        System.out.println(SAMLUtil.createSaml1AuthenticationAssertion());
        System.out.println("\nSAML2 Assertion: ");
        System.out.println(SAMLUtil.createSaml2AuthenticationAssertion());
        System.out.println("\nSAML1 Token: ");
        System.out.println(STSUtil.testIssueSaml1Token());
        System.out.println("\nSAML2 Token: ");
        System.out.println(STSUtil.testIssueSaml2Token());
    }
}
