package org.wso2.carbon.sts.rest.server;

import org.wso2.carbon.sts.rest.server.util.Util;

public class Test {

    public static void main(String[] args) throws Exception {
        System.out.println("SAML1 Assertion: ");
        System.out.println(Util.createSaml1AuthenticationAssertion());
        System.out.println("\nSAML2 Assertion: ");
        System.out.println(Util.createSaml2AuthenticationAssertion());
    }
}
