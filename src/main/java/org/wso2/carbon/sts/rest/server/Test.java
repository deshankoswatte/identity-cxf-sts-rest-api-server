package org.wso2.carbon.sts.rest.server;

import org.apache.cxf.jaxrs.client.WebClient;
import org.apache.cxf.testutil.common.AbstractBusClientServerTestBase;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.w3c.dom.Document;

import javax.ws.rs.core.MediaType;

public class Test extends AbstractBusClientServerTestBase {

    static final String STSPORT = allocatePort(STSRESTServer.class);

    private static final String SAML1_TOKEN_TYPE =
            "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV1.1";
    private static final String SAML2_TOKEN_TYPE =
            "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0";
    private static final String JWT_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:jwt";
    private static final String DEFAULT_ADDRESS =
            "https://localhost:8081/doubleit/services/doubleittransportsaml1";
    private WebClient webClient;

    private static Crypto serviceCrypto;
    public static void main(String[] args) throws Exception {

        launchServer(STSRESTServer.class, true);
        serviceCrypto = CryptoFactory.getInstance("serviceKeystore.properties");
//        Thread.currentThread().join();

        WebClient client = new Test().webClient()
                .path("saml2.0")
                .accept(MediaType.APPLICATION_XML);

        Document assertionDoc = client.get(Document.class);
        System.out.println(assertionDoc.toString());
    }


    private WebClient webClient() throws Exception {
        closeClient();

        webClient = WebClient.create("https://localhost:" + STSPORT + "/SecurityTokenService/token");
        webClient.getConfiguration().getHttpConduit()
                .setTlsClientParameters(TLSClientParametersUtils.getTLSClientParameters());
        return webClient;
    }

    public void closeClient() throws Exception {
        if (null != webClient) {
            webClient.close();
        }
    }
}
