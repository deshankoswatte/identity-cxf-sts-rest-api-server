package org.wso2.carbon.sts.rest.server.sts.util;

import org.apache.cxf.helpers.DOMUtils;
import org.apache.cxf.jaxws.context.WrappedMessageContext;
import org.apache.cxf.message.MessageImpl;
import org.apache.cxf.security.SecurityContext;
import org.apache.cxf.sts.QNameConstants;
import org.apache.cxf.sts.STSConstants;
import org.apache.cxf.sts.STSPropertiesMBean;
import org.apache.cxf.sts.StaticSTSProperties;
import org.apache.cxf.sts.claims.ClaimTypes;
import org.apache.cxf.sts.claims.ClaimsHandler;
import org.apache.cxf.sts.claims.ClaimsManager;
import org.apache.cxf.sts.operation.TokenIssueOperation;
import org.apache.cxf.sts.service.ServiceMBean;
import org.apache.cxf.sts.service.StaticService;
import org.apache.cxf.sts.token.provider.AttributeStatementProvider;
import org.apache.cxf.sts.token.provider.AuthenticationStatementProvider;
import org.apache.cxf.sts.token.provider.DefaultSubjectProvider;
import org.apache.cxf.sts.token.provider.SAMLTokenProvider;
import org.apache.cxf.sts.token.provider.TokenProvider;
import org.apache.cxf.ws.security.sts.provider.model.RequestSecurityTokenResponseCollectionType;
import org.apache.cxf.ws.security.sts.provider.model.RequestSecurityTokenResponseType;
import org.apache.cxf.ws.security.sts.provider.model.RequestSecurityTokenType;
import org.apache.wss4j.common.WSS4JConstants;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.principal.CustomTokenPrincipal;
import org.apache.wss4j.common.saml.builder.SAML1Constants;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.wso2.carbon.sts.rest.server.saml.custom.CustomAttributeProvider;
import org.wso2.carbon.sts.rest.server.saml.custom.CustomAuthenticationProvider;
import org.wso2.carbon.sts.rest.server.saml.custom.PasswordCallbackHandler;
import org.wso2.carbon.sts.rest.server.sts.custom.CustomClaimsHandler;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.Marshaller;
import java.io.StringWriter;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.wso2.carbon.sts.rest.server.saml.util.SAMLUtil.getEncryptionProperties;

public class STSUtil {

    public static String testIssueSaml1Token() throws Exception {
        TokenIssueOperation issueOperation = new TokenIssueOperation();

        addTokenProvider(issueOperation);

        addService(issueOperation);

        addSTSProperties(issueOperation);

        // Set the ClaimsManager
        ClaimsManager claimsManager = new ClaimsManager();
        ClaimsHandler claimsHandler = new CustomClaimsHandler();
        claimsManager.setClaimHandlers(Collections.singletonList(claimsHandler));
        issueOperation.setClaimsManager(claimsManager);

        // Mock up a request
        RequestSecurityTokenType request = new RequestSecurityTokenType();
        JAXBElement<String> tokenType =
                new JAXBElement<>(
                        QNameConstants.TOKEN_TYPE, String.class, WSS4JConstants.WSS_SAML_TOKEN_TYPE
                );
        request.getAny().add(tokenType);
        Element secondaryParameters = createSecondaryParameters();
        request.getAny().add(secondaryParameters);
        request.getAny().add(createAppliesToElement("PassiveSTSSampleApp"));

        Map<String, Object> msgCtx = setupMessageContext();

        List<RequestSecurityTokenResponseType> securityTokenResponse = issueToken(issueOperation, request,
                new CustomTokenPrincipal("admin"),
                msgCtx);

        JAXBElement<RequestSecurityTokenResponseType> jaxbResponse =
                QNameConstants.WS_TRUST_FACTORY.createRequestSecurityTokenResponse(securityTokenResponse.get(0));

        JAXBContext jaxbContext = JAXBContext.newInstance(RequestSecurityTokenResponseType.class);

        // Create XML Formatted Response.
        Marshaller jaxbMarshaller = jaxbContext.createMarshaller();
        jaxbMarshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE);
        StringWriter sw = new StringWriter();
        jaxbMarshaller.marshal(jaxbResponse, sw);

        return changeNamespaces(sw.toString());
    }

    public static String testIssueSaml2Token() throws Exception {
        TokenIssueOperation issueOperation = new TokenIssueOperation();

        addTokenProvider(issueOperation);

        addService(issueOperation);

        addSTSProperties(issueOperation);

        // Set the ClaimsManager
        ClaimsManager claimsManager = new ClaimsManager();
        ClaimsHandler claimsHandler = new CustomClaimsHandler();
        claimsManager.setClaimHandlers(Collections.singletonList(claimsHandler));
        issueOperation.setClaimsManager(claimsManager);

        // Mock up a request
        RequestSecurityTokenType request = new RequestSecurityTokenType();
        JAXBElement<String> tokenType =
                new JAXBElement<>(
                        QNameConstants.TOKEN_TYPE, String.class, WSS4JConstants.WSS_SAML2_TOKEN_TYPE
                );
        request.getAny().add(tokenType);
        Element secondaryParameters = createSecondaryParameters();
        request.getAny().add(secondaryParameters);
        request.getAny().add(createAppliesToElement("PassiveSTSSampleApp"));

        Map<String, Object> msgCtx = setupMessageContext();

        List<RequestSecurityTokenResponseType> securityTokenResponse = issueToken(issueOperation, request,
                new CustomTokenPrincipal("admin"),
                msgCtx);

        JAXBElement<RequestSecurityTokenResponseType> jaxbResponse =
                QNameConstants.WS_TRUST_FACTORY.createRequestSecurityTokenResponse(securityTokenResponse.get(0));

        JAXBContext jaxbContext = JAXBContext.newInstance(RequestSecurityTokenResponseType.class);

        // Create XML Formatted Response.
        Marshaller jaxbMarshaller = jaxbContext.createMarshaller();
        jaxbMarshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE);
        StringWriter sw = new StringWriter();
        jaxbMarshaller.marshal(jaxbResponse, sw);

        return changeNamespaces(sw.toString());
    }

    /**
     * @param issueOperation
     * @param request
     * @param principal
     * @param msgCtx
     * @return
     */
    private static List<RequestSecurityTokenResponseType> issueToken(TokenIssueOperation issueOperation,
                                                                     RequestSecurityTokenType request, Principal principal, Map<String, Object> msgCtx) {
        RequestSecurityTokenResponseCollectionType response =
                issueOperation.issue(request, principal, msgCtx);
        return response.getRequestSecurityTokenResponse();
    }

    /**
     * @return
     */
    private static Map<String, Object> setupMessageContext() {
        MessageImpl msg = new MessageImpl();
        WrappedMessageContext msgCtx = new WrappedMessageContext(msg);
        msgCtx.put(
                SecurityContext.class.getName(),
                createSecurityContext(new CustomTokenPrincipal("admin"))
        );
        return msgCtx;
    }

    /**
     * @param issueOperation
     * @throws WSSecurityException
     */
    private static void addSTSProperties(TokenIssueOperation issueOperation) throws WSSecurityException {
        STSPropertiesMBean stsProperties = new StaticSTSProperties();
        Crypto crypto = CryptoFactory.getInstance(getEncryptionProperties());
        stsProperties.setEncryptionCrypto(crypto);
        stsProperties.setSignatureCrypto(crypto);
        stsProperties.setEncryptionUsername("myservicekey");
        stsProperties.setSignatureUsername("mystskey");
        stsProperties.setCallbackHandler(new PasswordCallbackHandler());
        stsProperties.setIssuer("localhost");
        issueOperation.setStsProperties(stsProperties);
    }

    /**
     * @param issueOperation
     */
    private static void addService(TokenIssueOperation issueOperation) {
        ServiceMBean service = new StaticService();
        service.setEndpoints(Collections.singletonList("PassiveSTSSampleApp"));
        issueOperation.setServices(Collections.singletonList(service));
    }

    /**
     * @param issueOperation
     */
    private static void addTokenProvider(TokenIssueOperation issueOperation) {
        List<TokenProvider> providerList = new ArrayList<>();

        List<AttributeStatementProvider> customProviderList =
                new ArrayList<>();
        customProviderList.add(new CustomAttributeProvider());
        SAMLTokenProvider samlTokenProvider = new SAMLTokenProvider();

        DefaultSubjectProvider subjectProvider = new DefaultSubjectProvider();
        // The constant is same for SAML1.1 and SAML2.
        subjectProvider.setSubjectNameIDFormat(SAML1Constants.NAMEID_FORMAT_EMAIL_ADDRESS);
        samlTokenProvider.setSubjectProvider(subjectProvider);

        List<AuthenticationStatementProvider> customAuthenticationProviderList =
                new ArrayList<>();
        customAuthenticationProviderList.add(new CustomAuthenticationProvider());
        samlTokenProvider.setAuthenticationStatementProviders(customAuthenticationProviderList);

        samlTokenProvider.setAttributeStatementProviders(customProviderList);
        providerList.add(samlTokenProvider);
        issueOperation.setTokenProviders(providerList);
    }

    /*
     * Create a security context object
     */
    private static SecurityContext createSecurityContext(final Principal p) {
        return new SecurityContext() {
            public Principal getUserPrincipal() {
                return p;
            }

            public boolean isUserInRole(String role) {
                return false;
            }
        };
    }

    /*
     * Mock up an AppliesTo element using the supplied address
     */
    private static Element createAppliesToElement(String addressUrl) {
        Document doc = DOMUtils.getEmptyDocument();
        Element appliesTo = doc.createElementNS(STSConstants.WSP_NS, "wsp:AppliesTo");
        appliesTo.setAttributeNS(WSS4JConstants.XMLNS_NS, "xmlns:wsp", STSConstants.WSP_NS);
        Element endpointRef = doc.createElementNS(STSConstants.WSA_NS_05, "wsa:EndpointReference");
        endpointRef.setAttributeNS(WSS4JConstants.XMLNS_NS, "xmlns:wsa", STSConstants.WSA_NS_05);
        Element address = doc.createElementNS(STSConstants.WSA_NS_05, "wsa:Address");
        address.setAttributeNS(WSS4JConstants.XMLNS_NS, "xmlns:wsa", STSConstants.WSA_NS_05);
        address.setTextContent(addressUrl);
        endpointRef.appendChild(address);
        appliesTo.appendChild(endpointRef);
        return appliesTo;
    }

    /*
     * Mock up a SecondaryParameters DOM Element containing some claims
     */
    private static Element createSecondaryParameters() {
        Document doc = DOMUtils.getEmptyDocument();
        Element secondary = doc.createElementNS(STSConstants.WST_NS_05_12, "SecondaryParameters");
        secondary.setAttributeNS(WSS4JConstants.XMLNS_NS, "xmlns", STSConstants.WST_NS_05_12);

        Element claims = doc.createElementNS(STSConstants.WST_NS_05_12, "Claims");
        claims.setAttributeNS(null, "Dialect", STSConstants.IDT_NS_05_05);

        Element claimType = createClaimsType(doc);
        claims.appendChild(claimType);
        secondary.appendChild(claims);

        return secondary;
    }

    private static Element createClaimsType(Document doc) {
        Element claimType = doc.createElementNS(STSConstants.IDT_NS_05_05, "ClaimType");
        claimType.setAttributeNS(
                null, "Uri", ClaimTypes.LASTNAME.toString()
        );
        claimType.setAttributeNS(WSS4JConstants.XMLNS_NS, "xmlns", STSConstants.IDT_NS_05_05);

        return claimType;
    }

    private static String changeNamespaces(String response) {

        return response.
                replaceAll("ns2", "wsu").
                replaceAll("ns3", "wst").
                replaceAll("ns4", "wsse");
    }
}
