package org.wso2.carbon.sts.rest.server.saml.util;

import org.apache.cxf.jaxws.context.WrappedMessageContext;
import org.apache.cxf.message.MessageImpl;
import org.apache.cxf.sts.STSConstants;
import org.apache.cxf.sts.StaticSTSProperties;
import org.apache.cxf.sts.request.KeyRequirements;
import org.apache.cxf.sts.request.TokenRequirements;
import org.apache.cxf.sts.service.EncryptionProperties;
import org.apache.cxf.sts.token.provider.AttributeStatementProvider;
import org.apache.cxf.sts.token.provider.AuthenticationStatementProvider;
import org.apache.cxf.sts.token.provider.DefaultSubjectProvider;
import org.apache.cxf.sts.token.provider.SAMLTokenProvider;
import org.apache.cxf.sts.token.provider.TokenProvider;
import org.apache.cxf.sts.token.provider.TokenProviderParameters;
import org.apache.cxf.sts.token.provider.TokenProviderResponse;
import org.apache.wss4j.common.WSS4JConstants;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.principal.CustomTokenPrincipal;
import org.apache.wss4j.common.saml.builder.SAML1Constants;
import org.apache.wss4j.common.saml.builder.SAML2Constants;
import org.apache.wss4j.common.util.DOM2Writer;
import org.w3c.dom.Element;
import org.wso2.carbon.sts.rest.server.saml.custom.CustomAttributeProvider;
import org.wso2.carbon.sts.rest.server.saml.custom.CustomAuthenticationProvider;
import org.wso2.carbon.sts.rest.server.saml.custom.PasswordCallbackHandler;

import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

public class SAMLUtil {

    /**
     * @return
     * @throws Exception
     */
    public static String createSaml1AuthenticationAssertion() throws Exception {

        TokenProvider samlTokenProvider = new SAMLTokenProvider();
        TokenProviderParameters providerParameters =
                createProviderParameters(WSS4JConstants.WSS_SAML_TOKEN_TYPE, STSConstants.BEARER_KEY_KEYTYPE);

        DefaultSubjectProvider subjectProvider = new DefaultSubjectProvider();
        subjectProvider.setSubjectNameIDFormat(SAML1Constants.NAMEID_FORMAT_EMAIL_ADDRESS);
        ((SAMLTokenProvider) samlTokenProvider).setSubjectProvider(subjectProvider);

        List<AuthenticationStatementProvider> customProviderList =
                new ArrayList<>();
        customProviderList.add(new CustomAuthenticationProvider());
        ((SAMLTokenProvider) samlTokenProvider).setAuthenticationStatementProviders(customProviderList);

        List<AttributeStatementProvider> customAttributeProviderList =
                new ArrayList<>();
        customAttributeProviderList.add(new CustomAttributeProvider());
        ((SAMLTokenProvider)samlTokenProvider).setAttributeStatementProviders(customAttributeProviderList);

        TokenProviderResponse providerResponse = samlTokenProvider.createToken(providerParameters);

        Element token = (Element) providerResponse.getToken();

        return DOM2Writer.nodeToString(token);
    }

    /**
     * @return
     * @throws Exception
     */
    public static String createSaml2AuthenticationAssertion() throws Exception {

        TokenProvider samlTokenProvider = new SAMLTokenProvider();
        TokenProviderParameters providerParameters =
                createProviderParameters(WSS4JConstants.WSS_SAML2_TOKEN_TYPE, STSConstants.BEARER_KEY_KEYTYPE);

        DefaultSubjectProvider subjectProvider = new DefaultSubjectProvider();
        subjectProvider.setSubjectNameIDFormat(SAML2Constants.NAMEID_FORMAT_EMAIL_ADDRESS);
        ((SAMLTokenProvider) samlTokenProvider).setSubjectProvider(subjectProvider);

        List<AuthenticationStatementProvider> customProviderList =
                new ArrayList<>();
        customProviderList.add(new CustomAuthenticationProvider());
        ((SAMLTokenProvider) samlTokenProvider).setAuthenticationStatementProviders(customProviderList);

        List<AttributeStatementProvider> customAttributeProviderList =
                new ArrayList<>();
        customAttributeProviderList.add(new CustomAttributeProvider());
        ((SAMLTokenProvider)samlTokenProvider).setAttributeStatementProviders(customAttributeProviderList);

        TokenProviderResponse providerResponse = samlTokenProvider.createToken(providerParameters);

        Element token = (Element) providerResponse.getToken();

        return DOM2Writer.nodeToString(token);
    }

    /**
     * @param tokenType
     * @param keyType
     * @return
     * @throws WSSecurityException
     */
    private static TokenProviderParameters createProviderParameters(
            String tokenType, String keyType
    ) throws WSSecurityException {

        TokenProviderParameters parameters = new TokenProviderParameters();

        TokenRequirements tokenRequirements = new TokenRequirements();
        tokenRequirements.setTokenType(tokenType);
        parameters.setTokenRequirements(tokenRequirements);

        KeyRequirements keyRequirements = new KeyRequirements();
        keyRequirements.setKeyType(keyType);
        parameters.setKeyRequirements(keyRequirements);

        parameters.setPrincipal(new CustomTokenPrincipal("admin"));
        // Mock up message context
        MessageImpl msg = new MessageImpl();
        WrappedMessageContext msgCtx = new WrappedMessageContext(msg);
        parameters.setMessageContext(msgCtx);

        parameters.setAppliesToAddress("PassiveSTSSampleApp");

        // Add STSProperties object
        StaticSTSProperties stsProperties = new StaticSTSProperties();
        Crypto crypto = CryptoFactory.getInstance(getEncryptionProperties());
        stsProperties.setEncryptionCrypto(crypto);
        stsProperties.setSignatureCrypto(crypto);
        stsProperties.setEncryptionUsername("myservicekey");
        stsProperties.setSignatureUsername("mystskey");
        stsProperties.setCallbackHandler(new PasswordCallbackHandler());
        stsProperties.setIssuer("localhost");
        parameters.setStsProperties(stsProperties);

        parameters.setEncryptionProperties(new EncryptionProperties());

        return parameters;
    }

    /**
     * @return
     */
    public static Properties getEncryptionProperties() {

        Properties properties = new Properties();
        properties.put(
                "org.apache.wss4j.crypto.provider", "org.apache.wss4j.common.crypto.Merlin"
        );
        properties.put("org.apache.wss4j.crypto.merlin.keystore.password", "wso2carbon");
        properties.put("org.apache.wss4j.crypto.merlin.keystore.file", "keys/wso2carbon.jks");

        return properties;
    }
}
