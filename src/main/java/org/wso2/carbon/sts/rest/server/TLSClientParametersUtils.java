package org.wso2.carbon.sts.rest.server;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;

import org.apache.cxf.configuration.jsse.TLSClientParameters;
import org.apache.cxf.rt.security.crypto.CryptoUtils;
import org.apache.xml.security.utils.ClassLoaderUtils;

public final class TLSClientParametersUtils {

    private static final String CLIENTSTORE = "/keys/clientstore.jks";
    private static final String KEYSTORE_PASS = "cspass";
    private static final String KEY_PASS = "ckpass";

    private TLSClientParametersUtils() {
    }

    public static TLSClientParameters getTLSClientParameters() throws GeneralSecurityException, IOException {
        final TLSClientParameters tlsCP = new TLSClientParameters();
        tlsCP.setDisableCNCheck(true);

        final KeyStore keyStore;
        try (InputStream is = ClassLoaderUtils.getResourceAsStream(CLIENTSTORE, TLSClientParametersUtils.class)) {
            keyStore = CryptoUtils.loadKeyStore(is, KEYSTORE_PASS.toCharArray(), null);
        }

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, KEY_PASS.toCharArray());
        tlsCP.setKeyManagers(kmf.getKeyManagers());

        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(keyStore);
        tlsCP.setTrustManagers(tmf.getTrustManagers());

        return tlsCP;
    }

}
