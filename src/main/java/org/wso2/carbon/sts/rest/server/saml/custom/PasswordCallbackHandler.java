package org.wso2.carbon.sts.rest.server.saml.custom;

import java.io.IOException;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.apache.wss4j.common.ext.WSPasswordCallback;

public class PasswordCallbackHandler implements CallbackHandler {

    public void handle(Callback[] callbacks) throws IOException,
            UnsupportedCallbackException {
        for (Callback callback : callbacks) {
            if (callback instanceof WSPasswordCallback) { // CXF
                WSPasswordCallback pc = (WSPasswordCallback) callback;
                if ("alice".equals(pc.getIdentifier())) {
                    pc.setPassword("clarinet");
                    break;
                } else if ("bob".equals(pc.getIdentifier())) {
                    pc.setPassword("trombone");
                    break;
                } else if ("wso2carbon".equals(pc.getIdentifier())) {
                    pc.setPassword("wso2carbon");
                    break;
                } else if ("myservicekey".equals(pc.getIdentifier())) {
                    pc.setPassword("skpass");
                    break;
                }
            }
        }
    }
}
