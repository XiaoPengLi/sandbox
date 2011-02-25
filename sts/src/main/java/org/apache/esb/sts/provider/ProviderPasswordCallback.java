package org.apache.esb.sts.provider;

import java.io.IOException;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import org.apache.ws.security.WSPasswordCallback;

public class ProviderPasswordCallback implements CallbackHandler {

	private String username;
	private String password;

	public void handle(Callback[] callbacks) throws IOException,
			UnsupportedCallbackException {
		for (int i = 0; i < callbacks.length; i++) {
			WSPasswordCallback pc = (WSPasswordCallback) callbacks[i];

			int usage = pc.getUsage();
			if (usage == WSPasswordCallback.USERNAME_TOKEN_UNKNOWN) {
				username = pc.getIdentifier();
				password = pc.getPassword();			
			} else if (usage == WSPasswordCallback.SIGNATURE) {
			} else {
				throw new UnsupportedCallbackException(callbacks[i],
						"Unrecognized Callback");
			}
		}
	}

	public String resetUsername() {
		String result = username;
		username = null;
		return result;
	}

	public String resetPassword() {
		String result = password;
		password = null;
		return result;
	}
	
}
