package org.apache.esb.sts.provider.token;

import java.security.cert.X509Certificate;

import org.w3c.dom.Element;

public interface TokenProvider {

	String getTokenType();
	
	Element createToken(String username);
	
	Element createToken(X509Certificate certificate);
	
	String getTokenId(Element token);
}
