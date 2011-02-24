package org.apache.esb.sts.provider;

import java.io.File;
import java.io.IOException;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.stream.StreamSource;

import org.apache.cxf.helpers.DOMUtils;
import org.apache.ws.security.WSPasswordCallback;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

public class ProviderPasswordCallback implements CallbackHandler {

	private String username;

	public void handle(Callback[] callbacks) throws IOException,
			UnsupportedCallbackException {
		for (int i = 0; i < callbacks.length; i++) {
			WSPasswordCallback pc = (WSPasswordCallback) callbacks[i];

			int usage = pc.getUsage();
			if (usage == WSPasswordCallback.USERNAME_TOKEN_UNKNOWN) {
				username = pc.getIdentifier();
				String userPassword = pc.getPassword();

				try {
					Document document = DOMUtils.readXml(new StreamSource(new File(
							"src/main/resources/tomcat-users.xml")));
					NodeList users = document.getElementsByTagName("user");
					for (int userIndex = 0; userIndex < users.getLength(); userIndex++) {
						Node currentUser = users.item(userIndex);
						Attr currentUsername = (Attr) currentUser
								.getAttributes().getNamedItem("username");
						Attr currentPassword = (Attr) currentUser
								.getAttributes().getNamedItem("password");
						
						if (!username.equals(currentUsername.getTextContent())) {
							if (userIndex == users.getLength()-1) {
								throw new IOException("Wrong username");
							}
							continue;
						} else {
							if (!userPassword.equals(currentPassword.getTextContent())) {
								throw new IOException("Wrong password");
							}
							break;
						}
					}
				} catch (SAXException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (ParserConfigurationException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}

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

}
