package org.apache.esb.sts.provider.operation;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.xml.bind.JAXBElement;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.namespace.QName;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.cxf.helpers.DOMUtils;
import org.apache.esb.sts.provider.ProviderPasswordCallback;
import org.apache.esb.sts.provider.STSException;
import org.apache.esb.sts.provider.cert.CertificateVerificationException;
import org.apache.esb.sts.provider.cert.CertificateVerifier;
import org.apache.esb.sts.provider.cert.CertificateVerifierConfig;
import org.apache.esb.sts.provider.token.TokenProvider;
import org.oasis_open.docs.ws_sx.ws_trust._200512.RequestSecurityTokenResponseCollectionType;
import org.oasis_open.docs.ws_sx.ws_trust._200512.RequestSecurityTokenResponseType;
import org.oasis_open.docs.ws_sx.ws_trust._200512.RequestSecurityTokenType;
import org.oasis_open.docs.ws_sx.ws_trust._200512.RequestedReferenceType;
import org.oasis_open.docs.ws_sx.ws_trust._200512.RequestedSecurityTokenType;
import org.oasis_open.docs.ws_sx.ws_trust._200512.UseKeyType;
import org.oasis_open.docs.wss._2004._01.oasis_200401_wss_wssecurity_secext_1_0.KeyIdentifierType;
import org.oasis_open.docs.wss._2004._01.oasis_200401_wss_wssecurity_secext_1_0.SecurityTokenReferenceType;
import org.w3._2000._09.xmldsig.KeyInfoType;
import org.w3._2000._09.xmldsig.X509DataType;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

public class IssueDelegate implements IssueOperation {

	private static final org.oasis_open.docs.ws_sx.ws_trust._200512.ObjectFactory WS_TRUST_FACTORY = new org.oasis_open.docs.ws_sx.ws_trust._200512.ObjectFactory();
	private static final org.oasis_open.docs.wss._2004._01.oasis_200401_wss_wssecurity_secext_1_0.ObjectFactory WSSE_FACTORY = new org.oasis_open.docs.wss._2004._01.oasis_200401_wss_wssecurity_secext_1_0.ObjectFactory();

	private static final String SIGN_FACTORY_TYPE = "DOM";
	private static final String JKS_INSTANCE = "JKS";
	private static final String X_509 = "X.509";

	private static final QName QNAME_WST_TOKEN_TYPE = WS_TRUST_FACTORY
			.createTokenType("").getName();

	private ProviderPasswordCallback passwordCallback;
	private List<TokenProvider> tokenProviders;
	private CertificateVerifierConfig certificateVerifierConfig;

	public void setPasswordCallback(ProviderPasswordCallback passwordCallback) {
		this.passwordCallback = passwordCallback;
	}

	public void setTokenProviders(List<TokenProvider> tokenProviders) {
		this.tokenProviders = tokenProviders;
	}
	
	public void setCertificateVerifierConfig(CertificateVerifierConfig certificateVerifierConfig) {
		this.certificateVerifierConfig = certificateVerifierConfig;
	}

	@Override
	public RequestSecurityTokenResponseCollectionType issue(
			RequestSecurityTokenType request) {

		String tokenType = null;
		X509Certificate certificate = null;

		// parse input arguments
		for (Object requestObject : request.getAny()) {
			// certificate
			try {
				certificate = getCertificateFromRequest(requestObject);
			} catch (CertificateException e) {
				throw new STSException(
						"Can't extract X509 certificate from request", e);
			}

			// TokenType
			if (requestObject instanceof JAXBElement) {
				JAXBElement<?> jaxbElement = (JAXBElement<?>) requestObject;
				if (QNAME_WST_TOKEN_TYPE.equals(jaxbElement.getName())) {
					tokenType = (String) jaxbElement.getValue();
				}
			}
		}

		// check input arguments
		String username = passwordCallback.resetUsername();
		if (certificate != null) {
			try {
				verifyCertificate(certificate);
				username = certificate.getSubjectX500Principal().getName();
			} catch (Exception e) {
				throw new STSException(
						"Can't verify X509 certificate from request", e);
			}
		}

		if (username == null) {
			throw new STSException("No credentials provided");
		}

		if (tokenType == null) {
			throw new STSException("No token type requested");
		}

		if (certificate == null)
			try {
				authenticate(username, passwordCallback.resetPassword());
			} catch (IOException e) {
				// TODO Auto-generated catch block
				throw new STSException("Can not authenticate to STS provider for user " + username);
			}
		
		// create token
		TokenProvider tokenProvider = null;
		for (TokenProvider tp : tokenProviders) {
			if (tokenType.equals(tp.getTokenType())) {
				tokenProvider = tp;
				break;
			}
		}
		if (tokenProvider == null) {
			throw new STSException(
					"No token provider found for requested token type: "
							+ tokenType);
		}

		Element elementToken = tokenProvider.createToken(username);

		signSAML(elementToken);

		// prepare response
		RequestSecurityTokenResponseType response = wrapAssertionToResponse(
				tokenType, elementToken, tokenProvider.getTokenId(elementToken));

		RequestSecurityTokenResponseCollectionType responseCollection = WS_TRUST_FACTORY
				.createRequestSecurityTokenResponseCollectionType();
		responseCollection.getRequestSecurityTokenResponse().add(response);
		return responseCollection;
	}

	private void verifyCertificate(X509Certificate certificate)
			throws KeyStoreException, NoSuchAlgorithmException,
			CertificateException, FileNotFoundException, IOException, CertificateVerificationException {
		KeyStore ks = KeyStore.getInstance(JKS_INSTANCE);

		ks.load(this.getClass().getResourceAsStream(
				certificateVerifierConfig.getStorePath()),
				certificateVerifierConfig.getStorePwd().toCharArray());
		java.security.cert.Certificate stsCert = ks
				.getCertificate(certificateVerifierConfig.getKeyCertAlias());

		Set<X509Certificate> trustedRootCerts = new HashSet<X509Certificate>();
		trustedRootCerts.add((X509Certificate) stsCert);

		CertificateVerifier.verifyCertificate(certificate,
					trustedRootCerts);
	}

	private RequestSecurityTokenResponseType wrapAssertionToResponse(
			String tokenType, Element samlAssertion, String tokenId) {
		RequestSecurityTokenResponseType response = WS_TRUST_FACTORY
				.createRequestSecurityTokenResponseType();

		// TokenType
		JAXBElement<String> jaxbTokenType = WS_TRUST_FACTORY
				.createTokenType(tokenType);
		response.getAny().add(jaxbTokenType);

		// RequestedSecurityToken
		RequestedSecurityTokenType requestedTokenType = WS_TRUST_FACTORY
				.createRequestedSecurityTokenType();
		JAXBElement<RequestedSecurityTokenType> requestedToken = WS_TRUST_FACTORY
				.createRequestedSecurityToken(requestedTokenType);
		requestedTokenType.setAny(samlAssertion);
		response.getAny().add(requestedToken);

		// RequestedAttachedReference
		RequestedReferenceType requestedReferenceType = WS_TRUST_FACTORY
				.createRequestedReferenceType();
		SecurityTokenReferenceType securityTokenReferenceType = WSSE_FACTORY
				.createSecurityTokenReferenceType();
		KeyIdentifierType keyIdentifierType = WSSE_FACTORY
				.createKeyIdentifierType();
		keyIdentifierType.setValue(tokenId);
		JAXBElement<KeyIdentifierType> keyIdentifier = WSSE_FACTORY
				.createKeyIdentifier(keyIdentifierType);
		securityTokenReferenceType.getAny().add(keyIdentifier);
		requestedReferenceType
				.setSecurityTokenReference(securityTokenReferenceType);

		JAXBElement<RequestedReferenceType> requestedAttachedReference = WS_TRUST_FACTORY
				.createRequestedAttachedReference(requestedReferenceType);
		response.getAny().add(requestedAttachedReference);

		return response;
	}

	private X509Certificate getCertificateFromRequest(Object requestObject)
			throws CertificateException {
		UseKeyType useKeyType = extractType(requestObject, UseKeyType.class);
		if (null != useKeyType) {
			KeyInfoType keyInfoType = extractType(useKeyType.getAny(),
					KeyInfoType.class);
			if (null != keyInfoType) {
				for (Object keyInfoContent : keyInfoType.getContent()) {
					X509DataType x509DataType = extractType(keyInfoContent,
							X509DataType.class);
					if (null != x509DataType) {
						for (Object x509Object : x509DataType
								.getX509IssuerSerialOrX509SKIOrX509SubjectName()) {
							byte[] x509 = extractType(x509Object, byte[].class);
							if (null != x509) {
								CertificateFactory cf = CertificateFactory
										.getInstance(X_509);
								Certificate certificate = cf
										.generateCertificate(new ByteArrayInputStream(
												x509));
								X509Certificate ret = (X509Certificate) certificate;
								return ret;
							}
						}
					}
				}
			}
		}
		return null;
	}

	@SuppressWarnings("unchecked")
	private static final <T> T extractType(Object param, Class<T> clazz) {
		if (param instanceof JAXBElement) {
			JAXBElement<?> jaxbElement = (JAXBElement<?>) param;
			if (clazz == jaxbElement.getDeclaredType()) {
				return (T) jaxbElement.getValue();
			}
		}
		return null;
	}
	
	private void authenticate(String username, String password) throws IOException {
		try {
			Document document = DOMUtils.readXml(this.getClass().getResourceAsStream("/tomcat-users.xml"));
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
					if (!password.equals(currentPassword.getTextContent())) {
						throw new IOException("Wrong password");
					}
					System.out.println("Authentication successful for " + username);
					break;
				}
			}
		} catch (SAXException e) {
			// TODO Auto-generated catch block
		} catch (ParserConfigurationException e) {
			// TODO Auto-generated catch block
		} 
	}

	private void signSAML(Element assertionDocument) {

		InputStream isKeyStore = this.getClass()
				.getResourceAsStream(certificateVerifierConfig.getStorePath());


		KeyStoreInfo keyStoreInfo = new KeyStoreInfo(isKeyStore, certificateVerifierConfig.getStorePwd(),
				certificateVerifierConfig.getKeySignAlias(), certificateVerifierConfig.getKeySignPwd());

		signAssertion(assertionDocument, keyStoreInfo);
	}

	private void signAssertion(Element assertion, KeyStoreInfo keyStoreInfo) {

		String id = assertion.getAttribute("ID");
		String refId = (id != null) ? "#" + id : "";

		signXML(assertion, refId, keyStoreInfo);

		shiftSignatureElementInSaml(assertion);
	}

	private void shiftSignatureElementInSaml(Element target) {
		NodeList nl = target.getElementsByTagNameNS(XMLSignature.XMLNS,
				"Signature");
		if (nl.getLength() == 0) {
			return;
		}
		Element signatureElement = (Element) nl.item(0);

		boolean foundIssuer = false;
		Node elementAfterIssuer = null;
		NodeList children = target.getChildNodes();
		for (int i = 0; i < children.getLength(); i++) {
			Node child = children.item(i);
			if (foundIssuer) {
				elementAfterIssuer = child;
				break;
			}
			if (child.getNodeType() == Node.ELEMENT_NODE
					&& child.getLocalName().equals("Issuer"))
				foundIssuer = true;
		}

		// Place after the Issuer, or as first element if no Issuer:
		if (!foundIssuer || elementAfterIssuer != null) {
			target.removeChild(signatureElement);
			target.insertBefore(signatureElement,
					foundIssuer ? elementAfterIssuer : target.getFirstChild());
		}
	}

	private void signXML(Element target, String refId, KeyStoreInfo keyStoreInfo) {

		org.apache.xml.security.Init.init();

		XMLSignatureFactory signFactory = XMLSignatureFactory
				.getInstance(SIGN_FACTORY_TYPE);
		try {
			DigestMethod method = signFactory.newDigestMethod(
					"http://www.w3.org/2000/09/xmldsig#sha1", null);
			Transform transform = signFactory.newTransform(
					"http://www.w3.org/2000/09/xmldsig#enveloped-signature",
					(TransformParameterSpec) null);
			Reference ref = signFactory.newReference(refId, method,
					Collections.singletonList(transform), null, null);

			CanonicalizationMethod canonMethod = signFactory
					.newCanonicalizationMethod(
							"http://www.w3.org/2001/10/xml-exc-c14n#",
							(C14NMethodParameterSpec) null);
			SignatureMethod signMethod = signFactory.newSignatureMethod(
					"http://www.w3.org/2000/09/xmldsig#rsa-sha1", null);
			SignedInfo si = signFactory.newSignedInfo(canonMethod, signMethod,
					Collections.singletonList(ref));

			KeyStore.PrivateKeyEntry keyEntry = getKeyEntry(keyStoreInfo);
			if (keyEntry == null) {
				throw new IllegalStateException(
						"Key is not found in keystore. Alias: "
								+ keyStoreInfo.getAlias());
			}

			KeyInfo ki = getKeyInfo(signFactory, keyEntry);

			DOMSignContext dsc = new DOMSignContext(keyEntry.getPrivateKey(),
					target);

			XMLSignature signature = signFactory.newXMLSignature(si, ki);

			signature.sign(dsc);

		} catch (Exception e) {
			throw new STSException("Cannot sign xml document: " + e.getMessage(), e);
		}
	}

	private PrivateKeyEntry getKeyEntry(KeyStoreInfo keyStoreInfo)
			throws KeyStoreException, NoSuchAlgorithmException,
			CertificateException, IOException, UnrecoverableEntryException {

		KeyStore ks = KeyStore.getInstance(JKS_INSTANCE);
		ByteArrayInputStream is = new ByteArrayInputStream(
				keyStoreInfo.getContent());
		ks.load(is, keyStoreInfo.getStorePassword().toCharArray());
		KeyStore.PasswordProtection passwordProtection = new KeyStore.PasswordProtection(
				keyStoreInfo.getKeyPassword().toCharArray());
		KeyStore.PrivateKeyEntry keyEntry = (KeyStore.PrivateKeyEntry) ks
				.getEntry(keyStoreInfo.getAlias(), passwordProtection);
		return keyEntry;
	}

	private KeyInfo getKeyInfo(XMLSignatureFactory signFactory,
			PrivateKeyEntry keyEntry) {

		X509Certificate cert = (X509Certificate) keyEntry.getCertificate();

		KeyInfoFactory kif = signFactory.getKeyInfoFactory();
		List<Object> x509Content = new ArrayList<Object>();
		x509Content.add(cert.getSubjectX500Principal().getName());
		x509Content.add(cert);
		X509Data xd = kif.newX509Data(x509Content);
		return kif.newKeyInfo(Collections.singletonList(xd));
	}

	public class KeyStoreInfo {

		private byte[] content;
		private String storePassword;
		private String alias;
		private String keyPassword;

		public KeyStoreInfo(InputStream is, String storePassword, String alias,
				String keyPassword) {
			this.content = getBytes(is);
			this.alias = alias;
			this.storePassword = storePassword;
			this.keyPassword = keyPassword;
		}

		public byte[] getContent() {
			return content;
		}

		public String getAlias() {
			return alias;
		}

		public String getStorePassword() {
			return storePassword;
		}

		public String getKeyPassword() {
			return keyPassword;
		}

		private byte[] getBytes(InputStream is) {
			try {
				int len;
				int size = 1024;
				byte[] buf;

				ByteArrayOutputStream bos = new ByteArrayOutputStream();
				buf = new byte[size];
				while ((len = is.read(buf, 0, size)) != -1) {
					bos.write(buf, 0, len);
				}
				buf = bos.toByteArray();
				return buf;
			} catch (IOException e) {
				throw new IllegalStateException(
						"Cannot read keystore content: " + e.getMessage(), e);
			}
		}

	}
}