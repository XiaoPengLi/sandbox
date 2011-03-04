package org.apache.cxf.ws.security.sts.provider.token;

import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;

import org.joda.time.DateTime;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.impl.SecureRandomIdentifierGenerator;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.KeyInfoConfirmationDataType;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.saml2.core.impl.AssertionBuilder;
import org.opensaml.saml2.core.impl.AuthnContextBuilder;
import org.opensaml.saml2.core.impl.AuthnContextClassRefBuilder;
import org.opensaml.saml2.core.impl.AuthnStatementBuilder;
import org.opensaml.saml2.core.impl.ConditionsBuilder;
import org.opensaml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml2.core.impl.KeyInfoConfirmationDataTypeBuilder;
import org.opensaml.saml2.core.impl.NameIDBuilder;
import org.opensaml.saml2.core.impl.SubjectBuilder;
import org.opensaml.saml2.core.impl.SubjectConfirmationBuilder;
import org.opensaml.xml.security.credential.BasicKeyInfoGeneratorFactory;
import org.opensaml.xml.security.keyinfo.KeyInfoGenerator;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.security.x509.X509KeyInfoGeneratorFactory;
import org.opensaml.xml.signature.KeyInfo;
import org.w3c.dom.Element;

public class Saml2TokenProvider implements TokenProvider {

	private static final String SAML_AUTH_CONTEXT = "ac:classes:X509";

	@Override
	public String getTokenType() {
		return SAMLConstants.SAML20_NS;
	}

	@Override
	public Element createToken(X509Certificate certificate) {
		try {
			Subject subject = createSubject(certificate);
			Assertion samlAssertion = createAuthnAssertion(subject);
			return SamlUtils.toDom(samlAssertion).getDocumentElement();
		} catch (Exception e) {
			throw new TokenException("Can't serialize SAML assertion", e);
		}
	}
	
	@Override
	public Element createToken(String username) {
		Subject subject = createSubject(username);
		Assertion samlAssertion = createAuthnAssertion(subject);

		try {
			return SamlUtils.toDom(samlAssertion).getDocumentElement();
		} catch (Exception e) {
			throw new TokenException("Can't serialize SAML assertion", e);
		}
	}

	@Override
	public String getTokenId(Element token) {
		return token.getAttribute(Assertion.ID_ATTRIB_NAME);
	}

	private Subject createSubject(String username) {
		NameID nameID = (new NameIDBuilder()).buildObject();
		nameID.setValue(username);
		String format = "urn:oasis:names:tc:SAML:1.1:nameid-format:transient";
		if (format != null) {
			nameID.setFormat(format);
		}

		Subject subject = (new SubjectBuilder()).buildObject();
		subject.setNameID(nameID);

		SubjectConfirmation confirmation = (new SubjectConfirmationBuilder())
					.buildObject();
		confirmation.setMethod(SubjectConfirmation.METHOD_BEARER);
		subject.getSubjectConfirmations().add(confirmation);
		return subject;
	}

	private Subject createSubject(X509Certificate certificate) throws Exception{
		DefaultBootstrap.bootstrap();
		NameID nameID = (new NameIDBuilder()).buildObject();
		nameID.setValue(certificate.getSubjectDN().getName());
		String format = "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName";
		if (format != null) {
			nameID.setFormat(format);
		}
		Subject subject = (new SubjectBuilder()).buildObject();
		subject.setNameID(nameID);
		SubjectConfirmation confirmation = (new SubjectConfirmationBuilder())
					.buildObject();
		confirmation.setMethod(SubjectConfirmation.METHOD_HOLDER_OF_KEY);
		KeyInfoConfirmationDataType keyInfoDataType = new KeyInfoConfirmationDataTypeBuilder().buildObject();
		BasicX509Credential keyInfoCredential = new BasicX509Credential();
		keyInfoCredential.setEntityCertificate(certificate);
		keyInfoCredential.setPublicKey(certificate.getPublicKey());
		BasicKeyInfoGeneratorFactory kiFactory = new BasicKeyInfoGeneratorFactory();
		kiFactory.setEmitPublicKeyValue(true);
		KeyInfo keyInfo = kiFactory.newInstance().generate(keyInfoCredential);
		keyInfoDataType.getKeyInfos().add(keyInfo);	
		subject.getSubjectConfirmations().add(confirmation);
		subject.getSubjectConfirmations().get(0).setSubjectConfirmationData(keyInfoDataType);
		return subject;
	}
	
	private Assertion createAuthnAssertion(Subject subject) {
		Assertion assertion = createAssertion(subject);

		AuthnContextClassRef ref = (new AuthnContextClassRefBuilder())
				.buildObject();
		String authnCtx = SAML_AUTH_CONTEXT;
		if (authnCtx != null) {
			ref.setAuthnContextClassRef(authnCtx);
		}
		AuthnContext authnContext = (new AuthnContextBuilder()).buildObject();
		authnContext.setAuthnContextClassRef(ref);

		AuthnStatement authnStatement = (new AuthnStatementBuilder())
				.buildObject();
		authnStatement.setAuthnInstant(new DateTime());
		authnStatement.setAuthnContext(authnContext);

		assertion.getStatements().add(authnStatement);

		return assertion;
	}

	private Assertion createAssertion(Subject subject) {
		Assertion assertion = (new AssertionBuilder()).buildObject();
		try {
			SecureRandomIdentifierGenerator generator = new SecureRandomIdentifierGenerator();
			assertion.setID(generator.generateIdentifier());
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}

		DateTime now = new DateTime();
		assertion.setIssueInstant(now);

		String issuerURL = "http://www.sopera.de/SAML2";
		if (issuerURL != null) {
			Issuer issuer = (new IssuerBuilder()).buildObject();
			issuer.setValue(issuerURL);
			assertion.setIssuer(issuer);
		}

		assertion.setSubject(subject);

		Conditions conditions = (new ConditionsBuilder()).buildObject();
		conditions.setNotBefore(now.minusMillis(3600000));
		conditions.setNotOnOrAfter(now.plusMillis(3600000));
		assertion.setConditions(conditions);
		return assertion;
	}

}
