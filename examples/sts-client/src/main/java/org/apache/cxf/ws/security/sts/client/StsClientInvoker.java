package org.apache.cxf.ws.security.sts.client;

import java.io.ByteArrayInputStream;
import java.net.URL;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Timer;
import java.util.TimerTask;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.commons.codec.binary.Base64;
import org.apache.cxf.Bus;
import org.apache.cxf.bus.spring.SpringBusFactory;
import org.apache.cxf.ws.security.tokenstore.SecurityToken;
import org.apache.cxf.ws.security.trust.STSClient;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.util.XMLHelper;
import org.opensaml.xml.validation.ValidationException;
import org.springframework.beans.factory.InitializingBean;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

public class StsClientInvoker extends TimerTask implements InitializingBean {

	private STSClient stsClient;

	public void setStsClient(STSClient stsClient) {
		this.stsClient = stsClient;
	}

	@Override
	public void afterPropertiesSet() throws Exception {
		new Timer().schedule(this, 1000);
	}
	
	private XMLObject getSAMLAssertionResponse(SecurityToken securityToken) {
		
		Element token = securityToken.getToken();
		
		System.out.println(XMLHelper.prettyPrintXML(token));
		
		try {
			DefaultBootstrap.bootstrap();
		} catch (ConfigurationException e) {
			e.printStackTrace();
			throw new RuntimeException("OpenSAML configuration failed");
		}
		
		UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
		Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(token);
		
		try {
			return unmarshaller.unmarshall(token);
		} catch (UnmarshallingException e) {
			e.printStackTrace();
			throw new RuntimeException("Unmarshalling of token failed");
		}
	}
	
	public static Document toDom(XMLObject object) throws MarshallingException,
    ParserConfigurationException, ConfigurationException {
		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setValidating(false);
        factory.setNamespaceAware(true);
		Document document = factory.newDocumentBuilder().newDocument();
		
		DefaultBootstrap.bootstrap();
		
		Marshaller out = Configuration.getMarshallerFactory().getMarshaller(
		        object);
		out.marshall(object, document);
		return document;
		}
	
	@Override
	public void run() {
		try {
			SecurityToken securityToken = stsClient.requestSecurityToken();
			System.out.println("securityToken.getId()="
					+ securityToken.getId());
			
			XMLObject assertion = getSAMLAssertionResponse(securityToken);
			Signature signature = ((Assertion)assertion).getSignature();
			BasicX509Credential credential = new BasicX509Credential();
			byte[] x509 = null;
			Element elementNSImpl = (Element) toDom(((Assertion)assertion)).getDocumentElement();;
            NodeList x509CertData = elementNSImpl
                    .getElementsByTagNameNS("*", "X509Certificate");
            if (x509CertData != null && x509CertData.getLength() > 0) {
                x509 = Base64.decodeBase64(x509CertData.item(0)
                        .getTextContent().getBytes());
            }
            if (x509 != null) {
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                Certificate certificate = cf
                        .generateCertificate(new ByteArrayInputStream(x509));
                X509Certificate x509Cert = (X509Certificate) certificate;
                credential.setEntityCertificate(x509Cert);    
            }
            
            
			SignatureValidator sigValidator = new SignatureValidator(credential);
			try {
				sigValidator.validate(signature);
			} catch (ValidationException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			System.out.println("securityToken.getTokenType()="+securityToken.getTokenType());

			if (SAMLConstants.SAML1_NS.equals(securityToken.getTokenType())){
				System.out.println("assertion.getID() = " + ((org.opensaml.saml1.core.Assertion)assertion).getID());
				System.out.println("assertion.getIssuer() = " + ((org.opensaml.saml1.core.Assertion)assertion).getIssuer());
			} else if (SAMLConstants.SAML20_NS.equals(securityToken.getTokenType())) {
				System.out.println("assertion.getID() = " + ((Assertion)assertion).getID());
				System.out.println("assertion.getIssuer().getValue()" + ((Assertion)assertion).getIssuer().getValue());
			} else {
				throw new RuntimeException("Usupported token type");
			}
		} catch (RuntimeException e) {
			throw e;
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public static void main(String args[]) throws Exception {
		SpringBusFactory bf = new SpringBusFactory();
		URL busFile = StsClientInvoker.class
				.getResource("/META-INF/spring/beans.xml");
		Bus bus = bf.createBus(busFile.toString());
		SpringBusFactory.setDefaultBus(bus);
		Thread.sleep(50000);
	}
}
