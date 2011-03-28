/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.cxf.ws.security.sts.provider.operation;



import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import javax.xml.bind.JAXBElement;
import javax.xml.namespace.QName;
import org.apache.commons.codec.binary.Base64;
import org.apache.cxf.ws.security.sts.provider.ProviderPasswordCallback;
import org.apache.cxf.ws.security.sts.provider.STSException;
import org.apache.cxf.ws.security.sts.provider.cert.CertificateVerifierConfig;
import org.apache.cxf.ws.security.sts.provider.token.Saml1TokenProvider;
import org.apache.cxf.ws.security.sts.provider.token.Saml2TokenProvider;
import org.apache.cxf.ws.security.sts.provider.token.TokenProvider;
import org.easymock.EasyMock;
import org.junit.Test;
import org.oasis_open.docs.ws_sx.ws_trust._200512.RequestSecurityTokenType;
import org.oasis_open.docs.ws_sx.ws_trust._200512.UseKeyType;
import org.w3._2000._09.xmldsig.KeyInfoType;
import org.w3._2000._09.xmldsig.X509DataType;

import static org.easymock.EasyMock.createMock;
import static org.easymock.EasyMock.verify;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;


public class IssueDelegateTest {

    

    private static final String CERT_DATA = 
        //"MIICsjCCAhsCBRI0VniSMA0GCSqGSIb3DQEBBQUAMIGjMQswCQYDVQQGEwJVQTEQMA4GA1UECAwHTHVnYW5zazEQMA4GA1UEBwwHTHVnYW5zazESMBAGA1UECgwJSW5mb3B1bHNlMRMwEQYDVQQLDApUYWxlbmRUZWFtMRkwFwYDVQQDDBBQYXZlbFZhc2lsY2hlbmtvMSwwKgYJKoZIhvcNAQkBFh1QYXZlbC5TLlZhc2lsY2hlbmtvQGdtYWlsLmNvbTAeFw0xMTAyMjMxMjA4NDVaFw0yMTAyMjAxMjA4NDVaMIGaMRowGAYDVQQDExFUYWxlbmRDZXJ0aWZpY2F0ZTEPMA0GA1UECxMGVGFsZW5kMQ8wDQYDVQQKEwZUYWxlbmQxEzARBgNVBAcTCkN1c3RvbUNpdHkxFDASBgNVBAgTC0N1c3RvbVN0YXRlMQswCQYDVQQGEwJERTEiMCAGCSqGSIb3DQEJARYTZXhhbXBsZUBleGFtcGxlLmNvbTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAqD49IHig6rd9p5NTF0YzI+XMlUZThG5Us1DdcOUpPTp2i5m3wukWlRXFd4BZcp+PClbvyuNr/8kF0rDcxejvqMZrloQ1h4ncJvSW9udULh+M53vynuhSTDQWVWIOPxbREInNkx1kTm/uqhWf8JtewW6maH3Pz4Ll6Hcj8KWsnIUCAwEAATANBgkqhkiG9w0BAQUFAAOBgQB+EALhJN+LKDtTLSpgA3osgXmyV7UfKujTH/RQwGkMyM8KBzhaXvLgfLrcNrVFNzvv/BcWs2vxc15r0RmkAaSkpZig0scWR98mUW466xoh3cbbt4Dj7hmiinvyBingVdn3Z2IjRzfW2aACsMgk8e5kyhHdRY8OMucKxrDaQn0amg==";
    	"MIIEFjCCA3+gAwIBAgIJAJORWX2Xsa8DMA0GCSqGSIb3DQEBBQUAMIG5MQswCQYDVQQGEwJVUzERMA8GA1UECBMITmV3IFlvcmsxFjAUBgNVBAcTDU5pYWdhcmEgRmFsbHMxLDAqBgNVBAoTI1NhbXBsZSBDbGllbnQgLS0gTk9UIEZPUiBQUk9EVUNUSU9OMRYwFAYDVQQLEw1JVCBEZXBhcnRtZW50MRcwFQYDVQQDEw53d3cuY2xpZW50LmNvbTEgMB4GCSqGSIb3DQEJARYRY2xpZW50QGNsaWVudC5jb20wHhcNMTEwMjA5MTgzMDI3WhcNMjEwMjA2MTgzMDI3WjCBuTELMAkGA1UEBhMCVVMxETAPBgNVBAgTCE5ldyBZb3JrMRYwFAYDVQQHEw1OaWFnYXJhIEZhbGxzMSwwKgYDVQQKEyNTYW1wbGUgQ2xpZW50IC0tIE5PVCBGT1IgUFJPRFVDVElPTjEWMBQGA1UECxMNSVQgRGVwYXJ0bWVudDEXMBUGA1UEAxMOd3d3LmNsaWVudC5jb20xIDAeBgkqhkiG9w0BCQEWEWNsaWVudEBjbGllbnQuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDauFNVqi4B2+u/PC9ktDkn82bglEQYcL4o5JRUhQVEhTK2iEloz1Rvo/qyfDhBPc1lzIUn4ams+DKBSSjZMCgop3XbeCXzIVP784ruC8HF5QrYsXUQfTc7lzqafXZXH8Bk89gSScA1fFme6TpvYzM0zjBETSXADtKOs9oKB2VOIwIDAQABo4IBIjCCAR4wHQYDVR0OBBYEFFIz+0BSZlLtXkA/udRjRgphtREuMIHuBgNVHSMEgeYwgeOAFFIz+0BSZlLtXkA/udRjRgphtREuoYG/pIG8MIG5MQswCQYDVQQGEwJVUzERMA8GA1UECBMITmV3IFlvcmsxFjAUBgNVBAcTDU5pYWdhcmEgRmFsbHMxLDAqBgNVBAoTI1NhbXBsZSBDbGllbnQgLS0gTk9UIEZPUiBQUk9EVUNUSU9OMRYwFAYDVQQLEw1JVCBEZXBhcnRtZW50MRcwFQYDVQQDEw53d3cuY2xpZW50LmNvbTEgMB4GCSqGSIb3DQEJARYRY2xpZW50QGNsaWVudC5jb22CCQCTkVl9l7GvAzAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBBQUAA4GBAEjEr9QfaYsZf7ELnqB++OkWcKxpMt1Yj/VOyL99AekkVTM+rRHCU9Bu+tncMNsfy8mIXUC1JqKQ+Cq5RlaDh/ujzt6i17G7uSGd6U1U/DPZBqTm3Dxwl1cMAGU/CoAKTWE+o+fS4Q2xHv7L1KiXQQc9EWJ4C34Ik45fB6g3DiTj";
    RequestSecurityTokenType requestMock = createMock(RequestSecurityTokenType.class);

    ProviderPasswordCallback passwordCallbackMock = createMock(ProviderPasswordCallback.class); 
    private String storePath = "/stsstore.jks";
    private String storePwd = "stsspass";
    private String keySignAlias = "mystskey";
    private String keySignPwd = "stskpass";
    
    @Test
    public void testIssueDelegateNullParameter() {
        IssueDelegate id = new IssueDelegate();
        ProviderPasswordCallback passwordCallback = new ProviderPasswordCallback();
        id.setPasswordCallback(passwordCallback);

        try {
            id.issue(null);
            fail("NullPointerException should be thrown");
        } catch (NullPointerException e) {
        	// expected
        }
    }

    @Test
    public void testIssueDelegate() {
        IssueDelegate id = new IssueDelegate();
        CertificateVerifierConfig certificateVerifierConfig = new CertificateVerifierConfig();
        certificateVerifierConfig.setTrustCertAliases(Arrays.asList("myclientkey"));
        certificateVerifierConfig.setKeySignAlias(keySignAlias);
        certificateVerifierConfig.setKeySignPwd(keySignPwd);
        certificateVerifierConfig.setStorePath(storePath);
        certificateVerifierConfig.setStorePwd(storePwd);
        id.setCertificateVerifierConfig(certificateVerifierConfig);

        EasyMock.expect(passwordCallbackMock.resetUsername()).andReturn("joe");
        EasyMock.expect(passwordCallbackMock.resetPassword()).andReturn(
                "joespassword");
        EasyMock.replay(passwordCallbackMock);

        id.setPasswordCallback(passwordCallbackMock);

        JAXBElement<String> tokenType = new JAXBElement<String>(
                new QName("http://docs.oasis-open.org/ws-sx/ws-trust/200512",
                        "TokenType"), String.class,
                "urn:oasis:names:tc:SAML:1.0:assertion");

        EasyMock.expect(requestMock.getAny()).andStubReturn(
                Arrays.asList((Object) tokenType));

        EasyMock.replay(requestMock);

        TokenProvider tp1 = new Saml1TokenProvider();
        TokenProvider tp2 = new Saml2TokenProvider();
        id.setTokenProviders(Arrays.asList(tp1, tp2));

        id.issue(requestMock);

        verify(requestMock);
    }

    @Test
    public void TestIssueDelegateWrongUsername() {
        IssueDelegate id = new IssueDelegate();
        CertificateVerifierConfig certificateVerifierConfig = new CertificateVerifierConfig();
        certificateVerifierConfig.setTrustCertAliases(Arrays.asList("myclientkey"));
        certificateVerifierConfig.setKeySignAlias(keySignAlias);
        certificateVerifierConfig.setKeySignPwd(keySignPwd);
        certificateVerifierConfig.setStorePath(storePath);
        certificateVerifierConfig.setStorePwd(storePwd);
        id.setCertificateVerifierConfig(certificateVerifierConfig);

        EasyMock.expect(passwordCallbackMock.resetUsername()).andReturn(
                "joexxx");
        EasyMock.expect(passwordCallbackMock.resetPassword()).andReturn(
                "joespassword");
        EasyMock.replay(passwordCallbackMock);

        id.setPasswordCallback(passwordCallbackMock);

        JAXBElement<String> tokenType = new JAXBElement<String>(new QName(
                "http://docs.oasis-open.org/ws-sx/ws-trust/200512",
                "TokenType"), String.class,
                "urn:oasis:names:tc:SAML:1.0:assertion");

        EasyMock.expect(requestMock.getAny()).andStubReturn(
                Arrays.asList((Object) tokenType));

        EasyMock.replay(requestMock);

        TokenProvider tp1 = new Saml1TokenProvider();
        TokenProvider tp2 = new Saml2TokenProvider();
        id.setTokenProviders(Arrays.asList(tp1, tp2));

        try {
            id.issue(requestMock);
            fail("STSException should be thrown");
        } catch (STSException e) {
        	// expected
        } finally {
            verify(requestMock);
        }
    }

    @Test
    public void testIssueDelegateWrongPassword() {
        IssueDelegate id = new IssueDelegate();
        CertificateVerifierConfig certificateVerifierConfig = new CertificateVerifierConfig();
        certificateVerifierConfig.setTrustCertAliases(Arrays.asList("myclientkey"));
        certificateVerifierConfig.setKeySignAlias(keySignAlias);
        certificateVerifierConfig.setKeySignPwd(keySignPwd);
        certificateVerifierConfig.setStorePath(storePath);
        certificateVerifierConfig.setStorePwd(storePwd);
        id.setCertificateVerifierConfig(certificateVerifierConfig);

        EasyMock.expect(passwordCallbackMock.resetUsername()).andReturn(
                "joe");
        EasyMock.expect(passwordCallbackMock.resetPassword()).andReturn(
                "joespasswordxxx");
        EasyMock.replay(passwordCallbackMock);

        id.setPasswordCallback(passwordCallbackMock);

        JAXBElement<String> tokenType = new JAXBElement<String>(new QName(
                "http://docs.oasis-open.org/ws-sx/ws-trust/200512",
                "TokenType"), String.class,
                "urn:oasis:names:tc:SAML:1.0:assertion");

        EasyMock.expect(requestMock.getAny()).andStubReturn(
                Arrays.asList((Object) tokenType));

        EasyMock.replay(requestMock);

        TokenProvider tp1 = new Saml1TokenProvider();
        TokenProvider tp2 = new Saml2TokenProvider();
        id.setTokenProviders(Arrays.asList(tp1, tp2));

        try {
            id.issue(requestMock);

            fail("STSException should be thrown");
        } catch (STSException e) {
        	// expected 
        } finally {
            verify(requestMock);
        }
    }

    @Test
    public void testIssueDelegateWrongSignKey() {
        IssueDelegate id = new IssueDelegate();
        CertificateVerifierConfig certificateVerifierConfig = new CertificateVerifierConfig();
        certificateVerifierConfig.setTrustCertAliases(Arrays.asList("myclientkey"));
        certificateVerifierConfig.setKeySignAlias(keySignAlias);
        certificateVerifierConfig.setKeySignPwd("xxx");
        certificateVerifierConfig.setStorePath(storePath);
        certificateVerifierConfig.setStorePwd(storePwd);
        id.setCertificateVerifierConfig(certificateVerifierConfig);

        EasyMock.expect(passwordCallbackMock.resetUsername()).andReturn(
                "joe");
        EasyMock.expect(passwordCallbackMock.resetPassword()).andReturn(
                "joespassword");
        EasyMock.replay(passwordCallbackMock);

        id.setPasswordCallback(passwordCallbackMock);

        JAXBElement<String> tokenType = new JAXBElement<String>(new QName(
                "http://docs.oasis-open.org/ws-sx/ws-trust/200512",
                "TokenType"), String.class,
                "urn:oasis:names:tc:SAML:1.0:assertion");

        EasyMock.expect(requestMock.getAny()).andStubReturn(
                Arrays.asList((Object) tokenType));

        EasyMock.replay(requestMock);

        TokenProvider tp1 = new Saml1TokenProvider();
        TokenProvider tp2 = new Saml2TokenProvider();
        id.setTokenProviders(Arrays.asList(tp1, tp2));

        try {
            id.issue(requestMock);
            fail("STSException should be thrown");
        } catch (STSException e) {
        	// expected 
        } finally {
            verify(requestMock);
        }
    }

    @Test
    public void testIssueDelegateWrongSignAlias() {
        IssueDelegate id = new IssueDelegate();
        CertificateVerifierConfig certificateVerifierConfig = new CertificateVerifierConfig();
        certificateVerifierConfig.setTrustCertAliases(Arrays.asList("myclientkey"));
        certificateVerifierConfig.setKeySignAlias("xxx");
        certificateVerifierConfig.setKeySignPwd(keySignPwd);
        certificateVerifierConfig.setStorePath(storePath);
        certificateVerifierConfig.setStorePwd(storePwd);
        id.setCertificateVerifierConfig(certificateVerifierConfig);

        EasyMock.expect(passwordCallbackMock.resetUsername()).andReturn(
                "joe");
        EasyMock.expect(passwordCallbackMock.resetPassword()).andReturn(
                "joespassword");
        EasyMock.replay(passwordCallbackMock);

        id.setPasswordCallback(passwordCallbackMock);

        JAXBElement<String> tokenType = new JAXBElement<String>(new QName(
                "http://docs.oasis-open.org/ws-sx/ws-trust/200512",
                "TokenType"), String.class,
                "urn:oasis:names:tc:SAML:1.0:assertion");

        EasyMock.expect(requestMock.getAny()).andStubReturn(
                Arrays.asList((Object) tokenType));

        EasyMock.replay(requestMock);

        TokenProvider tp1 = new Saml1TokenProvider();
        TokenProvider tp2 = new Saml2TokenProvider();
        id.setTokenProviders(Arrays.asList(tp1, tp2));

        try {
            id.issue(requestMock);

            fail("STSException should be thrown");
        } catch (STSException e) {
        	// expected 
        } finally {
            verify(requestMock);
        }
    }

    @Test
    public void testIssueDelegateUsernameNull() {
        IssueDelegate id = new IssueDelegate();
        assertNotNull(id);

        EasyMock.expect(requestMock.getAny()).andStubReturn(Arrays.asList());
        EasyMock.replay(requestMock);

        EasyMock.expect(passwordCallbackMock.resetUsername()).andReturn(null);
        EasyMock.expect(passwordCallbackMock.resetPassword()).andReturn(
                "password");
        EasyMock.replay(passwordCallbackMock);

        id.setPasswordCallback(passwordCallbackMock);

        TokenProvider tp1 = new Saml1TokenProvider();
        TokenProvider tp2 = new Saml2TokenProvider();
        id.setTokenProviders(Arrays.asList(tp1, tp2));

        try {
            id.issue(requestMock);
            fail("STSException should be thrown");
        } catch (STSException e) {
        }
        verify(requestMock);
    }

    @Test
    public void testIssueDelegateWithCert() throws CertificateException {
        IssueDelegate id = new IssueDelegate();
        assertNotNull(id);
        CertificateVerifierConfig certificateVerifierConfig = new CertificateVerifierConfig();
        certificateVerifierConfig.setTrustCertAliases(Arrays.asList("myclientkey"));
        certificateVerifierConfig.setKeySignAlias(keySignAlias);
        certificateVerifierConfig.setKeySignPwd(keySignPwd);
        certificateVerifierConfig.setStorePath(storePath);
        certificateVerifierConfig.setStorePwd(storePwd);
        certificateVerifierConfig.setVerifySelfSignedCert(true);
        id.setCertificateVerifierConfig(certificateVerifierConfig);
        JAXBElement<byte[]> jX509Certificate = new JAXBElement<byte[]>(
                QName.valueOf("X509Certificate"), byte[].class,
                Base64.decodeBase64(CERT_DATA.getBytes()));

        X509DataType x509DataType = new X509DataType();
        x509DataType.getX509IssuerSerialOrX509SKIOrX509SubjectName().add(
                jX509Certificate);
        JAXBElement<X509DataType> jX509DataType = new JAXBElement<X509DataType>(
                QName.valueOf("X509Data"), X509DataType.class, x509DataType);

        KeyInfoType keyInfoType = new KeyInfoType();
        keyInfoType.getContent().add(jX509DataType);
        JAXBElement<KeyInfoType> jKeyInfoType = new JAXBElement<KeyInfoType>(
                QName.valueOf("KeyInfo"), KeyInfoType.class, keyInfoType);

        UseKeyType useKeyType = new UseKeyType();
        useKeyType.setAny(jKeyInfoType);
        JAXBElement<UseKeyType> jUseKeyType = new JAXBElement<UseKeyType>(
                QName.valueOf("UseKey"), UseKeyType.class, useKeyType);

        JAXBElement<String> tokenType = new JAXBElement<String>(
                new QName("http://docs.oasis-open.org/ws-sx/ws-trust/200512",
                        "TokenType"), String.class,
                "urn:oasis:names:tc:SAML:1.0:assertion");

        EasyMock.expect(requestMock.getAny()).andStubReturn(
                Arrays.asList((Object) jUseKeyType, (Object) tokenType));
        EasyMock.replay(requestMock);

        EasyMock.expect(passwordCallbackMock.resetUsername()).andReturn(null);
        EasyMock.replay(passwordCallbackMock);

        id.setPasswordCallback(passwordCallbackMock);

        TokenProvider tp1 = new Saml1TokenProvider();
        TokenProvider tp2 = new Saml2TokenProvider();
        id.setTokenProviders(Arrays.asList(tp1, tp2));

        id.issue(requestMock);

        verify(requestMock);
    }

    @Test
    public void testIssueDelegateWithCertWithWrongStorePass() throws CertificateException {
        IssueDelegate id = new IssueDelegate();

        CertificateVerifierConfig certificateVerifierConfig = new CertificateVerifierConfig();
        certificateVerifierConfig.setTrustCertAliases(Arrays.asList("myclientkey"));
        certificateVerifierConfig.setKeySignAlias(keySignAlias);
        certificateVerifierConfig.setKeySignPwd(keySignPwd);
        certificateVerifierConfig.setStorePath(storePath);
        certificateVerifierConfig.setStorePwd("xxx");
        id.setCertificateVerifierConfig(certificateVerifierConfig);
        JAXBElement<byte[]> jX509Certificate = new JAXBElement<byte[]>(
                QName.valueOf("X509Certificate"), byte[].class,
                Base64.decodeBase64(CERT_DATA.getBytes()));

        X509DataType x509DataType = new X509DataType();
        x509DataType.getX509IssuerSerialOrX509SKIOrX509SubjectName().add(
                jX509Certificate);
        JAXBElement<X509DataType> jX509DataType = new JAXBElement<X509DataType>(
                QName.valueOf("X509Data"), X509DataType.class, x509DataType);

        KeyInfoType keyInfoType = new KeyInfoType();
        keyInfoType.getContent().add(jX509DataType);
        JAXBElement<KeyInfoType> jKeyInfoType = new JAXBElement<KeyInfoType>(
                QName.valueOf("KeyInfo"), KeyInfoType.class, keyInfoType);

        UseKeyType useKeyType = new UseKeyType();
        useKeyType.setAny(jKeyInfoType);
        JAXBElement<UseKeyType> jUseKeyType = new JAXBElement<UseKeyType>(
                QName.valueOf("UseKey"), UseKeyType.class, useKeyType);

        JAXBElement<String> tokenType = new JAXBElement<String>(new QName(
                "http://docs.oasis-open.org/ws-sx/ws-trust/200512",
                "TokenType"), String.class,
                "urn:oasis:names:tc:SAML:1.0:assertion");

        EasyMock.expect(requestMock.getAny()).andStubReturn(
                Arrays.asList((Object) jUseKeyType, (Object) tokenType));
        EasyMock.replay(requestMock);

        EasyMock.expect(passwordCallbackMock.resetUsername()).andReturn(
                null);
        EasyMock.replay(passwordCallbackMock);

        id.setPasswordCallback(passwordCallbackMock);

        TokenProvider tp1 = new Saml1TokenProvider();
        TokenProvider tp2 = new Saml2TokenProvider();
        id.setTokenProviders(Arrays.asList(tp1, tp2));

        try {
            id.issue(requestMock);
            fail("STSException should be thrown");
        } catch (STSException e) {
        	// expected
        } finally {
            verify(requestMock);
        }
    }

    @Test
    public void testIssueDelegateWithCertWithoutTokenProvidersAndTokenType() throws CertificateException {
        IssueDelegate id = new IssueDelegate();

        CertificateVerifierConfig certificateVerifierConfig = new CertificateVerifierConfig();
        certificateVerifierConfig.setTrustCertAliases(Arrays.asList("myclientkey"));
        certificateVerifierConfig.setKeySignAlias(keySignAlias);
        certificateVerifierConfig.setKeySignPwd(keySignPwd);
        certificateVerifierConfig.setStorePath(storePath);
        certificateVerifierConfig.setStorePwd(storePwd);
        id.setCertificateVerifierConfig(certificateVerifierConfig);
        JAXBElement<byte[]> jX509Certificate = new JAXBElement<byte[]>(
                QName.valueOf("X509Certificate"), byte[].class,
                Base64.decodeBase64(CERT_DATA.getBytes()));

        X509DataType x509DataType = new X509DataType();
        x509DataType.getX509IssuerSerialOrX509SKIOrX509SubjectName().add(
                jX509Certificate);
        JAXBElement<X509DataType> jX509DataType = new JAXBElement<X509DataType>(
                QName.valueOf("X509Data"), X509DataType.class, x509DataType);

        KeyInfoType keyInfoType = new KeyInfoType();
        keyInfoType.getContent().add(jX509DataType);
        JAXBElement<KeyInfoType> jKeyInfoType = new JAXBElement<KeyInfoType>(
                QName.valueOf("KeyInfo"), KeyInfoType.class, keyInfoType);

        UseKeyType useKeyType = new UseKeyType();
        useKeyType.setAny(jKeyInfoType);
        JAXBElement<UseKeyType> jUseKeyType = new JAXBElement<UseKeyType>(
                QName.valueOf("UseKey"), UseKeyType.class, useKeyType);

        EasyMock.expect(requestMock.getAny()).andStubReturn(
                Arrays.asList((Object) jUseKeyType));
        EasyMock.replay(requestMock);

        EasyMock.expect(passwordCallbackMock.resetUsername()).andReturn(
                null);
        EasyMock.replay(passwordCallbackMock);

        id.setPasswordCallback(passwordCallbackMock);

        List<TokenProvider> tps = Collections.emptyList();
        id.setTokenProviders(tps);

        try {
            id.issue(requestMock);
            fail("STSException should be thrown");
        } catch (STSException e) {
        	// expected
        } finally {
            verify(requestMock);
        }
    }

    @Test
    public void testIssueDelegateWithoutCertAndUserToken() throws CertificateException {
        IssueDelegate id = new IssueDelegate();

        JAXBElement<String> tokenType = new JAXBElement<String>(new QName(
                "http://docs.oasis-open.org/ws-sx/ws-trust/200512",
                "TokenType"), String.class,
                "urn:oasis:names:tc:SAML:1.0:assertion");

        EasyMock.expect(requestMock.getAny()).andStubReturn(
                Arrays.asList((Object) tokenType));
        EasyMock.replay(requestMock);

        EasyMock.expect(passwordCallbackMock.resetUsername()).andReturn(
                null);
        EasyMock.expect(passwordCallbackMock.resetPassword()).andReturn(
                null);
        EasyMock.replay(passwordCallbackMock);

        id.setPasswordCallback(passwordCallbackMock);

        TokenProvider tp1 = new Saml1TokenProvider();
        TokenProvider tp2 = new Saml2TokenProvider();
        id.setTokenProviders(Arrays.asList(tp1, tp2));

        try {
            id.issue(requestMock);

            fail("STSException should be thrown");
        } catch (STSException e) {
        	// expected
        } finally {
            verify(requestMock);
        }
    }

    @Test
    public void testIssueDelegateWithInvalidCert() throws CertificateException {
        IssueDelegate id = new IssueDelegate();
        assertNotNull(id);

        // CertificateFactory certificateFactory =
        // CertificateFactory.getInstance("X.509");
        // X509Certificate x509Certificate = null;
        // try {
        // x509Certificate =
        // (X509Certificate)certificateFactory.generateCertificate(new
        // ByteArrayInputStream(Base64.decodeBase64(CERT_DATA.getBytes())));
        // } catch (CertificateException e) {
        // e.printStackTrace();
        // }
        // JAXBElement<X509Certificate> jX509Certificate = new
        // JAXBElement<X509Certificate>(QName.valueOf("X509Certificate"),
        // X509Certificate.class, x509Certificate);

        JAXBElement<byte[]> jX509Certificate = new JAXBElement<byte[]>(
                QName.valueOf("X509Certificate"), byte[].class,
                CERT_DATA.getBytes());

        X509DataType x509DataType = new X509DataType();
        x509DataType.getX509IssuerSerialOrX509SKIOrX509SubjectName().add(
                jX509Certificate);
        JAXBElement<X509DataType> jX509DataType = new JAXBElement<X509DataType>(
                QName.valueOf("X509Data"), X509DataType.class, x509DataType);

        KeyInfoType keyInfoType = new KeyInfoType();
        keyInfoType.getContent().add(jX509DataType);
        JAXBElement<KeyInfoType> jKeyInfoType = new JAXBElement<KeyInfoType>(
                QName.valueOf("KeyInfo"), KeyInfoType.class, keyInfoType);

        UseKeyType useKeyType = new UseKeyType();
        useKeyType.setAny(jKeyInfoType);
        JAXBElement<UseKeyType> jUseKeyType = new JAXBElement<UseKeyType>(
                QName.valueOf("UseKey"), UseKeyType.class, useKeyType);

        EasyMock.expect(requestMock.getAny()).andStubReturn(
                Arrays.asList((Object) jUseKeyType));
        EasyMock.replay(requestMock);

        EasyMock.expect(passwordCallbackMock.resetUsername()).andReturn(null);
        EasyMock.replay(passwordCallbackMock);

        id.setPasswordCallback(passwordCallbackMock);

        TokenProvider tp1 = new Saml1TokenProvider();
        TokenProvider tp2 = new Saml2TokenProvider();
        id.setTokenProviders(Arrays.asList(tp1, tp2));

        try {
            id.issue(requestMock);
            fail("STSException should be thrown");
        } catch (STSException e) {

        }

        verify(requestMock);
    }

    @Test
    public void testIssueDelegateWithInvalidCert2() throws CertificateException {
        IssueDelegate id = new IssueDelegate();
        assertNotNull(id);

        CertificateFactory certificateFactory = CertificateFactory
                .getInstance("X.509");
        X509Certificate x509Certificate = (X509Certificate) certificateFactory
                    .generateCertificate(new ByteArrayInputStream(Base64
                            .decodeBase64(CERT_DATA.getBytes())));
        JAXBElement<X509Certificate> jX509Certificate = new JAXBElement<X509Certificate>(
                QName.valueOf("X509Certificate"), X509Certificate.class,
                x509Certificate);

        // JAXBElement<byte[]> jX509Certificate = new
        // JAXBElement<byte[]>(QName.valueOf("X509Certificate"), byte[].class,
        // CERT_DATA.getBytes());

        X509DataType x509DataType = new X509DataType();
        x509DataType.getX509IssuerSerialOrX509SKIOrX509SubjectName().add(
                jX509Certificate);
        JAXBElement<X509DataType> jX509DataType = new JAXBElement<X509DataType>(
                QName.valueOf("X509Data"), X509DataType.class, x509DataType);

        KeyInfoType keyInfoType = new KeyInfoType();
        keyInfoType.getContent().add(jX509DataType);
        JAXBElement<KeyInfoType> jKeyInfoType = new JAXBElement<KeyInfoType>(
                QName.valueOf("KeyInfo"), KeyInfoType.class, keyInfoType);

        UseKeyType useKeyType = new UseKeyType();
        useKeyType.setAny(jKeyInfoType);
        JAXBElement<UseKeyType> jUseKeyType = new JAXBElement<UseKeyType>(
                QName.valueOf("UseKey"), UseKeyType.class, useKeyType);

        EasyMock.expect(requestMock.getAny()).andStubReturn(
                Arrays.asList((Object) jUseKeyType));
        EasyMock.replay(requestMock);

        EasyMock.expect(passwordCallbackMock.resetUsername()).andReturn(null);
        EasyMock.expect(passwordCallbackMock.resetPassword()).andReturn(
                "joespassword");
        EasyMock.replay(passwordCallbackMock);

        TokenProvider tp1 = new Saml1TokenProvider();
        TokenProvider tp2 = new Saml2TokenProvider();
        id.setTokenProviders(Arrays.asList(tp1, tp2));

        id.setPasswordCallback(passwordCallbackMock);

        try {
            id.issue(requestMock);
            fail("CertificateException should be thrown");
        } catch (Exception e) {
        }

        verify(requestMock);
    }
}
