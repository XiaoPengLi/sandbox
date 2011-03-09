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

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.cxf.Bus;
import org.apache.cxf.BusFactory;
import org.apache.cxf.bus.spring.SpringBusFactory;
import org.apache.cxf.common.security.TokenType;
import org.apache.cxf.ws.security.sts.provider.ProviderPasswordCallback;
import org.apache.cxf.ws.security.sts.provider.STSException;
import org.apache.cxf.ws.security.sts.provider.cert.CertificateVerifierConfig;
import org.apache.cxf.ws.security.sts.provider.operation.IssueDelegate;
import org.apache.cxf.ws.security.sts.provider.token.Saml1TokenProvider;
import org.apache.cxf.ws.security.sts.provider.token.Saml2TokenProvider;
import org.apache.cxf.ws.security.sts.provider.token.TokenProvider;
import org.apache.cxf.ws.security.trust.STSClient;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.xerces.dom.CoreDocumentImpl;
import org.apache.xerces.dom.DocumentTypeImpl;
import org.apache.xerces.dom.ElementNSImpl;
import org.apache.xml.security.keys.KeyInfo;
import org.easymock.EasyMock;

import static org.easymock.EasyMock.*;
import static org.junit.Assert.*;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CountDownLatch;

import javax.security.auth.callback.PasswordCallback;
import javax.xml.bind.JAXBElement;
import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import junit.framework.TestCase;

import org.junit.Ignore;
import org.junit.Test;
import org.oasis_open.docs.ws_sx.ws_trust._200512.RequestSecurityTokenType;
import org.oasis_open.docs.ws_sx.ws_trust._200512.UseKeyType;
import org.w3._2000._09.xmldsig.KeyInfoType;
import org.w3._2000._09.xmldsig.X509DataType;
import org.w3c.dom.Document;
import org.w3c.dom.DocumentType;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

public class IssueDelegateTest {

	private static final Log LOG = LogFactory
    .getLog(IssueDelegateTest.class.getName());
	
    RequestSecurityTokenType requestMock = createMock(RequestSecurityTokenType.class);

    ProviderPasswordCallback passwordCallbackMock = createMock(ProviderPasswordCallback.class);

    private static final String CERT_DATA = "MIICsjCCAhsCBRI0VniSMA0GCSqGSIb3DQEBBQUAMIGjMQswCQYDVQQGEwJVQTEQMA4GA1UECAwHTHVnYW5zazEQMA4GA1UEBwwHTHVnYW5zazESMBAGA1UECgwJSW5mb3B1bHNlMRMwEQYDVQQLDApUYWxlbmRUZWFtMRkwFwYDVQQDDBBQYXZlbFZhc2lsY2hlbmtvMSwwKgYJKoZIhvcNAQkBFh1QYXZlbC5TLlZhc2lsY2hlbmtvQGdtYWlsLmNvbTAeFw0xMTAyMjMxMjA4NDVaFw0yMTAyMjAxMjA4NDVaMIGaMRowGAYDVQQDExFUYWxlbmRDZXJ0aWZpY2F0ZTEPMA0GA1UECxMGVGFsZW5kMQ8wDQYDVQQKEwZUYWxlbmQxEzARBgNVBAcTCkN1c3RvbUNpdHkxFDASBgNVBAgTC0N1c3RvbVN0YXRlMQswCQYDVQQGEwJERTEiMCAGCSqGSIb3DQEJARYTZXhhbXBsZUBleGFtcGxlLmNvbTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAqD49IHig6rd9p5NTF0YzI+XMlUZThG5Us1DdcOUpPTp2i5m3wukWlRXFd4BZcp+PClbvyuNr/8kF0rDcxejvqMZrloQ1h4ncJvSW9udULh+M53vynuhSTDQWVWIOPxbREInNkx1kTm/uqhWf8JtewW6maH3Pz4Ll6Hcj8KWsnIUCAwEAATANBgkqhkiG9w0BAQUFAAOBgQB+EALhJN+LKDtTLSpgA3osgXmyV7UfKujTH/RQwGkMyM8KBzhaXvLgfLrcNrVFNzvv/BcWs2vxc15r0RmkAaSkpZig0scWR98mUW466xoh3cbbt4Dj7hmiinvyBingVdn3Z2IjRzfW2aACsMgk8e5kyhHdRY8OMucKxrDaQn0amg==";
    // private static final String CERT_DATA =
    // "MIICbDCCAdWgAwIBAgIBezANBgkqhkiG9w0BAQUFADAhMR8wHQYDVQQDDBZSdURpLVJvb3RDQS0wMUBydWRpLVBDMB4XDTEwMTEyMjE2MzkzNVoXDTExMDMwMjE2MzkzNVowJzElMCMGA1UEAwwcU2VjdXJpdHlUb2tlblNlcnZpY2VQcm92aWRlcjCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAl4sZX2T61J+5lm1fsSMDn5KFkiYbOGYaSXN8CC57aEZjVx1m7wKuQNNaskC5DA+x1mLcFqWN5OqO6+gphbHnZ3/LStRLQfckmv/2Kigg2MVikNduIpT94nEmKl4FP5aI+yDAGofXLUjnpiBGHUoMj8qVYmM3n4ZgyZXuX7/x3ukCAwEAAaOBrTCBqjAOBgNVHQ8BAf8EBAMCBDAwRAYDVR0jBD0wO4AU+pT7F58ucXMA186r19VELZeiIyyhIKQeMBwxGjAYBgNVBAMMEVJ1RGlfQ0EwMUBpYWJnLmRlggF7MFIGA1UdHwEB/wRIMEYwRKBCoECCPmh0dHA6Ly9zZXJ2aWNlcy5uYXRvLmludC9ERVUvQncvSVQvUnVEaS9JQVMvMDAxL1NvYVBraV9TZXJ2aWNlMA0GCSqGSIb3DQEBBQUAA4GBAFL1KM415BxQzn6zGHtI2RhkB2NcNQNkrybKfp2VrP66zcL9aIB5HRRN0RFFikLoSiJX7jHESS+tepGwg56kOgPk2f80WbHeMapeYK8MDT0F+yLdufEhAYbKNT7NALHVRA4HN+CEi4PHa9qVOOoJ2wmzhxrD4fVfUv/jWYY/+X4i";
    // private static final String CERT_DATA =
    // "MIICcTCCAdoCBRI0VniUMA0GCSqGSIb3DQEBBQUAMH8xCzAJBgNVBAYTAkRFMRAwDgYDVQQIDAcxMTExMTExMRAwDgYDVQQHDAcxMTExMTExMRAwDgYDVQQKDAcxMTExMTExMRAwDgYDVQQLDAcxMTExMTExMRAwDgYDVQQDDAcxMTExMTExMRYwFAYJKoZIhvcNAQkBFgcxMTExMTExMB4XDTExMDIwMjE1Mjk0NloXDTExMDIwMzE1Mjk0NlowfzEQMA4GA1UEAxMHMjIyMjIyMjEQMA4GA1UECxMHMjIyMjIyMjEQMA4GA1UEChMHMjIyMjIyMjEQMA4GA1UEBxMHMjIyMjIyMjEQMA4GA1UECBMHMjIyMjIyMjELMAkGA1UEBhMCREUxFjAUBgkqhkiG9w0BCQEWBzIyMjIyMjIwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAKaHED65XZ38tEextdY3qkHFR1SGcbnyP/GFbwJpFp2KGLTuO4+0jLfo4uYpgzucHt3kKtHZEzYPM/8GX3dWra16JcoMyP1UZdDnUNsURjZfDG90VwF2ugku/RtyM++virK7mkKnvWrMrmuq68vhcUGoUpVG9gt6ZmmWHZJ5dyYHAgMBAAEwDQYJKoZIhvcNAQEFBQADgYEAd/bbgvqUPQNkrnNGwHSPksH6jDSDWqLVmUwlPjLfFxaY7l8SYhMr/OznikO7ANezS8et/HKPrl0LT6QlH50AiTaST5u7w5qKpsrHEPx94GYx9CxAXRBbCiE5YV4yf/yFTbVTh2vKSfCMARtNcfLEROTpG3/yKCijnC8uwj4QjHY=";

    private static final String storePath = "/sts.jks";
    private static final String storePwd = "atleast8";
    private static final String keyCertAlias = "cacert";
    private static final String keySignAlias = "securitytokenserviceprovider";
    private static final String keySignPwd = "empty";

    @Test
    public void TestIssueDelegateNullParameter() {
        try {
            IssueDelegate id = new IssueDelegate();
            assertNotNull(id);
            ProviderPasswordCallback passwordCallback = new ProviderPasswordCallback();
            id.setPasswordCallback(passwordCallback);

            id.issue(null);
            fail("NullPointerException should be thrown");
        } catch (NullPointerException e) {

        }
    }

    @Test
    public void TestIssueDelegate() {
        IssueDelegate id = new IssueDelegate();
        CertificateVerifierConfig certificateVerifierConfig = new CertificateVerifierConfig();
        certificateVerifierConfig.setKeyCertAlias(keyCertAlias);
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
        try {
            IssueDelegate id = new IssueDelegate();
            CertificateVerifierConfig certificateVerifierConfig = new CertificateVerifierConfig();
            certificateVerifierConfig.setKeyCertAlias(keyCertAlias);
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

            id.issue(requestMock);

            verify(requestMock);
            fail("STSException should be thrown");
        } catch (STSException e) {

        }
    }

    @Test
    public void TestIssueDelegateWrongPassword() {
        try {
            IssueDelegate id = new IssueDelegate();
            CertificateVerifierConfig certificateVerifierConfig = new CertificateVerifierConfig();
            certificateVerifierConfig.setKeyCertAlias(keyCertAlias);
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

            id.issue(requestMock);

            verify(requestMock);
            fail("STSException should be thrown");
        } catch (STSException e) {

        }
    }

    @Test
    public void TestIssueDelegateWrongSignKey() {
        try {
            IssueDelegate id = new IssueDelegate();
            CertificateVerifierConfig certificateVerifierConfig = new CertificateVerifierConfig();
            certificateVerifierConfig.setKeyCertAlias(keyCertAlias);
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

            id.issue(requestMock);

            verify(requestMock);
            fail("STSException should be thrown");
        } catch (Exception e) {

        }
    }

    @Test
    public void TestIssueDelegateWrongSignAlias() {
        try {
            IssueDelegate id = new IssueDelegate();
            CertificateVerifierConfig certificateVerifierConfig = new CertificateVerifierConfig();
            certificateVerifierConfig.setKeyCertAlias(keyCertAlias);
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

            id.issue(requestMock);

            verify(requestMock);
            fail("STSException should be thrown");
        } catch (Exception e) {

        }
    }

    @Test
    public void TestIssueDelegateUsernameNull() {
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
    public void TestIssueDelegateWithCert() throws CertificateException {
        IssueDelegate id = new IssueDelegate();
        assertNotNull(id);
        CertificateVerifierConfig certificateVerifierConfig = new CertificateVerifierConfig();
        certificateVerifierConfig.setKeyCertAlias(keyCertAlias);
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
    public void TestIssueDelegateWithCertWithWrongStorePass()
            throws CertificateException {
        try {
            IssueDelegate id = new IssueDelegate();
            assertNotNull(id);
            CertificateVerifierConfig certificateVerifierConfig = new CertificateVerifierConfig();
            certificateVerifierConfig.setKeyCertAlias(keyCertAlias);
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

            id.issue(requestMock);

            verify(requestMock);
            fail("Exception should be thrown");
        } catch (Exception e) {

        }
    }

    @Test
    public void TestIssueDelegateWithCertWithoutTokenProvidersAndTokenType()
            throws CertificateException {
        try {
            IssueDelegate id = new IssueDelegate();
            assertNotNull(id);
            CertificateVerifierConfig certificateVerifierConfig = new CertificateVerifierConfig();
            certificateVerifierConfig.setKeyCertAlias(keyCertAlias);
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

            // TokenProvider tp1 = new Saml1TokenProvider();
            // TokenProvider tp2 = new Saml2TokenProvider();
            // id.setTokenProviders(Arrays.asList(tp1, tp2));
            id.setTokenProviders(new ArrayList<TokenProvider>());

            id.issue(requestMock);

            verify(requestMock);
            fail("STSException should be thrown");
        } catch (STSException e) {

        }
    }

    @Test
    public void TestIssueDelegateWithoutCertAndUserToken()
            throws CertificateException {
        try {
            IssueDelegate id = new IssueDelegate();
            assertNotNull(id);

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

            id.issue(requestMock);

            verify(requestMock);
            fail("STSException should be thrown");
        } catch (STSException e) {

        }
    }

    @Test
    public void TestIssueDelegateWithInvalidCert() throws CertificateException {
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
            fail("CertificateException should be thrown");
        } catch (Exception e) {

        }

        verify(requestMock);
    }

    @Test
    public void TestIssueDelegateWithInvalidCert2() throws CertificateException {
        IssueDelegate id = new IssueDelegate();
        assertNotNull(id);

        CertificateFactory certificateFactory = CertificateFactory
                .getInstance("X.509");
        X509Certificate x509Certificate = null;
        try {
            x509Certificate = (X509Certificate) certificateFactory
                    .generateCertificate(new ByteArrayInputStream(Base64
                            .decodeBase64(CERT_DATA.getBytes())));
        } catch (CertificateException e) {
            LOG.error(e);
        }
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
