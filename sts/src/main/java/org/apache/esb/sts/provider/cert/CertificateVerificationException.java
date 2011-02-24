package org.apache.esb.sts.provider.cert;

public class CertificateVerificationException extends Exception {
	private static final long serialVersionUID = 1L;

	public CertificateVerificationException(String message, Throwable cause) {
        super(message, cause);
    }

	public CertificateVerificationException(String message) {
        super(message);
    }
}