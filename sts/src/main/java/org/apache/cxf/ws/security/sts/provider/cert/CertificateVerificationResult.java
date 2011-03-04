package org.apache.cxf.ws.security.sts.provider.cert;

import java.security.cert.PKIXCertPathBuilderResult;

public class CertificateVerificationResult {
	private boolean valid;
	private PKIXCertPathBuilderResult result;
	private Throwable exception;

	/**
	 * Constructs a certificate verification result for valid
	 * certificate by given certification path.
	 */
	public CertificateVerificationResult(
			PKIXCertPathBuilderResult result) {
		this.valid = true;
		this.result = result;
	}

	public CertificateVerificationResult(Throwable exception) {
		this.valid = false;
		this.exception = exception;
	}

	public boolean isValid() {
		return valid;
	}

	public PKIXCertPathBuilderResult getResult() {
		return result;
	}

	public Throwable getException() {
		return exception;
	}
}
