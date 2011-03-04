package org.apache.cxf.ws.security.sts.provider.cert;

public class CertificateVerifierConfig {
	private String storePath;
	private String storePwd;
	
	private String keyCertAlias;	
	
	private String keySignAlias;	
	private String keySignPwd;
	
	public String getStorePath() {
		return storePath;
	}
	public void setStorePath(String storePath) {
		this.storePath = storePath;
	}
	public String getStorePwd() {
		return storePwd;
	}
	public void setStorePwd(String storePwd) {
		this.storePwd = storePwd;
	}
	public String getKeyCertAlias() {
		return keyCertAlias;
	}
	public void setKeyCertAlias(String keyCertAlias) {
		this.keyCertAlias = keyCertAlias;
	}
	public String getKeySignAlias() {
		return keySignAlias;
	}
	public void setKeySignAlias(String keySignAlias) {
		this.keySignAlias = keySignAlias;
	}
	public String getKeySignPwd() {
		return keySignPwd;
	}
	public void setKeySignPwd(String keySignPwd) {
		this.keySignPwd = keySignPwd;
	}
}
