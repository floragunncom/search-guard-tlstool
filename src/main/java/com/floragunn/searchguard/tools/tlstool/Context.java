package com.floragunn.searchguard.tools.tlstool;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.Provider;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Context {
	private final Provider securityProvider = new BouncyCastleProvider();
	private final FileOutput fileOutput = new FileOutput();
	
	private X509CertificateHolder rootCaCertificate;
	private X509CertificateHolder signingCertificate;
	private PrivateKey signingPrivateKey;
	private long idCounter = System.currentTimeMillis();
	private Config config;
	private char [] password;
	
	public Provider getSecurityProvider() {
		return securityProvider;
	}


	public FileOutput getFileOutput() {
		return fileOutput;
	}


	public X509CertificateHolder getRootCaCertificate() {
		return rootCaCertificate;
	}


	public void setRootCaCertificate(X509CertificateHolder rootCaCertificate) {
		this.rootCaCertificate = rootCaCertificate;
	}


	public X509CertificateHolder getSigningCertificate() {
		return signingCertificate;
	}


	public void setSigningCertificate(X509CertificateHolder signingCertificate) {
		this.signingCertificate = signingCertificate;
	}


	public PrivateKey getSigningPrivateKey() {
		return signingPrivateKey;
	}


	public void setSigningPrivateKey(PrivateKey signingPrivateKey) {
		this.signingPrivateKey = signingPrivateKey;
	}


	public BigInteger nextId() {
		return BigInteger.valueOf(idCounter++);
	}


	public Config getConfig() {
		return config;
	}


	public void setConfig(Config config) {
		this.config = config;
	}


	public char[] getPassword() {
		return password;
	}


	public void setPassword(char[] password) {
		this.password = password;
	}
}
