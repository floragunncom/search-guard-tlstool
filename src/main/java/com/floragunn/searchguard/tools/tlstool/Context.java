/*
 * Copyright 2017-2018 floragunn GmbH
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 */

package com.floragunn.searchguard.tools.tlstool;

import java.io.File;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.SecureRandom;

import org.bouncycastle.cert.X509CertificateHolder;

public class Context {
	private Provider securityProvider;
	private final FileOutput fileOutput = new FileOutput(this);

	private File targetDirectory;
	private X509CertificateHolder rootCaCertificate;
	private X509CertificateHolder signingCertificate;
	private File rootCaFile;
	private PrivateKey signingPrivateKey;
	private long idCounter = System.currentTimeMillis();
	private Config config;
	private final SecureRandom secureRandom = new SecureRandom();
	private boolean overwrite;

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

	public void setSecurityProvider(Provider securityProvider) {
		this.securityProvider = securityProvider;
	}

	public SecureRandom getSecureRandom() {
		return secureRandom;
	}

	public File getRootCaFile() {
		return rootCaFile;
	}

	public void setRootCaFile(File rootCaFile) {
		this.rootCaFile = rootCaFile;
	}

	public File getTargetDirectory() {
		return targetDirectory;
	}

	public void setTargetDirectory(File targetDirectory) {
		this.targetDirectory = targetDirectory;
	}

	public boolean isOverwrite() {
		return overwrite;
	}

	public void setOverwrite(boolean overwrite) {
		this.overwrite = overwrite;
	}

}
