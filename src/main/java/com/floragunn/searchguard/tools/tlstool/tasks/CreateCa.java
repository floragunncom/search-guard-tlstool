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

package com.floragunn.searchguard.tools.tlstool.tasks;

import java.io.File;
import java.math.BigInteger;
import java.security.KeyPair;
import java.util.Date;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import com.floragunn.searchguard.tools.tlstool.Config;
import com.floragunn.searchguard.tools.tlstool.Context;
import com.floragunn.searchguard.tools.tlstool.ToolException;

public class CreateCa extends Task {

	private static final Logger log = LogManager.getLogger(CreateCa.class);

	private Config.Ca.Certificate rootCertificateConfig;
	private Config.Ca.Certificate signingCertificateConfig;

	public CreateCa(Context ctx, Config.Ca caConfig) throws ToolException {
		super(ctx);

		if (caConfig == null) {
			throw new ToolException("Configuration ca is required");
		}

		this.rootCertificateConfig = caConfig.getRoot();

		if (this.rootCertificateConfig == null) {
			throw new ToolException("Configuration ca.root is required");
		}

		this.signingCertificateConfig = caConfig.getIntermediate();

	}

	@Override
	public void run() throws ToolException {
		File rootKeyFile = getConfiguredFile(rootCertificateConfig.getFile(), "root-ca.key", "key");
		File rootCertFile = getConfiguredFile(rootCertificateConfig.getFile(), "root-ca.pem", "pem");
		File readmeFile = getConfiguredFile(rootCertificateConfig.getFile(), "root-ca.readme", "readme");

		if (rootKeyFile.exists()) {
			throw new ToolException(rootKeyFile + " does already exist.");
		}

		if (rootCertFile.exists()) {
			throw new ToolException(rootCertFile + " does already exist.");
		}

		KeyPair rootCaKeyPair = generateKeyPair(rootCertificateConfig.getKeysize());

		X509CertificateHolder rootCaCertificate = createRootCaCertificate(rootCaKeyPair);

		ctx.setRootCaCertificate(rootCaCertificate);
		ctx.setRootCaFile(rootCertFile);

		String rootPrivateKeyPassword = getPassword(rootCertificateConfig.getPkPassword());
		String signingPrivateKeyPassword = null;

		addOutputFile(rootCertFile, rootCaCertificate);
		addEncryptedOutputFile(rootKeyFile, rootPrivateKeyPassword, rootCaKeyPair.getPrivate());

		if (signingCertificateConfig != null) {
			File signingKeyFile = getConfiguredFile(signingCertificateConfig.getFile(), "signing-ca.key", "key");
			File signingCertFile = getConfiguredFile(signingCertificateConfig.getFile(), "signing-ca.pem", "pem");

			if (signingKeyFile.exists()) {
				throw new ToolException(signingKeyFile + " does already exist.");
			}

			if (signingCertFile.exists()) {
				throw new ToolException(signingCertFile + " does already exist.");
			}

			KeyPair intermediateKeyPair = generateKeyPair(signingCertificateConfig.getKeysize());
			X509CertificateHolder intermediateCertificate = createIntermediateCertificate(intermediateKeyPair,
					rootCaKeyPair, rootCaCertificate);

			ctx.setSigningCertificate(intermediateCertificate);
			ctx.setSigningPrivateKey(intermediateKeyPair.getPrivate());

			signingPrivateKeyPassword = getPassword(signingCertificateConfig.getPkPassword());

			addOutputFile(signingCertFile, intermediateCertificate);
			addEncryptedOutputFile(signingKeyFile, signingPrivateKeyPassword, intermediateKeyPair.getPrivate());
		} else {
			ctx.setSigningCertificate(rootCaCertificate);
			ctx.setSigningPrivateKey(rootCaKeyPair.getPrivate());
		}

		if (isPasswordAutoGenerationEnabled(rootCertificateConfig.getPkPassword()) || (signingCertificateConfig != null
				&& isPasswordAutoGenerationEnabled(signingCertificateConfig.getPkPassword()))) {
			addOutputFile(readmeFile, createReadme(rootPrivateKeyPassword, signingPrivateKeyPassword));
		}

		log.info(createSuccessLog());
	}

	private String createSuccessLog() {
		StringBuilder result = new StringBuilder();

		result.append("Root certificate ");

		if (signingCertificateConfig != null) {
			result.append("and signing certificate have ");
		} else {
			result.append("has ");
		}

		result.append("been sucessfully created.\n");

		if (isPasswordAutoGenerationEnabled(rootCertificateConfig.getPkPassword()) || (signingCertificateConfig != null
				&& isPasswordAutoGenerationEnabled(signingCertificateConfig.getPkPassword()))) {
			result.append(
					"The passwords of the private key files have been auto generated. You can find the passwords in root-ca.readme.\n");
		}

		return result.toString();
	}

	private X509CertificateHolder createRootCaCertificate(KeyPair keyPair) throws ToolException {
		try {
			X500Name rootCaDn = createDn(rootCertificateConfig.getDn(), "root");

			Date validityStartDate = new Date(System.currentTimeMillis());
			Date validityEndDate = getEndDate(validityStartDate, rootCertificateConfig.getValidityDays());
			SubjectPublicKeyInfo subPubKeyInfo = SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());

			X509v3CertificateBuilder builder = new X509v3CertificateBuilder(rootCaDn, BigInteger.valueOf(1),
					validityStartDate, validityEndDate, rootCaDn, subPubKeyInfo);

			JcaX509ExtensionUtils extUtils = getExtUtils();

			// Mark this as root CA
			builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));

			builder.addExtension(Extension.authorityKeyIdentifier, false,
					extUtils.createAuthorityKeyIdentifier(keyPair.getPublic()))
					.addExtension(Extension.subjectKeyIdentifier, false,
							extUtils.createSubjectKeyIdentifier(keyPair.getPublic()))
					.addExtension(Extension.keyUsage, true,
							new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign | KeyUsage.cRLSign));

			X509CertificateHolder cert = builder
					.build(new JcaContentSignerBuilder(ctx.getConfig().getDefaults().getSignatureAlgorithm())
							.setProvider(ctx.getSecurityProvider()).build(keyPair.getPrivate()));
			return cert;
		} catch (CertIOException | OperatorCreationException e) {
			throw new ToolException("Error while composing certificate", e);
		}

	}

	private X509CertificateHolder createIntermediateCertificate(KeyPair intKey, KeyPair caKey,
			X509CertificateHolder caCert) throws ToolException {
		try {
			Date validityStartDate = new Date(System.currentTimeMillis());
			Date validityEndDate = getEndDate(validityStartDate, signingCertificateConfig.getValidityDays());

			X500Name intermediateDn = createDn(signingCertificateConfig.getDn(), "intermediate");

			SubjectPublicKeyInfo subPubKeyInfo = SubjectPublicKeyInfo.getInstance(intKey.getPublic().getEncoded());

			X509v3CertificateBuilder builder = new X509v3CertificateBuilder(caCert.getSubject(), BigInteger.valueOf(2),
					validityStartDate, validityEndDate, intermediateDn, subPubKeyInfo);

			JcaX509ExtensionUtils extUtils = getExtUtils();

			// Allow this certificate only to be used for leaf certificates
			builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(0));

			builder.addExtension(Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(caCert))
					.addExtension(Extension.subjectKeyIdentifier, false,
							extUtils.createSubjectKeyIdentifier(intKey.getPublic()))
					.addExtension(Extension.keyUsage, true,
							new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign | KeyUsage.cRLSign));

			X509CertificateHolder cert = builder
					.build(new JcaContentSignerBuilder(ctx.getConfig().getDefaults().getSignatureAlgorithm())
							.setProvider(ctx.getSecurityProvider()).build(caKey.getPrivate()));
			return cert;
		} catch (CertIOException | OperatorCreationException e) {
			throw new ToolException("Error while composing certificate", e);
		}
	}

	private String createReadme(String rootPrivateKeyPassword, String signingPrivateKeyPassword) {
		String result = "The private keys of the root certificate and/or the signing certificate have been saved encrypted with an auto-generated password.\n"
				+ "In order to use these new passwords later again with this tool, you must edit the tool config file and set the new passwords there.\n\n";

		result += "ca:\n" + "   root:\n" + "       pkPassword: " + rootPrivateKeyPassword + "\n";

		if (signingPrivateKeyPassword != null) {
			result += "   intermediate:\n" + "       pkPassword: " + signingPrivateKeyPassword;
		}

		return result;
	}

}
