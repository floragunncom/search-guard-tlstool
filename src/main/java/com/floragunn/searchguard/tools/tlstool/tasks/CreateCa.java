package com.floragunn.searchguard.tools.tlstool.tasks;

import java.io.File;
import java.math.BigInteger;
import java.security.KeyPair;
import java.util.Date;

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
		
		if (this.signingCertificateConfig == null) {
			throw new ToolException("Configuration ca.intermediate is required");
		}
		
	}

	@Override
	public void run() throws ToolException {
		File rootKeyFile = getConfiguredFile(rootCertificateConfig.getFile(), "root-ca.key", "key");
		File rootCertFile = getConfiguredFile(rootCertificateConfig.getFile(), "root-ca.pem", "pem");

		KeyPair rootCaKeyPair = generateKeyPair(rootCertificateConfig.getKeysize());
		
		X509CertificateHolder rootCaCertificate = createRootCaCertificate(rootCaKeyPair);

		ctx.setRootCaCertificate(rootCaCertificate);
		
		addOutputFile(rootCertFile, rootCaCertificate);
		addOutputFile(rootKeyFile, rootCaKeyPair.getPrivate());
		
		File signingKeyFile = getConfiguredFile(signingCertificateConfig.getFile(), "signing-ca.key", "key");
		File signingCertFile = getConfiguredFile(signingCertificateConfig.getFile(), "signing-ca.pem", "pem");
		
		KeyPair intermediateKeyPair = generateKeyPair(signingCertificateConfig.getKeysize());
		X509CertificateHolder intermediateCertificate = createIntermediateCertificate(intermediateKeyPair,
				rootCaKeyPair, rootCaCertificate);
		
		ctx.setSigningCertificate(intermediateCertificate);
		ctx.setSigningPrivateKey(intermediateKeyPair.getPrivate());

		addOutputFile(signingCertFile, intermediateCertificate);
		addOutputFile(signingKeyFile, intermediateKeyPair.getPrivate());
	}
	
	private X509CertificateHolder createRootCaCertificate(KeyPair keyPair)
			throws ToolException {
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

			X509CertificateHolder cert = builder.build(new JcaContentSignerBuilder("SHA1withRSA")
					.setProvider(ctx.getSecurityProvider()).build(keyPair.getPrivate()));
			return cert;
		} catch (CertIOException | OperatorCreationException e) {
			throw new ToolException("Error while composing certificate", e);
		}

	}

	private X509CertificateHolder createIntermediateCertificate(KeyPair intKey, KeyPair caKey, X509CertificateHolder caCert) throws ToolException {
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

			X509CertificateHolder cert = builder.build(
					new JcaContentSignerBuilder("SHA1withRSA").setProvider(ctx.getSecurityProvider()).build(caKey.getPrivate()));
			return cert;
		} catch (CertIOException | OperatorCreationException e) {
			throw new ToolException("Error while composing certificate", e);
		}
	}

}
