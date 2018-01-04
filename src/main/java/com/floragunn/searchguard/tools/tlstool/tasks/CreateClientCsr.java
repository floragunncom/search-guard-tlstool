package com.floragunn.searchguard.tools.tlstool.tasks;

import java.io.IOException;
import java.security.KeyPair;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import com.floragunn.searchguard.tools.tlstool.Config;
import com.floragunn.searchguard.tools.tlstool.Context;
import com.floragunn.searchguard.tools.tlstool.ToolException;

public class CreateClientCsr extends Task {

	private Config.Client clientConfig;

	public CreateClientCsr(Context ctx, Config.Client clientConfig) {
		super(ctx);
		this.clientConfig = clientConfig;
	}

	@Override
	public void run() throws ToolException {
		try {

			KeyPair clientKeyPair = generateKeyPair(clientConfig.getKeysize());

			PKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(
					new X500Principal(clientConfig.getDn()), clientKeyPair.getPublic());

			ExtensionsGenerator extensionsGenerator = new ExtensionsGenerator();

			extensionsGenerator.addExtension(Extension.keyUsage, true,
					new KeyUsage(KeyUsage.digitalSignature | KeyUsage.nonRepudiation | KeyUsage.keyEncipherment));

			extensionsGenerator.addExtension(Extension.extendedKeyUsage, true, new ExtendedKeyUsage(
					new KeyPurposeId[] { KeyPurposeId.id_kp_clientAuth }));


			JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder("SHA256withRSA");
			ContentSigner signer = csBuilder.build(clientKeyPair.getPrivate());
			org.bouncycastle.pkcs.PKCS10CertificationRequest csr = builder.build(signer);
			
			addOutputFile(getClientFileName(clientConfig) + ".key", clientKeyPair.getPrivate());
			addOutputFile(getClientFileName(clientConfig) + ".csr", csr);
			

		} catch (OperatorCreationException | IOException e) {
			throw new ToolException("Error while composing certificate", e);
		} 
	}
}
