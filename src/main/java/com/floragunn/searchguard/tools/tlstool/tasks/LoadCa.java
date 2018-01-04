package com.floragunn.searchguard.tools.tlstool.tasks;

import java.io.File;
import java.security.PrivateKey;

import org.bouncycastle.cert.X509CertificateHolder;

import com.floragunn.searchguard.tools.tlstool.Config;
import com.floragunn.searchguard.tools.tlstool.Context;
import com.floragunn.searchguard.tools.tlstool.ToolException;

public class LoadCa extends Task {
	private Config.Ca.Certificate signingCertificateConfig;

	public LoadCa(Context ctx, Config.Ca caConfig) throws ToolException {
		super(ctx);
		
		if (caConfig == null) {
			throw new ToolException("Configuration ca is required");
		}
		
		this.signingCertificateConfig = caConfig.getIntermediate();
		
		if (this.signingCertificateConfig == null) {
			throw new ToolException("Configuration ca.intermediate is required");
		}
	}

	@Override
	public void run() throws ToolException {
		File keyFile = getConfiguredFile(signingCertificateConfig.getFile(), "signing-ca.key", "key");
		File certFile = getConfiguredFile(signingCertificateConfig.getFile(), "signing-ca.pem", "pem");
		
		ctx.setSigningPrivateKey(readObjectFromPem(keyFile, PrivateKey.class));
		ctx.setSigningCertificate(readObjectFromPem(certFile, X509CertificateHolder.class));
	}
}
