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
import java.security.PrivateKey;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.cert.X509CertificateHolder;

import com.floragunn.searchguard.tools.tlstool.Config;
import com.floragunn.searchguard.tools.tlstool.Context;
import com.floragunn.searchguard.tools.tlstool.ToolException;

public class LoadCa extends Task {
	private static final Logger log = LogManager.getLogger(LoadCa.class);

	private Config.Ca.Certificate signingCertificateConfig;
	private String fileNameBase;

	public LoadCa(Context ctx, Config.Ca caConfig) throws ToolException {
		super(ctx);

		if (caConfig == null) {
			throw new ToolException("Configuration ca is required");
		}

		if (caConfig.getIntermediate() != null) {
			this.signingCertificateConfig = caConfig.getIntermediate();
			this.fileNameBase = "signing-ca";
			ctx.setRootCaFile(getConfiguredFile(caConfig.getIntermediate().getFile(), "signing-ca.pem", "pem"));
		} else {
			this.signingCertificateConfig = caConfig.getRoot();
			this.fileNameBase = "root-ca";
			ctx.setRootCaFile(getConfiguredFile(caConfig.getRoot().getFile(), "root-ca.pem", "pem"));
		}

		if (this.signingCertificateConfig == null) {
			throw new ToolException("Configuration ca.intermediate is required");
		}
	}

	@Override
	public void run() throws ToolException {
		File keyFile = getConfiguredFile(signingCertificateConfig.getFile(), fileNameBase + ".key", "key");
		File certFile = getConfiguredFile(signingCertificateConfig.getFile(), fileNameBase + ".pem", "pem");

		ctx.setSigningPrivateKey(readObjectFromPem(keyFile, PrivateKey.class, signingCertificateConfig.getPkPassword()));
		ctx.setSigningCertificate(readObjectFromPem(certFile, X509CertificateHolder.class));

		log.info("Using signing certificate: " + certFile.getAbsolutePath());
	}
}
