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

package com.floragunn.searchguard.tools.tlsdiag.tasks;

import java.io.File;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertStore;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jce.exception.ExtCertPathValidatorException;

public class ValidateCert extends DumpCert {
	private static final Logger log = LogManager.getLogger(ValidateCert.class);

	private final Set<TrustAnchor> trustAnchors;

	public ValidateCert(Set<TrustAnchor> trustAnchors, File certPemFile) {
		super(certPemFile);
		this.trustAnchors = trustAnchors;
	}

	@Override
	public void run() {

		super.run();

		if (certificates.size() == 0) {
			return;
		}

		checkCertPath(certificates);
	}

	private void checkCertPath(List<X509Certificate> certificates) {
		try {
			X509Certificate certificate = certificates.get(0);

			X509CertSelector target = new X509CertSelector();
			target.setCertificate(certificate);
			PKIXBuilderParameters builderParameters = new PKIXBuilderParameters(trustAnchors, target);
			builderParameters
					.addCertStore(CertStore.getInstance("Collection", new CollectionCertStoreParameters(certificates)));

			// TODO

			builderParameters.setRevocationEnabled(false);

			CertPathBuilder builder = CertPathBuilder.getInstance("PKIX", "BC");

			PKIXCertPathBuilderResult certPathBuilderResult = (PKIXCertPathBuilderResult) builder
					.build(builderParameters);

			log.info("Trust anchor:\n" + certPathBuilderResult.getTrustAnchor().getTrustedCert().getSubjectDN());

		} catch (CertPathBuilderException e) {
			if (e.getCause() instanceof ExtCertPathValidatorException) {
				ExtCertPathValidatorException cause = (ExtCertPathValidatorException) e.getCause();

				if (cause.getCause() != null && cause.getCause() != cause && cause.getCause().getMessage() != null) {
					log.error("No certificate path could be found: " + cause.getMessage() + " ["
							+ cause.getCause().getMessage() + "]");
				} else {
					log.error("No certificate path could be found: " + cause.getMessage());
				}

				log.debug(cause.getCertPath().toString());
				log.debug(cause.getReason());

				if (cause.getCause() != null && cause.getCause() != cause) {
					log.debug(cause.getCause());
				}
			} else {
				log.error("No certificate path could be found: " + e.getMessage());
			}
		} catch (Exception e) {
			log.error("Error in checkCertPath()", e);
		}
	}

}
