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

				log.error("No certificate path could be found: " + cause.getMessage());

				log.debug(cause.getCertPath().toString());
				log.debug(cause.getReason());
			} else {
				log.error("No certificate path could be found: " + e.getMessage());
			}
		} catch (Exception e) {
			log.error("Error in checkCertPath()", e);
		}
	}

}
