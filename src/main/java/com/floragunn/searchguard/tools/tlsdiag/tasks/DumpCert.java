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
import java.io.FileReader;
import java.io.IOException;
import java.net.InetAddress;
import java.security.MessageDigest;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.xml.bind.DatatypeConverter;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.util.Strings;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.x509.extension.X509ExtensionUtil;

import com.floragunn.searchguard.tools.util.PemFileUtils;
import com.floragunn.searchguard.tools.util.ReverseKeyPurposeIdMap;

public class DumpCert extends Task {
	private static final Logger log = LogManager.getLogger(ValidateCert.class);

	private static final String[] KEY_USAGE_NAMES = new String[] { "digitalSignature", "nonRepudiation",
			"keyEncipherment", "dataEncipherment", "keyAgreement", "keyCertSign", "cRLSign", "encipherOnly",
			"decipherOnly" };

	private static final String[] GENERAL_NAME_TAG_NAMES = new String[] { "otherName", "rfc822Name", "dNSName",
			"x400Address", "directoryName", "ediPartyName", "uniformResourceIdentifier", "iPAddress", "registeredID" };

	protected final File certPemFile;
	protected List<X509Certificate> certificates;

	public DumpCert(File certPemFile) {
		this.certPemFile = certPemFile;
	}

	@Override
	public void run() {

		try {
			log.info("\n========================================================================\n" + certPemFile
					+ "\n------------------------------------------------------------------------");
			log.debug("PEM Content:\n" + getPemFileSummary(certPemFile));

			certificates = PemFileUtils.readCertificatesFromPemFile(certPemFile);

			if (certificates.size() == 0) {
				log.error("No certificates were found in " + certPemFile);
				return;
			}

			for (int i = 0; i < certificates.size(); i++) {
				log.info("Certificate " + (i + 1));
				log.info("------------------------------------------------------------------------");
				log.info(getCertSummary(certificates.get(i)));
				log.debug("\nAll Extensions:");
				log.debug(getDetailedExtensionList(certificates.get(i)));
				log.info("------------------------------------------------------------------------");
			}

		} catch (Exception e) {
			log.error("Error while reading " + certPemFile + ": " + e, e);
		}
	}

	private String getPemFileSummary(File file) {
		StringBuilder result = new StringBuilder();

		try (PEMParser pemParser = new PEMParser(new FileReader(file))) {
			PemObject pemObject;

			while ((pemObject = pemParser.readPemObject()) != null) {
				result.append(pemObject.getType()).append('\n');
			}
		} catch (IOException e) {
			result.append(e.toString()).append('\n');
		}

		return result.toString();
	}

	private String getCertSummary(X509Certificate certificate) {
		StringBuilder result = new StringBuilder();

		result.append("            SHA1 FPR: ").append(getFingerprint(certificate, "SHA1")).append('\n');
		result.append("             MD5 FPR: ").append(getFingerprint(certificate, "MD5")).append('\n');
		result.append("Subject DN [RFC2253]: ").append(certificate.getSubjectX500Principal().getName()).append('\n');
		result.append("       Serial Number: ").append(certificate.getSerialNumber()).append('\n');
		result.append(" Issuer DN [RFC2253]: ").append(certificate.getIssuerX500Principal().getName()).append('\n');
		result.append("          Not Before: ").append(certificate.getNotBefore()).append('\n');
		result.append("           Not After: ").append(certificate.getNotAfter()).append('\n');
		result.append("           Key Usage: ").append(getKeyUsageInfo(certificate)).append('\n');
		result.append(" Signature Algorithm: ").append(certificate.getSigAlgName()).append('\n');
		result.append("             Version: ").append(certificate.getVersion()).append('\n');

		try {
			result.append("  Extended Key Usage: ")
					.append(Strings.join(ReverseKeyPurposeIdMap.getNamesById(certificate.getExtendedKeyUsage()), ' '))
					.append('\n');
		} catch (CertificateParsingException e) {
			result.append(e.toString()).append('\n');
		}
		result.append("  Basic Constraints: ").append(certificate.getBasicConstraints()).append('\n');
		result.append("                SAN: ").append(getSubjectAlternativeNameInfo(certificate));

		return result.toString();
	}

	private String getDetailedExtensionList(X509Certificate certificate) {
		try {
			StringBuilder result = new StringBuilder();

			// Looks weird. Unsure if there is a less convoluted way.
			TBSCertificate tbsCertificate = TBSCertificate.getInstance(certificate.getTBSCertificate());
			Extensions extensions = tbsCertificate.getExtensions();

			for (ASN1ObjectIdentifier oid : extensions.getExtensionOIDs()) {
				Extension extension = extensions.getExtension(oid);
				result.append(oid.getId());

				if (extension.isCritical()) {
					result.append(" (critical)");
				}

				result.append(": ");

				result.append(extension.getParsedValue()).append("\n");
			}

			return result.toString();
		} catch (Exception e) {
			log.debug("Error in getDetailedExtensionList()", e);
			return e.toString();
		}
	}

	private String getKeyUsageInfo(X509Certificate certificate) {
		boolean[] keyUsage = certificate.getKeyUsage();
		StringBuilder result = new StringBuilder();

		for (int i = 0; i < keyUsage.length && i < KEY_USAGE_NAMES.length; i++) {
			if (keyUsage[i]) {
				if (result.length() != 0) {
					result.append(' ');
				}

				result.append(KEY_USAGE_NAMES[i]);
			}
		}

		return result.toString();
	}

	private String getFingerprint(X509Certificate certificate, String algorithm) {
		try {
			MessageDigest messageDigest = MessageDigest.getInstance(algorithm);
			byte[] der = certificate.getEncoded();
			messageDigest.update(der);
			byte[] digest = messageDigest.digest();
			String digestHex = DatatypeConverter.printHexBinary(digest);
			return digestHex;
		} catch (Exception e) {
			log.debug("Error in getFingerprint()", e);
			return e.toString();
		}
	}

	private String getSubjectAlternativeNameInfo(X509Certificate cert) {
		try {
			byte[] extensionBytes = cert.getExtensionValue(Extension.subjectAlternativeName.getId());

			if (extensionBytes == null) {
				return "(none)";
			}

			StringBuilder result = new StringBuilder("\n");

			for (ASN1Encodable encodable : DERSequence
					.getInstance(X509ExtensionUtil.fromExtensionValue(extensionBytes))) {
				GeneralName generalName = GeneralName.getInstance(encodable);

				if (generalName.getTagNo() < GENERAL_NAME_TAG_NAMES.length) {
					result.append("                  ").append(GENERAL_NAME_TAG_NAMES[generalName.getTagNo()])
							.append(": ");
				}

				result.append(generalNameValueToString(generalName)).append('\n');
			}

			return result.toString();
		} catch (IOException e) {
			log.debug("Error in getSubjectAlternativeNameInfo()", e);
			return e.toString();
		}
	}

	private String generalNameValueToString(GeneralName generalName) {
		try {
			switch (generalName.getTagNo()) {
			case GeneralName.ediPartyName:
			case GeneralName.x400Address:
			case GeneralName.otherName:
				return String.valueOf(generalName.getName().toASN1Primitive());
			case GeneralName.directoryName:
				return String.valueOf(X500Name.getInstance(generalName.getName()));
			case GeneralName.dNSName:
			case GeneralName.rfc822Name:
			case GeneralName.uniformResourceIdentifier:
				return String.valueOf(((ASN1String) generalName.getName()).getString());
			case GeneralName.registeredID:
				return String.valueOf(ASN1ObjectIdentifier.getInstance(generalName.getName()).getId());
			case GeneralName.iPAddress:
				return String.valueOf(InetAddress
						.getByAddress(DEROctetString.getInstance(generalName.getName()).getOctets()).getHostAddress());
			default:
				return String.valueOf(generalName.getName());
			}
		} catch (Exception e) {
			log.debug("Exception in generalNameValueToString()", e);
			return e.toString();
		}
	}
}
