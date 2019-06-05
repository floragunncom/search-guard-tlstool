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
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.Reader;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Calendar;
import java.util.Date;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;

import org.apache.commons.io.FilenameUtils;
import org.apache.commons.text.CharacterPredicates;
import org.apache.commons.text.RandomStringGenerator;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.RFC4519Style;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;

import com.floragunn.searchguard.tools.tlstool.Config;
import com.floragunn.searchguard.tools.tlstool.Config.KeyGenParameters;
import com.floragunn.searchguard.tools.tlstool.Context;
import com.floragunn.searchguard.tools.tlstool.ToolException;
import com.google.common.base.Strings;

public abstract class Task {
	private static final Logger log = LogManager.getLogger(Task.class);

	protected final Context ctx;

	protected Task(Context ctx) {
		this.ctx = ctx;
	}

	public abstract void run() throws ToolException;

	protected KeyPair generateKeyPair(KeyGenParameters parameters) throws ToolException {
		try {

		    KeyPairGenerator generator;
		    if(parameters.getUseEllipticCurves() != null && parameters.getUseEllipticCurves()) {
		        log.debug("Create {} with EC ({})", parameters.getClass().getSimpleName(), parameters.getEllipticCurve());
		        generator = KeyPairGenerator.getInstance("EC", ctx.getSecurityProvider());
		        ECGenParameterSpec ecsp = new ECGenParameterSpec(parameters.getEllipticCurve());
		        generator.initialize(ecsp);
		    } else {
                log.debug("Create {} with RSA ({})", parameters.getClass().getSimpleName(), parameters.getKeysize());
		        generator = KeyPairGenerator.getInstance("RSA", ctx.getSecurityProvider());
		        generator.initialize(parameters.getKeysize());
		    }

			KeyPair keyPair = generator.generateKeyPair();
			return keyPair;

		} catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
			throw new RuntimeException(e);
		}
	}

	protected void addOutputFile(String fileName, Object... entries) {
		ctx.getFileOutput().add(fileName, entries);
	}

	protected void addOutputFile(File file, Object... entries) {
		ctx.getFileOutput().add(file, entries);
	}

	protected void addEncryptedOutputFile(String fileName, String password, Object... entries) {
		ctx.getFileOutput().addEncrypted(fileName, password, entries);
	}

	protected void addEncryptedOutputFile(File file, String password, Object... entries) {
		ctx.getFileOutput().addEncrypted(file, password, entries);
	}

	protected void appendOutputFile(File file, Object... entries) {
		ctx.getFileOutput().append(file, entries);
	}

	protected void appendEnryptedOutputFile(File file, String password, Object... entries) {
		ctx.getFileOutput().appendEncrypted(file, password, entries);
	}

	protected boolean checkFileOverwrite(String artifact, String dn, File... files) {
		for (File file : files) {
			if (file.exists()) {
				if (!ctx.isOverwrite()) {
					log.info(file + " does already exist. Skipping creation of " + artifact + " for " + dn);
					return false;
				} else {
					log.debug("Overwriting " + file);
				}
			}
		}

		return true;
	}

	protected String getPassword(String passwordConfig) {
		if (Strings.isNullOrEmpty(passwordConfig) || "none".equalsIgnoreCase(passwordConfig)) {
			return null;
		} else if (isPasswordAutoGenerationEnabled(passwordConfig)) {
			return getAutoGeneratedPassword();
		} else {
			return passwordConfig;
		}
	}

	protected boolean isPasswordAutoGenerationEnabled(String passwordConfig) {
		return "auto".equalsIgnoreCase(passwordConfig);
	}

	private String getAutoGeneratedPassword() {
		RandomStringGenerator randomStringGenerator = new RandomStringGenerator.Builder().withinRange('0', 'z')
				.filteredBy(CharacterPredicates.LETTERS, CharacterPredicates.DIGITS)
				.usingRandom(this.ctx.getSecureRandom()::nextInt).build();

		return randomStringGenerator.generate(ctx.getConfig().getDefaults().getGeneratedPasswordLength());
	}

	protected JcaX509ExtensionUtils getExtUtils() {
		try {
			return new JcaX509ExtensionUtils();
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}

	protected X500Name createDn(String dn, String role) throws ToolException {
		if (Strings.isNullOrEmpty(dn)) {
			throw new ToolException("No DN specified for " + role + " certificate");
		}

		try {
			return new X500Name(RFC4519Style.INSTANCE, dn);
		} catch (IllegalArgumentException e) {
			throw new ToolException("Invalid DN specified for " + role + " certificate: " + dn, e);
		}
	}
	
	protected String sanitizeDn(String dn, String role) throws ToolException {
		if (Strings.isNullOrEmpty(dn)) {
			throw new ToolException("No DN specified for " + role + " certificate");
		}

		try {
			return new LdapName(new LdapName(dn).getRdns()).toString();
		} catch (InvalidNameException e) {
			throw new ToolException("Invalid DN specified for " + role + " certificate: " + dn, e);
		}
	}

	protected Date getEndDate(Date startDate, int validityDays) {
		Calendar calendar = Calendar.getInstance();
		calendar.setTime(startDate);
		calendar.add(Calendar.DATE, validityDays);
		return calendar.getTime();
	}

	protected <E> E readObjectFromPem(File file, Class<E> expectedType) throws ToolException {
		try {
			return readObjectFromPem(file, new FileReader(file), expectedType);
		} catch (FileNotFoundException e) {
			throw new ToolException("File does not exist: " + file);
		}
	}

	protected <E> E readObjectFromPem(File file, Class<E> expectedType, String password) throws ToolException {
		try {
			if ("auto".equalsIgnoreCase(password) || "none".equalsIgnoreCase(password)) {
				password = null;
			}

			return readObjectFromPem(file, new FileReader(file), expectedType, password);
		} catch (FileNotFoundException e) {
			throw new ToolException("File does not exist: " + file);
		}
	}

	protected <E> E readObjectFromPem(File file, Reader reader, Class<E> expectedType) throws ToolException {
		return readObjectFromPem(file, reader, expectedType, null);
	}

	protected <E> E readObjectFromPem(File file, Reader reader, Class<E> expectedType, String password)
			throws ToolException {
		try (PEMParser pemParser = new PEMParser(reader)) {

			Object object = pemParser.readObject();
			if (object == null) {
				throw new ToolException("No object found in file " + file);
			}

			if (!(expectedType.isAssignableFrom(object.getClass()))) {
				object = tryConvertObjectToExpectedType(file, object, expectedType, password);
			}

			if (!(expectedType.isAssignableFrom(object.getClass()))) {
				throw new ToolException("Object in file " + file + " is not of type " + expectedType + "; Actually: "
						+ object.getClass());
			}

			return expectedType.cast(object);
		} catch (IOException | OperatorCreationException | PKCSException e) {
			throw new ToolException("Error while reading " + file + ": " + e.getMessage(), e);
		}
	}

	private Object tryConvertObjectToExpectedType(File file, Object object, Class<?> expectedType, String password)
			throws IOException, OperatorCreationException, PKCSException, ToolException {
		if (expectedType.equals(PrivateKey.class)) {
			if (object instanceof PEMEncryptedKeyPair) {
				if (Strings.isNullOrEmpty(password)) {
					throw new ToolException("File " + file
							+ " is encrypted but no password is given. Please specify a password in the configuration file.");
				}

				try {
					PEMKeyPair keyPair = ((PEMEncryptedKeyPair) object)
							.decryptKeyPair(new JcePEMDecryptorProviderBuilder().build(password.toCharArray()));

					return privateKeyInfoToPrivateKey(keyPair.getPrivateKeyInfo());
				} catch (Exception e) {
					throw new ToolException("Error reading encrypted file " + file + "; bad password?", e);
				}
			} else if (object instanceof PEMKeyPair) {
				return privateKeyInfoToPrivateKey(((PEMKeyPair) object).getPrivateKeyInfo());
			} else if (object instanceof PKCS8EncryptedPrivateKeyInfo) {
				if (Strings.isNullOrEmpty(password)) {
					throw new ToolException("File " + file
							+ " is encrypted but no password is given. Please specify a password in the configuration file.");
				}

				try {
					PrivateKeyInfo privateKeyInfo = ((PKCS8EncryptedPrivateKeyInfo) object).decryptPrivateKeyInfo(
							new JceOpenSSLPKCS8DecryptorProviderBuilder().build(password.toCharArray()));

					return privateKeyInfoToPrivateKey(privateKeyInfo);
				} catch (Exception e) {
					throw new ToolException("Error reading encrypted file " + file + "; bad password?", e);
				}
			} else if (object instanceof PrivateKeyInfo) {
				return privateKeyInfoToPrivateKey((PrivateKeyInfo) object);
			}
		}

		// if a conversion did not happen, just return the old value. Type will be
		// checked by the caller

		return object;
	}

	private PrivateKey privateKeyInfoToPrivateKey(PrivateKeyInfo privateKeyInfo) throws PEMException {
		return new JcaPEMKeyConverter().setProvider(ctx.getSecurityProvider()).getPrivateKey(privateKeyInfo);
	}

	protected File getConfiguredFile(String configValue, String defaultValue, String extension) {
		if (configValue == null) {
			return new File(ctx.getTargetDirectory(), defaultValue);
		}

		return new File(ctx.getTargetDirectory(), FilenameUtils.removeExtension(configValue) + "." + extension);
	}

	protected String getSimpleNameFromDn(String dnString) {
		try {
			X500Name dn = new X500Name(dnString);
			RDN[] rdns = dn.getRDNs();

			if (rdns != null && rdns.length > 0) {
				return rdns[0].getFirst().getValue().toString();
			}
		} catch (IllegalArgumentException e) {
			// DN was invalid - fall through
		}

		return null;
	}

	protected String getClientFileName(Config.Client client) {
		if (client.getName() != null) {
			return client.getName();
		}

		if (client.getDn() != null) {
			String name = getSimpleNameFromDn(client.getDn());

			if (name != null) {
				return name;
			}
		}

		return "client" + (ctx.getConfig().getClients().indexOf(client) + 1);
	}
}
