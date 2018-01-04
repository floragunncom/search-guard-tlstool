package com.floragunn.searchguard.tools.tlstool.tasks;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.Reader;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.util.Calendar;
import java.util.Date;

import org.apache.commons.io.FilenameUtils;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
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
import com.floragunn.searchguard.tools.tlstool.Context;
import com.floragunn.searchguard.tools.tlstool.ToolException;

public abstract class Task {

	protected final Context ctx;

	protected Task(Context ctx) {
		this.ctx = ctx;
	}

	public abstract void run() throws ToolException;

	protected KeyPair generateKeyPair(int keySize) throws ToolException {
		try {
			KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", ctx.getSecurityProvider());
			generator.initialize(keySize);

			KeyPair keyPair = generator.generateKeyPair();
			return keyPair;
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}

	protected void addOutputFile(String fileName, Object... entries) {
		ctx.getFileOutput().add(fileName, entries);
	}

	protected void addOutputFile(File file, Object... entries) {
		ctx.getFileOutput().add(file, entries);
	}

	protected JcaX509ExtensionUtils getExtUtils() {
		try {
			return new JcaX509ExtensionUtils();
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}

	protected X500Name createDn(String dn, String role) throws ToolException {
		try {
			return new X500Name(dn);
		} catch (IllegalArgumentException e) {
			throw new ToolException("Invalid DN specified for " + role + ": " + dn, e);
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

	protected <E> E readObjectFromPem(File file, Reader reader, Class<E> expectedType) throws ToolException {
		try (PEMParser pemParser = new PEMParser(reader)) {

			Object object = pemParser.readObject();
			if (object == null) {
				throw new ToolException("No object found in file " + file);
			}

			if (!(expectedType.isAssignableFrom(object.getClass()))) {
				object = tryConvertObjectToExpectedType(file, object, expectedType);
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

	private Object tryConvertObjectToExpectedType(File file, Object object, Class<?> expectedType)
			throws IOException, OperatorCreationException, PKCSException, ToolException {
		if (expectedType.equals(PrivateKey.class)) {
			if (object instanceof PEMEncryptedKeyPair) {
				try {
					PEMKeyPair keyPair = ((PEMEncryptedKeyPair) object)
							.decryptKeyPair(new JcePEMDecryptorProviderBuilder().build(ctx.getPassword()));

					return privateKeyInfoToPrivateKey(keyPair.getPrivateKeyInfo());
				} catch (Exception e) {
					throw new ToolException("Error reading encrypted file " + file + "; bad password?", e);
				}
			} else if (object instanceof PEMKeyPair) {
				return privateKeyInfoToPrivateKey(((PEMKeyPair) object).getPrivateKeyInfo());
			} else if (object instanceof PKCS8EncryptedPrivateKeyInfo) {
				try {
					PrivateKeyInfo privateKeyInfo = ((PKCS8EncryptedPrivateKeyInfo) object).decryptPrivateKeyInfo(
							new JceOpenSSLPKCS8DecryptorProviderBuilder().build(ctx.getPassword()));

					return privateKeyInfoToPrivateKey(privateKeyInfo);
				} catch (Exception e) {
					throw new ToolException("Error reading encrypted file " + file + "; bad password?", e);
				}
			}
		}

		// if conversion did not happen, just return the old value. Type will be checked
		// by the caller

		return object;
	}

	private PrivateKey privateKeyInfoToPrivateKey(PrivateKeyInfo privateKeyInfo) throws PEMException {
		return new JcaPEMKeyConverter().setProvider(ctx.getSecurityProvider()).getPrivateKey(privateKeyInfo);
	}

	protected File getConfiguredFile(String configValue, String defaultValue, String extension) {
		if (configValue == null) {
			return new File(defaultValue);
		}

		return new File(FilenameUtils.removeExtension(configValue) + "." + extension);
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
