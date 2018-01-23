package com.floragunn.searchguard.tools.tlstool;

import java.io.File;
import java.io.FileWriter;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PKCS8Generator;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8EncryptorBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.util.io.pem.PemGenerationException;
import org.bouncycastle.util.io.pem.PemObject;

public class FileOutput {
	private static final Logger log = LogManager.getLogger(FileOutput.class);

	private Map<File, FileEntry> fileEntryMap = new HashMap<>();
	private List<FileEntry> fileEntries = new ArrayList<>();

	public void add(String fileName, Object... entries) {
		add(new File(fileName), null, entries);
	}

	public void add(File file, Object... entries) {
		add(file, null, entries);
	}

	public void addEncrypted(String fileName, String password, Object... entries) {
		addEncrypted(new File(fileName), password, entries);
	}

	public void addEncrypted(File file, String password, Object... entries) {
		add(file, password, entries);
	}

	public void append(File file, Object... entries) {
		append(file, null, entries);
	}

	public void appendEncrypted(File file, String password, Object... entries) {
		append(file, password, entries);
	}

	private void add(File file, String password, Object... entries) {
		FileEntry fileEntry = fileEntryMap.get(file);

		if (fileEntry == null) {
			fileEntry = new FileEntry(file, password, entries);
			fileEntries.add(fileEntry);
			fileEntryMap.put(file, fileEntry);

		} else {
			// Just skip this call. Thus, we are able to create a unique header for a file
		}

	}

	private void append(File file, String password, Object... entries) {
		FileEntry fileEntry = fileEntryMap.get(file);

		if (fileEntry == null) {
			fileEntry = new FileEntry(file, password, entries);
			fileEntries.add(fileEntry);
			fileEntryMap.put(file, fileEntry);

		} else {
			fileEntry.entries.addAll(Arrays.asList(entries));
		}

	}

	public void saveAllFiles() throws ToolException {
		for (FileEntry fileEntry : fileEntries) {
			log.info("Going to write: " + fileEntry.getFile() + " " + fileEntry.getEntries());
			
			try (JcaPEMWriter writer = new JcaPEMWriter(new FileWriter(fileEntry.getFile()))) {
				for (Object object : fileEntry.getEntries()) {
					if (object instanceof String) {
						writer.write((String) object);
					} else {
						if (object instanceof PrivateKey && fileEntry.getPassword() != null) {
							object = createEncryptedPem((PrivateKey) object, fileEntry.getPassword().toCharArray());
						}

						writer.writeObject(object);
					}
				}
			} catch (Exception e) {
				throw new ToolException("Error while writing " + fileEntry.getFile() + ": " + e.getMessage(), e);
			}
		}
	}

	private PemObject createEncryptedPem(PrivateKey privateKey, char[] password)
			throws PemGenerationException, OperatorCreationException {
		JceOpenSSLPKCS8EncryptorBuilder encryptorBuilder = new JceOpenSSLPKCS8EncryptorBuilder(
				PKCS8Generator.PBE_SHA1_3DES);
		// encryptorBuilder.setRandom(EntropySource.); // TODO
		encryptorBuilder.setPasssword(password);
		OutputEncryptor outputEncryptor = encryptorBuilder.build();
		PKCS8Generator generator = new PKCS8Generator(PrivateKeyInfo.getInstance(privateKey.getEncoded()),
				outputEncryptor);
		return generator.generate();
	}

	static class FileEntry {
		private final File file;
		private final List<Object> entries;
		private final String password;

		FileEntry(File file, String password, Object... entries) {
			this.file = file;
			this.password = password;
			this.entries = new ArrayList<>(Arrays.asList(entries));
		}

		public List<Object> getEntries() {
			return entries;
		}

		public File getFile() {
			return file;
		}

		public String getPassword() {
			return password;
		}

	}
}
