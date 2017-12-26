package com.floragunn.searchguard.tools.tlstool;

import java.io.File;
import java.io.FileWriter;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PKCS8Generator;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8EncryptorBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.util.io.pem.PemGenerationException;
import org.bouncycastle.util.io.pem.PemObject;


class FileOutput {
	private List<FileEntry> fileEntries = new ArrayList<>();

	void add(String fileName, Object ...entries) {
		fileEntries.add(new FileEntry(fileName, entries));
	}
	
	void saveAllFiles(char [] password) throws ToolException {
		for (FileEntry fileEntry : fileEntries) {
			try (JcaPEMWriter writer = new JcaPEMWriter(new FileWriter(new File(fileEntry.getName())))) {
				for (Object object : fileEntry.getEntries()) {
					if (object instanceof PrivateKey && password != null) {
						object = createEncryptedPem((PrivateKey) object, password);
					}
					
					writer.writeObject(object);
				}
			} catch (Exception e) {
				throw new ToolException("Error while writing " + fileEntry.getName() + ": " + e.getMessage(), e);
			}
		}
	}
	
	private PemObject createEncryptedPem(PrivateKey privateKey, char [] password) throws PemGenerationException, OperatorCreationException {
		JceOpenSSLPKCS8EncryptorBuilder encryptorBuilder = new JceOpenSSLPKCS8EncryptorBuilder(PKCS8Generator.PBE_SHA1_3DES);
	    // encryptorBuilder.setRandom(EntropySource.); // TODO
	    encryptorBuilder.setPasssword(password);
	    OutputEncryptor outputEncryptor = encryptorBuilder.build();
		PKCS8Generator generator = new PKCS8Generator(PrivateKeyInfo.getInstance(privateKey.getEncoded()), outputEncryptor);
		return generator.generate();
	}
	
	static class FileEntry {
		private final String name;
		private final List<Object> entries;
		
		FileEntry(String name, Object... entries) {
			this.name = name;
			this.entries = Arrays.asList(entries);
		}

		public String getName() {
			return name;
		}

		public List<Object> getEntries() {
			return entries;
		}
		
	}
}
