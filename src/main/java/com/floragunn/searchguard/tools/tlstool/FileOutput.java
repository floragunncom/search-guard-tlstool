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


public class FileOutput {
	private List<FileEntry> fileEntries = new ArrayList<>();

	public void add(String fileName, Object ...entries) {
		fileEntries.add(new FileEntry(new File(fileName), entries));
	}

	public void add(File file, Object ...entries) {
		fileEntries.add(new FileEntry(file, entries));
	}

	
	public void saveAllFiles(char [] password) throws ToolException {
		for (FileEntry fileEntry : fileEntries) {
			try (JcaPEMWriter writer = new JcaPEMWriter(new FileWriter(fileEntry.getFile()))) {
				for (Object object : fileEntry.getEntries()) {
					if (object instanceof PrivateKey && password != null) {
						object = createEncryptedPem((PrivateKey) object, password);
					}
					
					writer.writeObject(object);
				}
			} catch (Exception e) {
				throw new ToolException("Error while writing " + fileEntry.getFile() + ": " + e.getMessage(), e);
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
		private final File file;
		private final List<Object> entries;
		
		FileEntry(File file, Object... entries) {
			this.file = file;
			this.entries = Arrays.asList(entries);
		}

		public List<Object> getEntries() {
			return entries;
		}


		public File getFile() {
			return file;
		}
		
	}
}
