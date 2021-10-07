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

import com.google.common.base.Ascii;

public class FileOutput {
	private static final Logger log = LogManager.getLogger(FileOutput.class);

	private final Map<File, FileEntry> fileEntryMap = new HashMap<>();
	private final List<FileEntry> fileEntries = new ArrayList<>();
	private final Context ctx;

	public FileOutput(Context ctx) {
		this.ctx = ctx;
	}

	public void add(File file, Object... entries) {
		add(file, null, entries);
	}

	public void addEncrypted(File file, String password, Object... entries) {
		add(file, password, entries);
	}

	public void append(File file, Object... entries) {
		append(file, null, entries);
	}

	public FileEntry getEntryByFileName(String fileName) {
		return fileEntryMap.get(new File(fileName));
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
			log.debug("Going to write: " + fileEntry.getFile() + " " + filterEntriesForLog(fileEntry.getEntries()));

			try (JcaPEMWriter writer = new JcaPEMWriter(new FileWriter(fileEntry.getFile()))) {
				for (Object object : fileEntry.getEntries()) {
					if (object instanceof String) {
						writer.write((String) object);
					} else {
						if (object instanceof PrivateKey) {
							object = createPkcs8PrivateKeyPem((PrivateKey) object, fileEntry.getPassword());
						}

						writer.writeObject(object);
					}
				}
			} catch (Exception e) {
				throw new ToolException("Error while writing " + fileEntry.getFile() + ": " + e.getMessage(), e);
			}
		}
	}

	private List<Object> filterEntriesForLog(List<Object> entries) {
		List<Object> result = new ArrayList<Object>(entries.size());

		for (Object object : entries) {
			if (object instanceof String) {
				result.add(Ascii.truncate((String) object, 10, "..."));
			} else {
				result.add(object);
			}
		}

		return result;
	}

	private PemObject createPkcs8PrivateKeyPem(PrivateKey privateKey, String password)
			throws PemGenerationException, OperatorCreationException {
		OutputEncryptor outputEncryptor = null;

		if (password != null) {
			JceOpenSSLPKCS8EncryptorBuilder encryptorBuilder = new JceOpenSSLPKCS8EncryptorBuilder(
					PKCS8Generator.PBE_SHA1_3DES);
			encryptorBuilder.setRandom(ctx.getSecureRandom());
			encryptorBuilder.setPasssword(password.toCharArray());
			outputEncryptor = encryptorBuilder.build();
		}

		PKCS8Generator generator = new PKCS8Generator(PrivateKeyInfo.getInstance(privateKey.getEncoded()),
				outputEncryptor);
		return generator.generate();
	}

	public static class FileEntry {
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
