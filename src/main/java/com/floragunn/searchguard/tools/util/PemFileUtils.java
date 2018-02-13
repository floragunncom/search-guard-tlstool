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

package com.floragunn.searchguard.tools.util;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMParser;

public class PemFileUtils {
	public static List<X509Certificate> readCertificatesFromPemFile(File file) throws IOException, CertificateException {

		List<X509Certificate> result = new ArrayList<>();

		try (PEMParser pemParser = new PEMParser(new FileReader(file))) {

			Object object;

			while ((object = pemParser.readObject()) != null) {
				if (object instanceof X509CertificateHolder) {
					result.add(new JcaX509CertificateConverter().setProvider("BC")
							.getCertificate((X509CertificateHolder) object));
				}
			}

		}

		return result;
	}
}
