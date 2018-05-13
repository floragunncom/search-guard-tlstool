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

import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import com.floragunn.searchguard.tools.tlstool.Config;
import com.floragunn.searchguard.tools.tlstool.Context;
import com.floragunn.searchguard.tools.tlstool.ToolException;

public class LoadCaTest {

	@BeforeClass
	public static void init() {
		Security.addProvider(new BouncyCastleProvider());
	}

	@Test
	public void testWithIntermediateCert() throws ToolException {
		Context ctx = new Context();
		Config.Ca caConfig = new Config.Ca();
		Config.Ca.Certificate rootCertificateConfig = new Config.Ca.Certificate();
		Config.Ca.Certificate intermediateCertificateConfig = new Config.Ca.Certificate();

		rootCertificateConfig.setFile(TestResources.getAbsolutePath("with-intermediate/root-ca.pem"));
		rootCertificateConfig.setPkPassword("secret");
		intermediateCertificateConfig.setFile(TestResources.getAbsolutePath("with-intermediate/signing-ca.pem"));
		intermediateCertificateConfig.setPkPassword("secret");
		
		caConfig.setRoot(rootCertificateConfig);
		caConfig.setIntermediate(intermediateCertificateConfig);

		LoadCa loadCa = new LoadCa(ctx, caConfig);

		loadCa.run();

		Assert.assertEquals("DC=com,DC=example,O=Example Com\\, Inc.,OU=CA,CN=signing.ca.example.com",
				ctx.getSigningCertificate().getSubject().toString());
		Assert.assertEquals(1272483699, ctx.getSigningPrivateKey().hashCode());
	}

	@Test
	public void testWithoutIntermediateCert() throws ToolException {
		Context ctx = new Context();
		Config.Ca caConfig = new Config.Ca();
		Config.Ca.Certificate rootCertificateConfig = new Config.Ca.Certificate();

		rootCertificateConfig.setFile(TestResources.getAbsolutePath("without-intermediate/root-ca.pem"));
		rootCertificateConfig.setPkPassword("secret");

		caConfig.setRoot(rootCertificateConfig);

		LoadCa loadCa = new LoadCa(ctx, caConfig);

		loadCa.run();

		Assert.assertEquals("DC=com,DC=example,O=Example Com\\, Inc.,OU=CA,CN=root.ca.example.com",
				ctx.getSigningCertificate().getSubject().toString());
		Assert.assertEquals(-1135900547, ctx.getSigningPrivateKey().hashCode());


	}
	
	@Test
	public void testWithIntermediateCertUnencryptedPk() throws ToolException {
		Context ctx = new Context();
		Config.Ca caConfig = new Config.Ca();
		Config.Ca.Certificate rootCertificateConfig = new Config.Ca.Certificate();
		Config.Ca.Certificate intermediateCertificateConfig = new Config.Ca.Certificate();

		rootCertificateConfig.setFile(TestResources.getAbsolutePath("with-intermediate-unencrypted-pk/root-ca.pem"));
		rootCertificateConfig.setPkPassword("none");
		intermediateCertificateConfig.setFile(TestResources.getAbsolutePath("with-intermediate-unencrypted-pk/signing-ca.pem"));
		intermediateCertificateConfig.setPkPassword("none");
		
		caConfig.setRoot(rootCertificateConfig);
		caConfig.setIntermediate(intermediateCertificateConfig);

		LoadCa loadCa = new LoadCa(ctx, caConfig);

		loadCa.run();

		Assert.assertEquals("DC=com,DC=example,O=Example Com\\, Inc.,OU=CA,CN=signing.ca.example.com",
				ctx.getSigningCertificate().getSubject().toString());
		Assert.assertEquals(-1490461901, ctx.getSigningPrivateKey().hashCode());
	}
}
