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
}
