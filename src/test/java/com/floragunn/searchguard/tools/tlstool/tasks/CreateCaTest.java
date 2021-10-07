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

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import com.floragunn.searchguard.tools.tlstool.Config;
import com.floragunn.searchguard.tools.tlstool.Context;
import com.floragunn.searchguard.tools.tlstool.FileOutput;
import com.floragunn.searchguard.tools.tlstool.ToolException;

public class CreateCaTest {
	@BeforeClass
	public static void init() {
		Security.addProvider(new BouncyCastleProvider());
	}

	@Test
	public void testWithIntermediateCert() throws ToolException {
		Context ctx = new Context();
		Config config = new Config();
		Config.Ca caConfig = new Config.Ca();
		Config.Ca.Certificate rootCertificateConfig = new Config.Ca.Certificate();
		Config.Ca.Certificate intermediateCertificateConfig = new Config.Ca.Certificate();
		Config.Defaults defaults = new Config.Defaults();

		rootCertificateConfig.setFile("root-ca.pem");
		rootCertificateConfig.setPkPassword("secret");
		rootCertificateConfig.setKeysize(2048);
		rootCertificateConfig.setValidityDays(3650);
		rootCertificateConfig.setDn("CN=root.ca.example.com,OU=QA");

		intermediateCertificateConfig.setFile("signing-ca.pem");
		intermediateCertificateConfig.setPkPassword("secret");
		intermediateCertificateConfig.setKeysize(2048);
		intermediateCertificateConfig.setValidityDays(3650);
		intermediateCertificateConfig.setDn("CN=signing.ca.example.com,OU=QA");
		
		caConfig.setRoot(rootCertificateConfig);
		caConfig.setIntermediate(intermediateCertificateConfig);
		
		config.setDefaults(defaults);
		config.setCa(caConfig);
		
		ctx.setConfig(config);

		CreateCa createCa = new CreateCa(ctx, caConfig);
		createCa.run();

		Assert.assertEquals("cn=signing.ca.example.com,ou=QA", ctx.getSigningCertificate().getSubject().toString());
		Assert.assertNotNull(ctx.getSigningPrivateKey());
		
		FileOutput fileOutput = ctx.getFileOutput();
		
		FileOutput.FileEntry fileEntry = fileOutput.getEntryByFileName("root-ca.pem");
		Assert.assertEquals("cn=root.ca.example.com,ou=QA", ((X509CertificateHolder) fileEntry.getEntries().get(0)).getSubject().toString());
		
		fileEntry = fileOutput.getEntryByFileName("signing-ca.pem");
		Assert.assertEquals("cn=signing.ca.example.com,ou=QA", ((X509CertificateHolder) fileEntry.getEntries().get(0)).getSubject().toString());

		Assert.assertNotNull(fileOutput.getEntryByFileName("root-ca-key.pem"));
		Assert.assertNotNull(fileOutput.getEntryByFileName("signing-ca-key.pem"));
	}
	
    @Test
    public void testWithIntermediateCertEC() throws ToolException {
        Context ctx = new Context();
        Config config = new Config();
        Config.Ca caConfig = new Config.Ca();
        Config.Ca.Certificate rootCertificateConfig = new Config.Ca.Certificate();
        Config.Ca.Certificate intermediateCertificateConfig = new Config.Ca.Certificate();
        Config.Defaults defaults = new Config.Defaults();
        defaults.setUseEllipticCurves(true);

        rootCertificateConfig.setFile("root-ca.pem");
        rootCertificateConfig.setPkPassword("secret");
        rootCertificateConfig.setKeysize(2048);
        rootCertificateConfig.setValidityDays(3650);
        rootCertificateConfig.setDn("CN=root.ca.example.com,OU=QA");
        rootCertificateConfig.applyDefaults(defaults);

        intermediateCertificateConfig.setFile("signing-ca.pem");
        intermediateCertificateConfig.setPkPassword("secret");
        intermediateCertificateConfig.setKeysize(2048);
        intermediateCertificateConfig.setValidityDays(3650);
        intermediateCertificateConfig.setDn("CN=signing.ca.example.com,OU=QA");
        intermediateCertificateConfig.applyDefaults(defaults);

        caConfig.setRoot(rootCertificateConfig);
        caConfig.setIntermediate(intermediateCertificateConfig);

        config.setDefaults(defaults);
        caConfig.applyDefaults(defaults);
        config.setCa(caConfig);

        ctx.setConfig(config);

        CreateCa createCa = new CreateCa(ctx, caConfig);
        createCa.run();

        Assert.assertEquals("cn=signing.ca.example.com,ou=QA", ctx.getSigningCertificate().getSubject().toString());
        Assert.assertNotNull(ctx.getSigningPrivateKey());

        FileOutput fileOutput = ctx.getFileOutput();

        FileOutput.FileEntry fileEntry = fileOutput.getEntryByFileName("root-ca.pem");
        Assert.assertEquals("cn=root.ca.example.com,ou=QA", ((X509CertificateHolder) fileEntry.getEntries().get(0)).getSubject().toString());

        fileEntry = fileOutput.getEntryByFileName("signing-ca.pem");
        Assert.assertEquals("cn=signing.ca.example.com,ou=QA", ((X509CertificateHolder) fileEntry.getEntries().get(0)).getSubject().toString());

        Assert.assertNotNull(fileOutput.getEntryByFileName("root-ca-key.pem"));
        Assert.assertNotNull(fileOutput.getEntryByFileName("signing-ca-key.pem"));
    }
    
    @Test
    public void testWithIntermediateCertECNoDefaults() throws ToolException {
        Context ctx = new Context();
        Config config = new Config();
        Config.Ca caConfig = new Config.Ca();
        Config.Ca.Certificate rootCertificateConfig = new Config.Ca.Certificate();
        Config.Ca.Certificate intermediateCertificateConfig = new Config.Ca.Certificate();
        Config.Defaults defaults = new Config.Defaults();
        defaults.setUseEllipticCurves(true);
        defaults.setEllipticCurve("secp256k1");
        defaults.setSignatureAlgorithm("SHA512withECDSA");

        rootCertificateConfig.setFile("root-ca.pem");
        rootCertificateConfig.setPkPassword("secret");
        rootCertificateConfig.setValidityDays(3650);
        rootCertificateConfig.setDn("CN=root.ca.example.com,OU=QA");
        rootCertificateConfig.applyDefaults(defaults);

        intermediateCertificateConfig.setFile("signing-ca.pem");
        intermediateCertificateConfig.setPkPassword("secret");
        intermediateCertificateConfig.setKeysize(2048);
        intermediateCertificateConfig.setValidityDays(3650);
        intermediateCertificateConfig.setDn("CN=signing.ca.example.com,OU=QA");
        intermediateCertificateConfig.applyDefaults(defaults);

        caConfig.setRoot(rootCertificateConfig);
        caConfig.setIntermediate(intermediateCertificateConfig);

        config.setDefaults(defaults);
        caConfig.applyDefaults(defaults);
        config.setCa(caConfig);

        ctx.setConfig(config);

        CreateCa createCa = new CreateCa(ctx, caConfig);
        createCa.run();

        Assert.assertEquals("cn=signing.ca.example.com,ou=QA", ctx.getSigningCertificate().getSubject().toString());
        Assert.assertNotNull(ctx.getSigningPrivateKey());

        FileOutput fileOutput = ctx.getFileOutput();

        FileOutput.FileEntry fileEntry = fileOutput.getEntryByFileName("root-ca.pem");
        Assert.assertEquals("cn=root.ca.example.com,ou=QA", ((X509CertificateHolder) fileEntry.getEntries().get(0)).getSubject().toString());

        fileEntry = fileOutput.getEntryByFileName("signing-ca.pem");
        Assert.assertEquals("cn=signing.ca.example.com,ou=QA", ((X509CertificateHolder) fileEntry.getEntries().get(0)).getSubject().toString());

        Assert.assertNotNull(fileOutput.getEntryByFileName("root-ca-key.pem"));
        Assert.assertNotNull(fileOutput.getEntryByFileName("signing-ca-key.pem"));
    }
    
    @Test
    public void testWithIntermediateCertRSANoDefaults() throws ToolException {
        Context ctx = new Context();
        Config config = new Config();
        Config.Ca caConfig = new Config.Ca();
        Config.Ca.Certificate rootCertificateConfig = new Config.Ca.Certificate();
        Config.Ca.Certificate intermediateCertificateConfig = new Config.Ca.Certificate();
        Config.Defaults defaults = new Config.Defaults();
        defaults.setKeysize(1024);
        defaults.setEllipticCurve("secp256k1");
        defaults.setSignatureAlgorithm("SHA512withRSA");

        rootCertificateConfig.setFile("root-ca.pem");
        rootCertificateConfig.setPkPassword("secret");
        rootCertificateConfig.setValidityDays(3650);
        rootCertificateConfig.setDn("CN=root.ca.example.com,OU=QA");
        rootCertificateConfig.applyDefaults(defaults);

        intermediateCertificateConfig.setFile("signing-ca.pem");
        intermediateCertificateConfig.setPkPassword("secret");
        intermediateCertificateConfig.setKeysize(2048);
        intermediateCertificateConfig.setValidityDays(3650);
        intermediateCertificateConfig.setDn("CN=signing.ca.example.com,OU=QA");
        intermediateCertificateConfig.applyDefaults(defaults);

        caConfig.setRoot(rootCertificateConfig);
        caConfig.setIntermediate(intermediateCertificateConfig);

        config.setDefaults(defaults);
        caConfig.applyDefaults(defaults);
        config.setCa(caConfig);

        ctx.setConfig(config);

        CreateCa createCa = new CreateCa(ctx, caConfig);
        createCa.run();

        Assert.assertEquals("cn=signing.ca.example.com,ou=QA", ctx.getSigningCertificate().getSubject().toString());
        Assert.assertNotNull(ctx.getSigningPrivateKey());

        FileOutput fileOutput = ctx.getFileOutput();

        FileOutput.FileEntry fileEntry = fileOutput.getEntryByFileName("root-ca.pem");
        Assert.assertEquals("cn=root.ca.example.com,ou=QA", ((X509CertificateHolder) fileEntry.getEntries().get(0)).getSubject().toString());

        fileEntry = fileOutput.getEntryByFileName("signing-ca.pem");
        Assert.assertEquals("cn=signing.ca.example.com,ou=QA", ((X509CertificateHolder) fileEntry.getEntries().get(0)).getSubject().toString());

        Assert.assertNotNull(fileOutput.getEntryByFileName("root-ca-key.pem"));
        Assert.assertNotNull(fileOutput.getEntryByFileName("signing-ca-key.pem"));
    }
}
