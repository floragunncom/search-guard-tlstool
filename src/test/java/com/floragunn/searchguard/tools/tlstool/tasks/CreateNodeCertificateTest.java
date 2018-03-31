package com.floragunn.searchguard.tools.tlstool.tasks;

import java.net.InetAddress;
import java.security.Security;
import java.util.Collections;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import com.floragunn.searchguard.tools.tlstool.Config;
import com.floragunn.searchguard.tools.tlstool.Context;
import com.floragunn.searchguard.tools.tlstool.FileOutput;
import com.floragunn.searchguard.tools.tlstool.ToolException;
import com.google.common.collect.Lists;

public class CreateNodeCertificateTest {
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
		Config.Node nodeConfig = new Config.Node();

		rootCertificateConfig.setFile(TestResources.getAbsolutePath("with-intermediate/root-ca.pem"));
		rootCertificateConfig.setPkPassword("secret");

		intermediateCertificateConfig.setFile(TestResources.getAbsolutePath("with-intermediate/signing-ca.pem"));
		intermediateCertificateConfig.setPkPassword("secret");

		nodeConfig.setName("test-node");
		nodeConfig.setDn("CN=node99.example.com,OU=QA");
		nodeConfig.setDns(Lists.newArrayList("node99.example.com", "*.node99.example.com"));
		nodeConfig.setIp(Lists.newArrayList("10.8.0.123"));
		nodeConfig.setKeysize(2048);
		nodeConfig.setValidityDays(10);
		nodeConfig.setOid(Lists.newArrayList("3.1.4"));
		nodeConfig.setPkPassword("secret");

		defaults.setHttpsEnabled(true);

		caConfig.setRoot(rootCertificateConfig);
		caConfig.setIntermediate(intermediateCertificateConfig);

		config.setDefaults(defaults);
		config.setCa(caConfig);
		config.setNodes(Collections.singletonList(nodeConfig));

		ctx.setConfig(config);

		LoadCa loadCa = new LoadCa(ctx, caConfig);
		loadCa.run();

		CreateNodeCertificate createNodeCertificate = new CreateNodeCertificate(ctx, nodeConfig);
		createNodeCertificate.run();

		FileOutput fileOutput = ctx.getFileOutput();

		FileOutput.FileEntry fileEntry = fileOutput.getEntryByFileName("test-node.pem");
		Assert.assertEquals("cn=node99.example.com,ou=QA",
				((X509CertificateHolder) fileEntry.getEntries().get(0)).getSubject().toString());
		Assert.assertEquals("DC=com,DC=example,O=Example Com\\, Inc.,OU=CA,CN=signing.ca.example.com",
				((X509CertificateHolder) fileEntry.getEntries().get(1)).getSubject().toString());
		Assert.assertEquals(2, fileEntry.getEntries().size());

		Assert.assertNotNull(fileOutput.getEntryByFileName("test-node.key"));
		
		X509CertificateHolder cert = (X509CertificateHolder) fileEntry.getEntries().get(0);
		
		Assert.assertEquals("2:node99.example.com;2:*.node99.example.com;7:10.8.0.123;", getSubjectAlternativeNameInfo(cert));
		
		
		fileEntry = fileOutput.getEntryByFileName("test-node_http.pem");
		Assert.assertEquals("cn=node99.example.com,ou=QA",
				((X509CertificateHolder) fileEntry.getEntries().get(0)).getSubject().toString());
		Assert.assertEquals("DC=com,DC=example,O=Example Com\\, Inc.,OU=CA,CN=signing.ca.example.com",
				((X509CertificateHolder) fileEntry.getEntries().get(1)).getSubject().toString());
		Assert.assertEquals(2, fileEntry.getEntries().size());

		Assert.assertNotNull(fileOutput.getEntryByFileName("test-node_http.key"));
	}

	@Test
	public void testWithoutIntermediateCert() throws Exception {
		Context ctx = new Context();
		Config config = new Config();
		Config.Ca caConfig = new Config.Ca();
		Config.Ca.Certificate rootCertificateConfig = new Config.Ca.Certificate();
		Config.Defaults defaults = new Config.Defaults();
		Config.Node nodeConfig = new Config.Node();

		rootCertificateConfig.setFile(TestResources.getAbsolutePath("without-intermediate/root-ca.pem"));
		rootCertificateConfig.setPkPassword("secret");

		nodeConfig.setName("test-node");
		nodeConfig.setDn("CN=node99.example.com,OU=QA");
		nodeConfig.setDns(Lists.newArrayList("node99.example.com", "*.node99.example.com"));
		nodeConfig.setIp(Lists.newArrayList("10.8.0.123"));
		nodeConfig.setKeysize(2048);
		nodeConfig.setValidityDays(10);
		nodeConfig.setOid(Lists.newArrayList("3.1.4"));
		nodeConfig.setPkPassword("secret");

		defaults.setHttpsEnabled(true);

		caConfig.setRoot(rootCertificateConfig);

		config.setDefaults(defaults);
		config.setCa(caConfig);
		config.setNodes(Collections.singletonList(nodeConfig));

		ctx.setConfig(config);

		LoadCa loadCa = new LoadCa(ctx, caConfig);
		loadCa.run();

		CreateNodeCertificate createNodeCertificate = new CreateNodeCertificate(ctx, nodeConfig);
		createNodeCertificate.run();

		FileOutput fileOutput = ctx.getFileOutput();

		FileOutput.FileEntry fileEntry = fileOutput.getEntryByFileName("test-node.pem");
		Assert.assertEquals("cn=node99.example.com,ou=QA",
				((X509CertificateHolder) fileEntry.getEntries().get(0)).getSubject().toString());
		Assert.assertEquals(1, fileEntry.getEntries().size());

		Assert.assertNotNull(fileOutput.getEntryByFileName("test-node.key"));

		fileEntry = fileOutput.getEntryByFileName("test-node_http.pem");
		Assert.assertEquals("cn=node99.example.com,ou=QA",
				((X509CertificateHolder) fileEntry.getEntries().get(0)).getSubject().toString());
		Assert.assertEquals(1, fileEntry.getEntries().size());

		Assert.assertNotNull(fileOutput.getEntryByFileName("test-node_http.key"));
	}

	private String getSubjectAlternativeNameInfo(X509CertificateHolder cert) {

		StringBuilder result = new StringBuilder("");
		
		for (GeneralName generalName : GeneralNames.fromExtensions(cert.getExtensions(), Extension.subjectAlternativeName).getNames()) {
			
			result.append(generalName.getTagNo()).append(":").append(generalNameValueToString(generalName)).append(";");
		}

		return result.toString();
	}

	private String generalNameValueToString(GeneralName generalName) {
		try {
			switch (generalName.getTagNo()) {
			case GeneralName.ediPartyName:
			case GeneralName.x400Address:
			case GeneralName.otherName:
				return String.valueOf(generalName.getName().toASN1Primitive());
			case GeneralName.directoryName:
				return String.valueOf(X500Name.getInstance(generalName.getName()));
			case GeneralName.dNSName:
			case GeneralName.rfc822Name:
			case GeneralName.uniformResourceIdentifier:
				return String.valueOf(((ASN1String) generalName.getName()).getString());
			case GeneralName.registeredID:
				return String.valueOf(ASN1ObjectIdentifier.getInstance(generalName.getName()).getId());
			case GeneralName.iPAddress:
				return String.valueOf(InetAddress
						.getByAddress(DEROctetString.getInstance(generalName.getName()).getOctets()).getHostAddress());
			default:
				return String.valueOf(generalName.getName());
			}
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
}
