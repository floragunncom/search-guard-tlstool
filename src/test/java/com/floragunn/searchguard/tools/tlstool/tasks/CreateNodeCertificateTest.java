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

import java.net.InetAddress;
import java.security.Security;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
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

		Assert.assertEquals("2:node99.example.com;2:*.node99.example.com;7:10.8.0.123;",
				getSubjectAlternativeNameInfo(cert));

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

	@Test
	public void testSplitEku() throws Exception {
		Context ctx = createContext(true);
		Config.Node nodeConfig = ctx.getConfig().getNodes().get(0);

		new CreateNodeCertificate(ctx, nodeConfig).run();

		FileOutput fileOutput = ctx.getFileOutput();

		Assert.assertNull(fileOutput.getEntryByFileName("test-node.pem"));
		Assert.assertNull(fileOutput.getEntryByFileName("test-node.key"));
		Assert.assertNotNull(fileOutput.getEntryByFileName("test-node_server.key"));
		Assert.assertNotNull(fileOutput.getEntryByFileName("test-node_client.key"));

		FileOutput.FileEntry serverEntry = fileOutput.getEntryByFileName("test-node_server.pem");
		X509CertificateHolder serverCert = (X509CertificateHolder) serverEntry.getEntries().get(0);
		Assert.assertEquals("cn=node99-server.example.com,ou=QA", serverCert.getSubject().toString());
		Assert.assertEquals(2, serverEntry.getEntries().size());
		assertEku(serverCert, KeyPurposeId.id_kp_serverAuth);

		FileOutput.FileEntry clientEntry = fileOutput.getEntryByFileName("test-node_client.pem");
		X509CertificateHolder clientCert = (X509CertificateHolder) clientEntry.getEntries().get(0);
		Assert.assertEquals("cn=node99-client.example.com,ou=QA", clientCert.getSubject().toString());
		Assert.assertEquals(2, clientEntry.getEntries().size());
		assertEku(clientCert, KeyPurposeId.id_kp_clientAuth);

		Assert.assertEquals("2:node99.example.com;2:*.node99.example.com;7:10.8.0.123;",
				getSubjectAlternativeNameInfo(serverCert));
		Assert.assertEquals(getSubjectAlternativeNameInfo(serverCert), getSubjectAlternativeNameInfo(clientCert));

		X509CertificateHolder httpCert = (X509CertificateHolder) fileOutput.getEntryByFileName("test-node_http.pem")
				.getEntries().get(0);
		Assert.assertEquals("cn=node99.example.com,ou=QA", httpCert.getSubject().toString());
		assertEku(httpCert, KeyPurposeId.id_kp_serverAuth);

		String snippet = getConfigSnippet(fileOutput);
		Assert.assertTrue(snippet, snippet.contains("searchguard.ssl.transport.server_pemcert_filepath: test-node_server.pem\n"));
		Assert.assertTrue(snippet, snippet.contains("searchguard.ssl.transport.server_pemkey_filepath: test-node_server.key\n"));
		Assert.assertTrue(snippet, snippet.contains("searchguard.ssl.transport.server_pemkey_password: secret\n"));
		Assert.assertTrue(snippet, snippet.contains("searchguard.ssl.transport.server_pemtrustedcas_filepath: root-ca.pem\n"));
		Assert.assertTrue(snippet, snippet.contains("searchguard.ssl.transport.client_pemcert_filepath: test-node_client.pem\n"));
		Assert.assertTrue(snippet, snippet.contains("searchguard.ssl.transport.client_pemkey_filepath: test-node_client.key\n"));
		Assert.assertTrue(snippet, snippet.contains("searchguard.ssl.transport.client_pemkey_password: secret\n"));
		Assert.assertTrue(snippet, snippet.contains("searchguard.ssl.transport.client_pemtrustedcas_filepath: root-ca.pem\n"));
		Assert.assertFalse(snippet, snippet.contains("searchguard.ssl.transport.pemcert_filepath"));
		Assert.assertFalse(snippet, snippet.contains("searchguard.ssl.transport.pemkey_filepath"));
		Assert.assertTrue(snippet, snippet.contains("searchguard.ssl.http.pemcert_filepath: test-node_http.pem\n"));
		Assert.assertTrue(snippet, snippet.contains("\"CN=node99-server.example.com,OU=QA\""));
		Assert.assertTrue(snippet, snippet.contains("\"CN=node99-client.example.com,OU=QA\""));
		Assert.assertFalse(snippet, snippet.contains("\"CN=node99.example.com,OU=QA\""));
	}

	@Test
	public void testSplitEkuExplicitDns() throws Exception {
		Context ctx = createContext(true);
		Config.Node nodeConfig = ctx.getConfig().getNodes().get(0);
		nodeConfig.setServerDn("CN=srv,OU=QA");
		nodeConfig.setClientDn("CN=cli,OU=QA");

		new CreateNodeCertificate(ctx, nodeConfig).run();

		FileOutput fileOutput = ctx.getFileOutput();

		Assert.assertEquals("cn=srv,ou=QA", ((X509CertificateHolder) fileOutput
				.getEntryByFileName("test-node_server.pem").getEntries().get(0)).getSubject().toString());
		Assert.assertEquals("cn=cli,ou=QA", ((X509CertificateHolder) fileOutput
				.getEntryByFileName("test-node_client.pem").getEntries().get(0)).getSubject().toString());

		String snippet = getConfigSnippet(fileOutput);
		Assert.assertTrue(snippet, snippet.contains("\"CN=srv,OU=QA\""));
		Assert.assertTrue(snippet, snippet.contains("\"CN=cli,OU=QA\""));
	}

	@Test
	public void testSplitEkuExplicitDnsWithoutDn() throws Exception {
		Context ctx = createContext(true);
		ctx.getConfig().getDefaults().setHttpsEnabled(false);
		Config.Node nodeConfig = ctx.getConfig().getNodes().get(0);
		nodeConfig.setDn(null);
		nodeConfig.setServerDn("CN=srv,OU=QA");
		nodeConfig.setClientDn("CN=cli,OU=QA");

		new CreateNodeCertificate(ctx, nodeConfig).run();

		String snippet = getConfigSnippet(ctx.getFileOutput());
		Assert.assertTrue(snippet, snippet.contains("\"CN=srv,OU=QA\""));
		Assert.assertTrue(snippet, snippet.contains("\"CN=cli,OU=QA\""));
		Assert.assertTrue(snippet, snippet.contains("searchguard.ssl.http.enabled: false\n"));
	}

	@Test
	public void testSplitEkuReuseTransportCertificatesForHttp() throws Exception {
		Context ctx = createContext(true);
		ctx.getConfig().getDefaults().setReuseTransportCertificatesForHttp(true);
		Config.Node nodeConfig = ctx.getConfig().getNodes().get(0);

		new CreateNodeCertificate(ctx, nodeConfig).run();

		FileOutput fileOutput = ctx.getFileOutput();

		Assert.assertNull(fileOutput.getEntryByFileName("test-node_http.pem"));
		Assert.assertNull(fileOutput.getEntryByFileName("test-node_http.key"));

		String snippet = getConfigSnippet(fileOutput);
		Assert.assertTrue(snippet, snippet.contains("searchguard.ssl.http.pemcert_filepath: test-node_server.pem\n"));
		Assert.assertTrue(snippet, snippet.contains("searchguard.ssl.http.pemkey_filepath: test-node_server.key\n"));
		Assert.assertTrue(snippet, snippet.contains("searchguard.ssl.http.pemkey_password: secret\n"));
		Assert.assertTrue(snippet, snippet.contains("searchguard.ssl.http.pemtrustedcas_filepath: root-ca.pem\n"));
	}

	@Test
	public void testSplitEkuOffKeepsSharedCertificate() throws Exception {
		Context ctx = createContext(false);
		Config.Node nodeConfig = ctx.getConfig().getNodes().get(0);

		new CreateNodeCertificate(ctx, nodeConfig).run();

		FileOutput fileOutput = ctx.getFileOutput();

		Assert.assertNull(fileOutput.getEntryByFileName("test-node_server.pem"));
		Assert.assertNull(fileOutput.getEntryByFileName("test-node_client.pem"));

		X509CertificateHolder transportCert = (X509CertificateHolder) fileOutput.getEntryByFileName("test-node.pem")
				.getEntries().get(0);
		Assert.assertEquals("cn=node99.example.com,ou=QA", transportCert.getSubject().toString());
		assertEku(transportCert, KeyPurposeId.id_kp_serverAuth, KeyPurposeId.id_kp_clientAuth);

		X509CertificateHolder httpCert = (X509CertificateHolder) fileOutput.getEntryByFileName("test-node_http.pem")
				.getEntries().get(0);
		assertEku(httpCert, KeyPurposeId.id_kp_serverAuth, KeyPurposeId.id_kp_clientAuth);

		String snippet = getConfigSnippet(fileOutput);
		Assert.assertTrue(snippet, snippet.contains("searchguard.ssl.transport.pemcert_filepath: test-node.pem\n"));
		Assert.assertTrue(snippet, snippet.contains("searchguard.ssl.transport.pemkey_filepath: test-node.key\n"));
		Assert.assertFalse(snippet, snippet.contains("server_pem"));
		Assert.assertFalse(snippet, snippet.contains("client_pem"));
		Assert.assertTrue(snippet, snippet.contains("\"CN=node99.example.com,OU=QA\""));
		Assert.assertFalse(snippet, snippet.contains("node99-server"));
	}

	private Context createContext(boolean splitEku) throws ToolException {
		Context ctx = new Context();
		Config config = new Config();
		Config.Ca caConfig = new Config.Ca();
		Config.Ca.Certificate rootCertificateConfig = new Config.Ca.Certificate();
		Config.Ca.Certificate intermediateCertificateConfig = new Config.Ca.Certificate();
		Config.Defaults defaults = new Config.Defaults();
		Config.Node nodeConfig = new Config.Node();
		Config.Client adminConfig = new Config.Client();

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
		nodeConfig.setPkPassword("secret");

		adminConfig.setName("admin");
		adminConfig.setDn("CN=admin,OU=QA");
		adminConfig.setAdmin(true);

		defaults.setHttpsEnabled(true);
		defaults.setSplitEku(splitEku);

		caConfig.setRoot(rootCertificateConfig);
		caConfig.setIntermediate(intermediateCertificateConfig);

		config.setDefaults(defaults);
		config.setCa(caConfig);
		config.setNodes(Collections.singletonList(nodeConfig));
		config.setClients(Collections.singletonList(adminConfig));

		ctx.setConfig(config);

		new LoadCa(ctx, caConfig).run();

		return ctx;
	}

	private String getConfigSnippet(FileOutput fileOutput) {
		return (String) fileOutput.getEntryByFileName("test-node_elasticsearch_config_snippet.yml").getEntries().get(1);
	}

	static void assertEku(X509CertificateHolder cert, KeyPurposeId... expected) {
		ExtendedKeyUsage eku = ExtendedKeyUsage.fromExtensions(cert.getExtensions());
		Assert.assertNotNull("No EKU extension", eku);
		Assert.assertEquals(new HashSet<>(Arrays.asList(expected)), new HashSet<>(Arrays.asList(eku.getUsages())));
	}

	private String getSubjectAlternativeNameInfo(X509CertificateHolder cert) {

		StringBuilder result = new StringBuilder("");

		for (GeneralName generalName : GeneralNames
				.fromExtensions(cert.getExtensions(), Extension.subjectAlternativeName).getNames()) {
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
