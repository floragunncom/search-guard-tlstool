package com.floragunn.searchguard.tools.tlstool.tasks;

import java.security.Security;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;

import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import com.floragunn.searchguard.tools.tlstool.Config;
import com.floragunn.searchguard.tools.tlstool.Context;
import com.floragunn.searchguard.tools.tlstool.FileOutput;
import com.google.common.collect.Lists;

public class CreateNodeCsrTest {
	@BeforeClass
	public static void init() {
		Security.addProvider(new BouncyCastleProvider());
	}

	@Test
	public void testSplitEku() throws Exception {
		Context ctx = createContext(true);
		Config.Node nodeConfig = ctx.getConfig().getNodes().get(0);

		new CreateNodeCsr(ctx, nodeConfig).run();

		FileOutput fileOutput = ctx.getFileOutput();

		Assert.assertNull(fileOutput.getEntryByFileName("test-node.csr"));
		Assert.assertNull(fileOutput.getEntryByFileName("test-node.key"));
		Assert.assertNotNull(fileOutput.getEntryByFileName("test-node_server.key"));
		Assert.assertNotNull(fileOutput.getEntryByFileName("test-node_client.key"));

		PKCS10CertificationRequest serverCsr = (PKCS10CertificationRequest) fileOutput
				.getEntryByFileName("test-node_server.csr").getEntries().get(0);
		Assert.assertEquals("cn=node99-server.example.com,ou=QA", serverCsr.getSubject().toString());
		assertEku(serverCsr, KeyPurposeId.id_kp_serverAuth);

		PKCS10CertificationRequest clientCsr = (PKCS10CertificationRequest) fileOutput
				.getEntryByFileName("test-node_client.csr").getEntries().get(0);
		Assert.assertEquals("cn=node99-client.example.com,ou=QA", clientCsr.getSubject().toString());
		assertEku(clientCsr, KeyPurposeId.id_kp_clientAuth);

		PKCS10CertificationRequest httpCsr = (PKCS10CertificationRequest) fileOutput
				.getEntryByFileName("test-node_http.csr").getEntries().get(0);
		Assert.assertEquals("cn=node99.example.com,ou=QA", httpCsr.getSubject().toString());
		assertEku(httpCsr, KeyPurposeId.id_kp_serverAuth);

		FileOutput.FileEntry snippetEntry = fileOutput.getEntryByFileName("test-node_elasticsearch_config_snippet.yml");
		String comment = (String) snippetEntry.getEntries().get(0);
		String snippet = (String) snippetEntry.getEntries().get(1);

		Assert.assertTrue(comment, comment.contains("test-node_server.csr, test-node_client.csr, test-node_http.csr"));
		Assert.assertTrue(snippet, snippet.contains("searchguard.ssl.transport.server_pemkey_filepath: test-node_server.key\n"));
		Assert.assertTrue(snippet, snippet.contains("searchguard.ssl.transport.client_pemkey_filepath: test-node_client.key\n"));
		Assert.assertTrue(snippet, snippet.contains("searchguard.ssl.transport.server_pemcert_filepath: <path to transport server certificate"));
		Assert.assertTrue(snippet, snippet.contains("searchguard.ssl.transport.client_pemcert_filepath: <path to transport client certificate"));
		Assert.assertFalse(snippet, snippet.contains("searchguard.ssl.transport.pemkey_filepath"));
		Assert.assertTrue(snippet, snippet.contains("\"CN=node99-server.example.com,OU=QA\""));
		Assert.assertTrue(snippet, snippet.contains("\"CN=node99-client.example.com,OU=QA\""));
	}

	@Test
	public void testSplitEkuOff() throws Exception {
		Context ctx = createContext(false);
		Config.Node nodeConfig = ctx.getConfig().getNodes().get(0);

		new CreateNodeCsr(ctx, nodeConfig).run();

		FileOutput fileOutput = ctx.getFileOutput();

		Assert.assertNull(fileOutput.getEntryByFileName("test-node_server.csr"));
		Assert.assertNull(fileOutput.getEntryByFileName("test-node_client.csr"));

		PKCS10CertificationRequest transportCsr = (PKCS10CertificationRequest) fileOutput
				.getEntryByFileName("test-node.csr").getEntries().get(0);
		Assert.assertEquals("cn=node99.example.com,ou=QA", transportCsr.getSubject().toString());
		assertEku(transportCsr, KeyPurposeId.id_kp_serverAuth, KeyPurposeId.id_kp_clientAuth);

		FileOutput.FileEntry snippetEntry = fileOutput.getEntryByFileName("test-node_elasticsearch_config_snippet.yml");
		String comment = (String) snippetEntry.getEntries().get(0);
		String snippet = (String) snippetEntry.getEntries().get(1);

		Assert.assertTrue(comment, comment.contains("file test-node.csr, test-node_http.csr to your PKI"));
		Assert.assertTrue(snippet, snippet.contains("searchguard.ssl.transport.pemkey_filepath: test-node.key\n"));
		Assert.assertFalse(snippet, snippet.contains("server_pem"));
	}

	private Context createContext(boolean splitEku) {
		Context ctx = new Context();
		Config config = new Config();
		Config.Defaults defaults = new Config.Defaults();
		Config.Node nodeConfig = new Config.Node();
		Config.Client adminConfig = new Config.Client();

		nodeConfig.setName("test-node");
		nodeConfig.setDn("CN=node99.example.com,OU=QA");
		nodeConfig.setDns(Lists.newArrayList("node99.example.com"));
		nodeConfig.setKeysize(2048);
		nodeConfig.setValidityDays(10);
		nodeConfig.setPkPassword("secret");

		adminConfig.setName("admin");
		adminConfig.setDn("CN=admin,OU=QA");
		adminConfig.setAdmin(true);

		defaults.setHttpsEnabled(true);
		defaults.setSplitEku(splitEku);

		config.setDefaults(defaults);
		config.setNodes(Collections.singletonList(nodeConfig));
		config.setClients(Collections.singletonList(adminConfig));

		ctx.setConfig(config);

		return ctx;
	}

	private static void assertEku(PKCS10CertificationRequest csr, KeyPurposeId... expected) {
		ExtendedKeyUsage eku = ExtendedKeyUsage.fromExtensions(csr.getRequestedExtensions());
		Assert.assertNotNull("No EKU extension", eku);
		Assert.assertEquals(new HashSet<>(Arrays.asList(expected)), new HashSet<>(Arrays.asList(eku.getUsages())));
	}
}
