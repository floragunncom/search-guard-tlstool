package com.floragunn.searchguard.tools.tlstool.tasks;

import java.util.Collections;

import org.junit.Assert;
import org.junit.Test;

import com.floragunn.searchguard.tools.tlstool.Config;
import com.floragunn.searchguard.tools.tlstool.Context;
import com.floragunn.searchguard.tools.tlstool.ToolException;

public class ValidateTest {

	@Test
	public void testSplitEkuWithDerivedDns() throws Exception {
		new Validate(createContext(true, "CN=node1.example.com,OU=Ops")).run();
	}

	@Test
	public void testSplitEkuOffWithoutRoleDns() throws Exception {
		new Validate(createContext(false, "CN=node1.example.com,OU=Ops")).run();
	}

	@Test
	public void testSplitEkuWithIdenticalDns() {
		Context ctx = createContext(true, "CN=node1.example.com,OU=Ops");
		Config.Node node = ctx.getConfig().getNodes().get(0);
		node.setServerDn("CN=same,OU=Ops");
		node.setClientDn("cn=same, ou=Ops");

		try {
			new Validate(ctx).run();
			Assert.fail("Expected ToolException");
		} catch (ToolException e) {
			Assert.assertTrue(e.getMessage(), e.getMessage().contains("must differ"));
		}
	}

	@Test
	public void testRoleDnsWithoutSplitEku() {
		Context ctx = createContext(false, "CN=node1.example.com,OU=Ops");
		ctx.getConfig().getNodes().get(0).setServerDn("CN=srv,OU=Ops");

		try {
			new Validate(ctx).run();
			Assert.fail("Expected ToolException");
		} catch (ToolException e) {
			Assert.assertTrue(e.getMessage(), e.getMessage().contains("splitEku"));
		}
	}

	@Test
	public void testSplitEkuWithDnWithoutCn() {
		Context ctx = createContext(true, "OU=Ops,O=Example");

		try {
			new Validate(ctx).run();
			Assert.fail("Expected ToolException");
		} catch (ToolException e) {
			Assert.assertTrue(e.getMessage(), e.getMessage().contains("does not contain a CN"));
		}
	}

	private Context createContext(boolean splitEku, String nodeDn) {
		Context ctx = new Context();
		Config config = new Config();
		Config.Defaults defaults = new Config.Defaults();
		Config.Node nodeConfig = new Config.Node();
		Config.Client adminConfig = new Config.Client();

		nodeConfig.setName("node1");
		nodeConfig.setDn(nodeDn);

		adminConfig.setName("admin");
		adminConfig.setDn("CN=admin,OU=Ops");
		adminConfig.setAdmin(true);

		defaults.setSplitEku(splitEku);

		config.setDefaults(defaults);
		config.setNodes(Collections.singletonList(nodeConfig));
		config.setClients(Collections.singletonList(adminConfig));

		ctx.setConfig(config);

		return ctx;
	}
}
