package com.floragunn.searchguard.tools.tlstool;

import org.junit.Assert;
import org.junit.Test;

public class ConfigNodeDnTest {

	@Test
	public void testDeriveDnRewritesFirstCnLabel() {
		Assert.assertEquals("CN=node1-server.example.com,OU=Ops,O=Example Com\\, Inc.,DC=example,DC=com",
				Config.Node.deriveDn("CN=node1.example.com,OU=Ops,O=Example Com\\, Inc.,DC=example,DC=com", "-server"));
		Assert.assertEquals("CN=node1-client.example.com,OU=Ops,O=Example Com\\, Inc.,DC=example,DC=com",
				Config.Node.deriveDn("CN=node1.example.com,OU=Ops,O=Example Com\\, Inc.,DC=example,DC=com", "-client"));
	}

	@Test
	public void testDeriveDnWithoutDotInCn() {
		Assert.assertEquals("CN=node1-server,OU=Ops", Config.Node.deriveDn("CN=node1,OU=Ops", "-server"));
	}

	@Test
	public void testDeriveDnCnNotFirst() {
		Assert.assertEquals("OU=Ops,CN=node1-client.example.com", Config.Node.deriveDn("OU=Ops,CN=node1.example.com", "-client"));
	}

	@Test
	public void testDeriveDnKeepsAttributesUnknownToBcStyle() {
		Assert.assertEquals("CN=node1-server.example.com,SN=v,TITLE=t,O=x",
				Config.Node.deriveDn("cn=node1.example.com,sn=v,title=t,o=x", "-server"));
	}

	@Test
	public void testDeriveDnMultiValuedRdn() {
		// attributes inside a multi-valued RDN are DER-sorted by BouncyCastle
		Assert.assertEquals("OU=b+CN=a-server,O=x", Config.Node.deriveDn("CN=a+OU=b,O=x", "-server"));
	}

	@Test
	public void testDeriveDnEscaping() {
		Assert.assertEquals("CN=a\\+b-server.c,O=x\\, y\\\"z", Config.Node.deriveDn("CN=a\\+b.c,O=x\\, y\\\"z", "-server"));
	}

	@Test(expected = IllegalArgumentException.class)
	public void testDeriveDnWithoutCn() {
		Config.Node.deriveDn("OU=Ops,O=Example", "-server");
	}

	@Test(expected = IllegalArgumentException.class)
	public void testDeriveDnNull() {
		Config.Node.deriveDn(null, "-server");
	}

	@Test
	public void testResolveDnsPreferExplicitValues() {
		Config.Node node = new Config.Node();
		node.setDn("CN=node1.example.com,OU=Ops");

		Assert.assertEquals("CN=node1-server.example.com,OU=Ops", node.resolveServerDn());
		Assert.assertEquals("CN=node1-client.example.com,OU=Ops", node.resolveClientDn());

		node.setServerDn("CN=srv,OU=Ops");
		node.setClientDn("CN=cli,OU=Ops");

		Assert.assertEquals("CN=srv,OU=Ops", node.resolveServerDn());
		Assert.assertEquals("CN=cli,OU=Ops", node.resolveClientDn());
	}
}
