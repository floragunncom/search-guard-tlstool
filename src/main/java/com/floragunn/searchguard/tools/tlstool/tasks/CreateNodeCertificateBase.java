package com.floragunn.searchguard.tools.tlstool.tasks;

import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.x509.GeneralName;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.fasterxml.jackson.dataformat.yaml.YAMLGenerator;
import com.floragunn.searchguard.support.WildcardMatcher;
import com.floragunn.searchguard.tools.tlstool.Config;
import com.floragunn.searchguard.tools.tlstool.Context;
import com.floragunn.searchguard.tools.tlstool.ToolException;
import com.floragunn.searchguard.tools.util.EsNodeConfig;
import com.google.common.base.Strings;

public abstract class CreateNodeCertificateBase extends Task {
	private Config.Node nodeConfig;
	protected final EsNodeConfig nodeResultConfig = new EsNodeConfig();
	protected File privateKeyFile;
	protected File configSnippetFile;
	protected File httpPrivateKeyFile;

	public CreateNodeCertificateBase(Context ctx, Config.Node nodeConfig) {
		super(ctx);
		this.nodeConfig = nodeConfig;
	}

	protected ASN1Encodable[] createSubjectAlternativeNameList(boolean includeOid) {
		List<ASN1Encodable> subjectAlternativeNameList = new ArrayList<ASN1Encodable>();

		if (includeOid && !Strings.isNullOrEmpty(ctx.getConfig().getDefaults().getNodeOid())) {
			subjectAlternativeNameList
					.add(new GeneralName(GeneralName.registeredID, ctx.getConfig().getDefaults().getNodeOid()));
		}

		if (nodeConfig.getDns() != null) {
			for (String dnsName : nodeConfig.getDns()) {
				subjectAlternativeNameList.add(new GeneralName(GeneralName.dNSName, dnsName));
			}
		}

		if (nodeConfig.getIp() != null) {
			for (String ip : nodeConfig.getIp()) {
				subjectAlternativeNameList.add(new GeneralName(GeneralName.iPAddress, ip));
			}
		}

		return subjectAlternativeNameList.toArray(new ASN1Encodable[subjectAlternativeNameList.size()]);
	}

	protected String getNodeFileName(Config.Node node) {
		if (node.getName() != null) {
			return node.getName();
		}

		if (node.getDns() != null && node.getDns().size() > 0) {
			return node.getDns().get(0);
		}

		if (node.getDn() != null) {
			String name = getSimpleNameFromDn(node.getDn());

			if (name != null) {
				return name;
			}
		}

		return "node" + (ctx.getConfig().getNodes().indexOf(node) + 1);
	}

	protected String createConfigSnippet() throws ToolException {

		try {

			nodeResultConfig.setNodesDn(collectFilteredNodesDn());
			nodeResultConfig.setAuthczAdminDn(collectAdminDn());

			if (ctx.getConfig().getDefaults().getNodeOid() != null) {
				nodeResultConfig.setCertOid(ctx.getConfig().getDefaults().getNodeOid());
			}

			ObjectMapper objectMapper = new ObjectMapper(
					new YAMLFactory().disable(YAMLGenerator.Feature.WRITE_DOC_START_MARKER)
							.enable(YAMLGenerator.Feature.MINIMIZE_QUOTES));

			return objectMapper.writeValueAsString(nodeResultConfig);
		} catch (JsonProcessingException e) {
			throw new RuntimeException(e);
		}
	}

	private List<String> collectFilteredNodesDn() {

		List<String> preconfiguredNodesDn = ctx.getConfig().getDefaults().getNodesDn();

		if (preconfiguredNodesDn != null) {
			List<String> result = new ArrayList<>(ctx.getConfig().getDefaults().getNodesDn());

			for (String dn : collectNodesDn()) {
				if (!WildcardMatcher.matchAny(preconfiguredNodesDn, dn)) {
					result.add(dn);
				}
			}

			return result;

		} else {
			return collectNodesDn();
		}
	}

	private List<String> collectNodesDn() {
		if (ctx.getConfig().getNodes() == null) {
			return Collections.emptyList();
		}

		List<String> result = new ArrayList<>(ctx.getConfig().getNodes().size());

		for (Config.Node node : ctx.getConfig().getNodes()) {
			if (node.getDn() != null) {
				result.add(node.getDn());
			}
		}

		return result;
	}

	private List<String> collectAdminDn() throws ToolException {
		if (ctx.getConfig().getClients() == null) {
			return Collections.emptyList();
		}

		List<String> result = new ArrayList<>(ctx.getConfig().getClients().size());

		for (Config.Client client : ctx.getConfig().getClients()) {
			if (client.isAdmin()) {
				if (Strings.isNullOrEmpty(client.getDn())) {
					throw new ToolException("No dn specified for admin client " + client);
				}

				result.add(client.getDn());
			}
		}

		return result;
	}
}
