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
	private final Config.Node nodeConfig;
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
			nodeResultConfig.setAuthczAdminDn(collectAdminDn());

			if (!Strings.isNullOrEmpty(ctx.getConfig().getDefaults().getNodeOid())) {
				nodeResultConfig.setCertOid(ctx.getConfig().getDefaults().getNodeOid());
			} else {
				nodeResultConfig.setNodesDn(collectFilteredNodesDn());
			}

			nodeResultConfig.setTransportEnforceHostnameVerification(ctx.getConfig().getDefaults().isVerifyHostnames());
			nodeResultConfig.setTransportResolveDns(ctx.getConfig().getDefaults().isResolveHostnames());

			ObjectMapper objectMapper = new ObjectMapper(
					new YAMLFactory().disable(YAMLGenerator.Feature.WRITE_DOC_START_MARKER)
							.enable(YAMLGenerator.Feature.MINIMIZE_QUOTES));

			return objectMapper.writeValueAsString(nodeResultConfig);
		} catch (JsonProcessingException e) {
			throw new RuntimeException(e);
		}
	}

	private List<String> collectFilteredNodesDn() throws ToolException {
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

	private List<String> collectNodesDn() throws ToolException {
		if (ctx.getConfig().getNodes() == null) {
			return Collections.emptyList();
		}

		List<String> result = new ArrayList<>(ctx.getConfig().getNodes().size());

		for (Config.Node node : ctx.getConfig().getNodes()) {
			if (node.getDn() != null) {
				result.add(sanitizeDn(node.getDn(), "node"));
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

				result.add(sanitizeDn(client.getDn(), "admin"));
			}
		}

		return result;
	}
}
