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

import java.util.List;

import com.floragunn.searchguard.tools.tlstool.Config;
import com.floragunn.searchguard.tools.tlstool.Context;
import com.floragunn.searchguard.tools.tlstool.ToolException;

public class Validate extends Task {

	public Validate(Context ctx) {
		super(ctx);
	}

	@Override
	public void run() throws ToolException {
		validateAdminCert();
		validateSplitEku();
	}

	private void validateSplitEku() throws ToolException {
		Config.Defaults defaults = ctx.getConfig().getDefaults();
		List<Config.Node> nodes = ctx.getConfig().getNodes();

		if (defaults == null || nodes == null) {
			return;
		}

		for (Config.Node node : nodes) {
			String nodeName = node.getName() != null ? node.getName() : String.valueOf(node.getDn());

			if (!defaults.isSplitEku()) {
				if (node.getServerDn() != null || node.getClientDn() != null) {
					throw new ToolException("serverDn or clientDn is specified for node " + nodeName
							+ ", but defaults.splitEku is not enabled. Please set splitEku: true or remove these settings.");
				}

				continue;
			}

			String serverDn;
			String clientDn;

			try {
				serverDn = sanitizeDn(node.resolveServerDn(), "node server");
				clientDn = sanitizeDn(node.resolveClientDn(), "node client");
			} catch (IllegalArgumentException e) {
				throw new ToolException("Cannot determine server and client DN for node " + nodeName + ": " + e.getMessage()
						+ ". Please specify serverDn and clientDn for this node.", e);
			}

			if (serverDn.equalsIgnoreCase(clientDn)) {
				throw new ToolException("The server DN and the client DN of node " + nodeName
						+ " must differ when splitEku is enabled: " + serverDn);
			}
		}
	}

	private void validateAdminCert() throws ToolException {
		if (ctx.getConfig().getClients() == null) {
			return;
		}

		int adminCount = 0;

		for (Config.Client client : ctx.getConfig().getClients()) {
			if (client.isAdmin()) {
				adminCount++;
			}
		}

		if (adminCount == 0) {
			throw new ToolException(
					"No client certificate was elected as admin certificate. If no admin certificate is present, the ES cluster cannot be used. Please specify admin: true for at least one client certificate. In order to generate the certificates anyway, specify the -f flag.");
		}

	}
}
