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
