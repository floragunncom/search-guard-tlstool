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
