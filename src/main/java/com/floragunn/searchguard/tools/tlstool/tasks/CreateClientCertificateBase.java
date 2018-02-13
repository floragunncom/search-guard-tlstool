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

import com.floragunn.searchguard.tools.tlstool.Config;
import com.floragunn.searchguard.tools.tlstool.Context;

public abstract class CreateClientCertificateBase extends Task {
	protected final Config.Client clientConfig;
	protected File privateKeyFile;

	public CreateClientCertificateBase(Context ctx, Config.Client clientConfig) {
		super(ctx);
		this.clientConfig = clientConfig;
	}
	
	protected String createPasswordInfo(File privateKeyFile, String privateKeyPassword) {
		return clientConfig.getDn() + " Password: " + privateKeyPassword + "\n";
	}

	protected String createReadme() {
		return "Client certificates are used to authenticate REST clients against your authentication backend.\n"
				+ "Thus, the users represented by the client certificates must be also present in your authentication backend.\n\n"
				+ "See http://docs.search-guard.com/latest/client-certificate-auth for more on this topic.\n\n\n";
	}

}
