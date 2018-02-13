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

package com.floragunn.searchguard.tools.tlstool;

import java.io.File;
import java.io.IOException;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.config.Configurator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.floragunn.searchguard.tools.tlstool.tasks.CreateCa;
import com.floragunn.searchguard.tools.tlstool.tasks.CreateClientCertificate;
import com.floragunn.searchguard.tools.tlstool.tasks.CreateClientCsr;
import com.floragunn.searchguard.tools.tlstool.tasks.CreateNodeCertificate;
import com.floragunn.searchguard.tools.tlstool.tasks.CreateNodeCsr;
import com.floragunn.searchguard.tools.tlstool.tasks.LoadCa;
import com.floragunn.searchguard.tools.tlstool.tasks.Task;
import com.floragunn.searchguard.tools.tlstool.tasks.Validate;
import com.google.common.base.Strings;

public class SearchGuardTlsTool {

	private static final ObjectMapper objectMapper = new ObjectMapper(new YAMLFactory());
	private static final Provider securityProvider = new BouncyCastleProvider();
	private static final Logger log = LogManager.getLogger(SearchGuardTlsTool.class);
	private static Options options;

	public static void main(String[] args) {
		Security.addProvider(securityProvider);
		objectMapper.configure(DeserializationFeature.ACCEPT_SINGLE_VALUE_AS_ARRAY, true);

		try {
			new SearchGuardTlsTool(parseOptions(args)).run();
		} catch (ToolException e) {
			log.error(e.getMessage());
			log.info("No files have been written");
			log.debug("Exception: ", e);
			System.exit(1);
		}
	}

	private static CommandLine parseOptions(String[] args) {
		options = new Options();
		options.addOption(Option.builder("ca").longOpt("create-ca").desc("Create a new certificate authority").build());
		options.addOption(Option.builder("crt").longOpt("create-cert")
				.desc("Create certificates using an existing or newly created local certificate authority").build());
		options.addOption(
				Option.builder("csr").longOpt("create-csr").desc("Create certificate signing requests").build());

		options.addOption(Option.builder("c").longOpt("config").hasArg().desc("Path to the config file").build());
		options.addOption(Option.builder("t").longOpt("target").hasArg().desc("Path to the target directory").build());
		options.addOption(Option.builder("o").longOpt("overwrite").desc("Overwrite existing files").build());

		options.addOption(Option.builder("v").longOpt("verbose").desc("Enable detailed output").build());
		options.addOption(Option.builder("f").longOpt("force")
				.desc("Force certificate generation despite of validation errors").build());

		try {

			CommandLineParser parser = new DefaultParser();
			CommandLine line = parser.parse(options, args);

			return line;
		} catch (ParseException e) {
			new HelpFormatter().printHelp("sgtlstool.sh", options, true);
			System.exit(1);
			return null;
		}
	}

	private CommandLine commandLine;

	SearchGuardTlsTool(CommandLine commandLine) {
		this.commandLine = commandLine;
	}

	private Config getConfig() throws ToolException {
		try {
			String configOptionValue = commandLine.getOptionValue("config");

			if (Strings.isNullOrEmpty(configOptionValue)) {
				throw new ToolException(
						"No config specified. In order to use this tool, you always need to specify a config file using the -c option. To create a config file, copy the file config/template.yml and edit it to match your needs.");
			}

			File configFile = new File(configOptionValue);

			if (!configFile.exists()) {
				throw new ToolException("Config file does not exist: " + configFile);
			}

			Config config = objectMapper.readValue(configFile, Config.class);

			config.applyDefaults();

			return config;
		} catch (IOException e) {
			throw new ToolException(e);
		}
	}

	private void run() throws ToolException {
		if (!commandLine.hasOption("ca") && !commandLine.hasOption("crt") && !commandLine.hasOption("csr")) {
			System.out.println(
					"In order to use sgtlstool, you have to use at least one of these parameters:\n\n--create-ca - Creates a new CA\n--create-cert - Creates new certificates\n--create-csr - Creates certificate signing requests.\n");

			if (!commandLine.hasOption("c")) {
				System.out.println(
						"Furthermore, you need to specify a config file using the -c option. To create a config file, copy the file config/template.yml and edit it to match your needs.\n");
			}
			new HelpFormatter().printHelp("sgtlstool.sh", options, true);

			System.exit(1);
		}

		Config config = getConfig();

		Context ctx = new Context();
		ctx.setConfig(config);
		ctx.setSecurityProvider(securityProvider);

		List<Task> tasks = new ArrayList<>();

		if (commandLine.hasOption("v")) {
			Configurator.setRootLevel(Level.DEBUG);
			Configurator.setLevel("STDOUT", Level.DEBUG);
		}

		File targetDirectory = new File(commandLine.getOptionValue("t", "out"));

		if (!targetDirectory.exists() && commandLine.getOptionValue("t") == null) {
			targetDirectory.mkdir();
		}

		if (!targetDirectory.exists()) {
			throw new ToolException("Target directory does not exist: " + targetDirectory);
		}

		ctx.setTargetDirectory(targetDirectory);

		if (commandLine.hasOption("o")) {
			ctx.setOverwrite(true);
		}

		if (!commandLine.hasOption("f")) {
			tasks.add(new Validate(ctx));
		}

		if (commandLine.hasOption("ca")) {
			tasks.add(new CreateCa(ctx, config.getCa()));
		} else if (commandLine.hasOption("crt")) {
			tasks.add(new LoadCa(ctx, config.getCa()));
		}

		if (commandLine.hasOption("csr")) {
			if (config.getNodes() != null) {
				for (Config.Node nodeConfig : config.getNodes()) {
					tasks.add(new CreateNodeCsr(ctx, nodeConfig));
				}
			}

			if (config.getClients() != null) {
				for (Config.Client clientConfig : config.getClients()) {
					tasks.add(new CreateClientCsr(ctx, clientConfig));
				}
			}

		} else if (commandLine.hasOption("crt")) {
			if (config.getNodes() != null) {
				for (Config.Node nodeConfig : config.getNodes()) {
					tasks.add(new CreateNodeCertificate(ctx, nodeConfig));
				}
			}

			if (config.getClients() != null) {
				for (Config.Client clientConfig : config.getClients()) {
					tasks.add(new CreateClientCertificate(ctx, clientConfig));
				}
			}
		}

		for (Task task : tasks) {
			log.debug("Executing: " + task);
			task.run();
		}

		ctx.getFileOutput().saveAllFiles();

		if (CreateNodeCertificate.getGeneratedCertificateCount() > 0) {
			log.info("Created " + CreateNodeCertificate.getGeneratedCertificateCount() + " node certificates.");

			if (CreateNodeCertificate.isPasswordAutoGenerated()) {
				log.info(
						"Passwords for the private keys of the node certificates have been auto-generated. The passwords are stored in the config snippet files.");
			}
		}

		if (CreateNodeCsr.getGeneratedCsrCount() > 0) {
			log.info("Created " + CreateNodeCsr.getGeneratedCsrCount() + " node certificate signing requests.");

			if (CreateNodeCsr.isPasswordAutoGenerated()) {
				log.info(
						"Passwords for the private keys of the node certificates have been auto-generated. The passwords are stored in the config snippet files.");
			}
		}

		if (CreateClientCertificate.getGeneratedCertificateCount() > 0) {
			log.info("Created " + CreateClientCertificate.getGeneratedCertificateCount() + " client certificates.");

			if (CreateClientCertificate.isPasswordAutoGenerated()) {
				log.info(
						"Passwords for the private keys of the client certificates have been auto-generated. The passwords are stored in the file \"client-certificates.readme\"");
			}
		}

		if (CreateClientCsr.getGeneratedCsrCount() > 0) {
			log.info("Created " + CreateClientCsr.getGeneratedCsrCount() + " client certificate signing requests.");

			if (CreateClientCsr.isPasswordAutoGenerated()) {
				log.info(
						"Passwords for the private keys of the client certificates have been auto-generated. The passwords are stored in the file \"client-certificates.readme\"");
			}
		}

	}

}
