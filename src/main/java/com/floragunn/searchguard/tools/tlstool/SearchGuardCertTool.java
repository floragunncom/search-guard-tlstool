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

/**
 * TODO Criticality TODO Base directory
 * 
 * HTTP Certs: DN gleich wie Transport? Also use transport?
 */
public class SearchGuardCertTool {

	private static final ObjectMapper objectMapper = new ObjectMapper(new YAMLFactory());
	private static final Provider securityProvider = new BouncyCastleProvider();
	private static final Logger log = LogManager.getLogger(SearchGuardCertTool.class);

	public static void main(String[] args) {
		Security.addProvider(securityProvider);
		objectMapper.configure(DeserializationFeature.ACCEPT_SINGLE_VALUE_AS_ARRAY, true);

		try {
			new SearchGuardCertTool(parseOptions(args)).run();
		} catch (ToolException e) {
			log.error(e.getMessage());
			log.info("No files have been written");
			log.debug("Exception: ", e);
			System.exit(1);
		}
	}

	private static CommandLine parseOptions(String[] args) {
		Options options = new Options();
		options.addOption(Option.builder("ca").longOpt("create-ca").desc("Create a new certificate authority").build());
		options.addOption(Option.builder("crt").longOpt("create-cert")
				.desc("Create certificates using an existing or newly created local certificate authority").build());
		options.addOption(
				Option.builder("csr").longOpt("create-csr").desc("Create certificate signing requests").build());

		options.addOption(Option.builder("pass").hasArg().desc("Private key password").build());
		options.addOption(Option.builder("config").hasArg().desc("Path to the config file").build());
		options.addOption(Option.builder("t").longOpt("target").hasArg().desc("Path to the target directory").build());
		options.addOption(Option.builder("es").longOpt("elastic-search-target").hasArg().desc(
				"Path to the installation directory of ElasticSearch. Files will be written to the config directory of that installation. Mutually exclusive to --target.")
				.build());
		options.addOption(Option.builder("v").longOpt("verbose").desc("Enable detailed output").build());

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

	SearchGuardCertTool(CommandLine commandLine) {
		this.commandLine = commandLine;
	}

	private Config getConfig() throws ToolException {
		try {
			File configFile = new File(commandLine.getOptionValue("config", "config/example.yml"));

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
		Config config = getConfig();

		Context ctx = new Context();
		ctx.setConfig(config);
		ctx.setSecurityProvider(securityProvider);

		List<Task> tasks = new ArrayList<>();

		if (commandLine.hasOption("v")) {
			Configurator.setRootLevel(Level.DEBUG);
			Configurator.setLevel("STDOUT", Level.DEBUG);
		}

		if (commandLine.hasOption("ca")) {
			tasks.add(new CreateCa(ctx, config.getCa()));
		} else if (commandLine.hasOption("create-cert")) {
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

		log.info("Success.");

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
