package com.floragunn.searchguard.tools.tlstool;

import java.io.Console;
import java.io.File;
import java.io.IOException;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
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


public class SearchGuardCertTool {

	private static final ObjectMapper objectMapper = new ObjectMapper(new YAMLFactory());
	private static final Provider securityProvider = new BouncyCastleProvider();

	public static void main(String[] args) {
		Security.addProvider(securityProvider);
		objectMapper.configure(DeserializationFeature.ACCEPT_SINGLE_VALUE_AS_ARRAY, true);

		try {
			new SearchGuardCertTool(parseOptions(args)).run();
		} catch (ToolException e) {
			System.err.println(e.getMessage());
			System.exit(1);
		}
	}

	private static CommandLine parseOptions(String[] args) {
		Options options = new Options();
		options.addOption(Option.builder("ca").longOpt("create-ca").desc("Create a new certificate authority").build());
		options.addOption(Option.builder("crt").longOpt("create-cert").desc("Create certificates using an existing or newly created local certificate authority").build());
		options.addOption(Option.builder("csr").longOpt("create-csr").desc("Create certificate signing requests").build());

		
		options.addOption(Option.builder("pass").hasArg().desc("Private key password").build());
		options.addOption(Option.builder("config").hasArg().desc("Path to the config file").build());
		
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
	
	
	private char[] readPassword() {
		if (commandLine.getOptionValue("pass") != null) {
			return commandLine.getOptionValue("pass").toCharArray();
		}
		
		Console console = System.console();

		if (console == null) {
			// No interactive console available => cannot read password
			return null;
		}

		console.printf("Please enter password for private keys: ");

		for (;;) {
			char[] password = console.readPassword();

			console.printf("Please enter password again: ");

			char[] verification = console.readPassword();

			if (Arrays.equals(password, verification)) {
				return password;
			} else {
				console.printf("Passwords do not match. Please try again: ");
			}
		}

	}

	private Config getConfig() throws ToolException {
		try {
			File configFile = new File(commandLine.getOptionValue("config", "config/example.yml"));

			if (!configFile.exists()) {
				throw new ToolException("Config file does not exist: " + configFile);
			}

			return objectMapper.readValue(configFile, Config.class);
		} catch (IOException e) {
			throw new ToolException(e);
		}
	}

	private void run() throws ToolException {
		Config config = getConfig();
		char [] password = readPassword();
		
		Context ctx = new Context();
		ctx.setConfig(config);
		ctx.setPassword(password);
	
		List<Task> tasks = new ArrayList<>();
		
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
			task.run();
		}

		ctx.getFileOutput().saveAllFiles(password);

	}


}
