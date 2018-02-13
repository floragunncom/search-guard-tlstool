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

package com.floragunn.searchguard.tools.tlsdiag;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.Provider;
import java.security.Security;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

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

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.floragunn.searchguard.tools.tlsdiag.tasks.DumpCert;
import com.floragunn.searchguard.tools.tlsdiag.tasks.Task;
import com.floragunn.searchguard.tools.tlsdiag.tasks.ValidateCert;
import com.floragunn.searchguard.tools.tlstool.ToolException;
import com.floragunn.searchguard.tools.util.EsNodeConfig;
import com.floragunn.searchguard.tools.util.PemFileUtils;

/**
 * TODO - KeyStore for TrustAnchors?
 * https://stackoverflow.com/questions/2457795/x-509-certificate-validation-with-java-and-bouncycastle
 * - CRL
 */
public class SearchGuardTlsDiagnosis {
	private static final ObjectMapper objectMapper = new ObjectMapper(new YAMLFactory());
	private static final Provider securityProvider = new BouncyCastleProvider();
	private static final Logger log = LogManager.getLogger(SearchGuardTlsDiagnosis.class);
	private static Options options;

	public static void main(String[] args) {
		Security.addProvider(securityProvider);
		objectMapper.configure(DeserializationFeature.ACCEPT_SINGLE_VALUE_AS_ARRAY, true);

		try {
			new SearchGuardTlsDiagnosis(parseOptions(args)).run();
		} catch (ToolException e) {
			log.error(e.getMessage());
			log.debug("Exception: ", e);
			System.exit(1);
		}
	}

	private static CommandLine parseOptions(String[] args) {
		options = new Options();
		options.addOption(Option.builder("es").longOpt("es-config").hasArg()
				.desc("Path to the ElasticSearch config file containing the SearchGuard TLS configuration").build());
		options.addOption(Option.builder("ca").longOpt("trusted-ca").hasArgs()
				.desc("Path to a PEM file containing the certificate of a trusted CA").build());
		options.addOption(Option.builder("crt").longOpt("certificates").hasArgs()
				.desc("Path to PEM files containing certificates to be checked").build());

		options.addOption(Option.builder("v").longOpt("verbose").desc("Enable detailed output").build());

		try {

			CommandLineParser parser = new DefaultParser();
			CommandLine line = parser.parse(options, args);

			return line;
		} catch (ParseException e) {
			new HelpFormatter().printHelp("sgtlsdiag.sh", options, true);
			System.exit(1);
			return null;
		}
	}

	private CommandLine commandLine;
	private List<Task> tasks = new ArrayList<>();

	SearchGuardTlsDiagnosis(CommandLine commandLine) {
		this.commandLine = commandLine;
	}

	private void run() throws ToolException {

		if (commandLine.hasOption("v")) {
			Configurator.setRootLevel(Level.DEBUG);
			Configurator.setLevel("STDOUT", Level.DEBUG);

			System.setProperty("java.security.debug", "certpath");
		}

		if (commandLine.hasOption("ca") && !commandLine.hasOption("crt")) {
			throw new ToolException(
					"You must specifiy at least one certificate to check using the --certificates option");
		}

		if (commandLine.hasOption("crt")) {
			if (!commandLine.hasOption("ca")) {
				throw new ToolException(
						"You must specify the certificate of the trusted CA using the --trusted-ca option");
			}

			Set<TrustAnchor> trustAnchors = loadTrustAnchors(Stream.of(commandLine.getOptionValues("ca"))
					.map(fileName -> new File(fileName)).collect(Collectors.toSet()));

			for (String certFileName : commandLine.getOptionValues("crt")) {
				tasks.add(new ValidateCert(trustAnchors, new File(certFileName)));
			}

			if (commandLine.hasOption("v")) {
				for (String caFileName : commandLine.getOptionValues("ca")) {
					tasks.add(new DumpCert(new File(caFileName)));
				}
			}
		}

		if (commandLine.hasOption("es")) {
			processEsConfigFile(new File(commandLine.getOptionValue("es")));
		}

		if (!commandLine.hasOption("crt") && !commandLine.hasOption("es")) {
			new HelpFormatter().printHelp("sgtlsdiag.sh", options, true);
			System.exit(1);
		}

		for (Task task : tasks) {
			task.run();
		}

	}

	private Set<TrustAnchor> loadTrustAnchors(Set<File> files) throws ToolException {

		HashSet<TrustAnchor> result = new HashSet<>();

		for (File file : files) {
			try {
				List<X509Certificate> certificates = PemFileUtils.readCertificatesFromPemFile(file);

				for (X509Certificate certificate : certificates) {
					result.add(new TrustAnchor(certificate, null));
				}
			} catch (FileNotFoundException e) {
				throw new ToolException("The file " + file + " does not exist", e);
			} catch (Exception e) {
				throw new ToolException("Error while reading " + file + ": " + e, e);
			}
		}

		return result;
	}

	private void processEsConfigFile(File file) throws ToolException {
		try {
			log.info("Reading node config file " + file);

			EsNodeConfig esNodeConfig = objectMapper.readValue(file, EsNodeConfig.class);

			Set<TrustAnchor> transportTrustAnchors = new HashSet<>();
			Set<TrustAnchor> httpTrustAnchors = new HashSet<>();
			Set<File> allCaFiles = new HashSet<>();

			if (esNodeConfig.getTransportPemTrustedCasFilePath() != null) {
				File pemFile = new File(file.getParentFile(), esNodeConfig.getTransportPemTrustedCasFilePath());
				transportTrustAnchors = loadTrustAnchors(Collections.singleton(pemFile));
				allCaFiles.add(pemFile);
			}

			if (esNodeConfig.getHttpPemTrustedCasFilePath() != null) {
				File pemFile = new File(file.getParentFile(), esNodeConfig.getHttpPemTrustedCasFilePath());
				httpTrustAnchors = loadTrustAnchors(Collections.singleton(pemFile));
				allCaFiles.add(pemFile);
			}

			if (esNodeConfig.getTransportPemCertFilePath() != null) {
				tasks.add(new ValidateCert(transportTrustAnchors,
						new File(file.getParentFile(), esNodeConfig.getTransportPemCertFilePath())));
			}

			if (esNodeConfig.getHttpPemCertFilePath() != null) {
				tasks.add(new ValidateCert(httpTrustAnchors,
						new File(file.getParentFile(), esNodeConfig.getHttpPemCertFilePath())));
			}

			for (File caFile : allCaFiles) {
				tasks.add(new DumpCert(caFile));
			}

		} catch (JsonParseException | JsonMappingException e) {
			throw new ToolException("ES node config file " + file + " is invalid: " + file, e);
		} catch (FileNotFoundException e) {
			throw new ToolException("ES node config file does not exist: " + file);
		} catch (IOException e) {
			throw new ToolException("Error while reading " + file + ": " + e, e);
		}

	}
}
