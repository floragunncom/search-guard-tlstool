package com.floragunn.searchguard.tools.tlstool;

import java.io.Console;
import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.Arrays;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;


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
	private Config config;
	private X509CertificateHolder rootCaCertificate;
	private X509CertificateHolder intermediateCertificate;
	private KeyPair intermediateKeyPair;
	private long idCounter = System.currentTimeMillis();
	private FileOutput fileOutput = new FileOutput();
	private char[] password;

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

			if (Arrays.areEqual(password, verification)) {
				return password;
			} else {
				console.printf("Passwords do not match. Please try again: ");
			}
		}

	}

	private Config getConfig() throws ToolException {
		try {
			// File configFile = new File("sg-tls-config.yml");
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
		config = getConfig();
		password = readPassword();

		if (config.getCa() != null) {
			createSelfSignedCa();
		} else {
			// TODO something else: load existing signing certificate or create CSR
		}

		if (config.getNodes() != null) {
			for (Config.Node nodeConfig : config.getNodes()) {
				KeyPair nodeKeyPair = generateKeyPair(2048); // TODO

				X509CertificateHolder nodeCertificate = createNodeCert(nodeConfig, nodeKeyPair, intermediateKeyPair,
						intermediateCertificate);

				addOutputFile(getNodeFileName(nodeConfig) + ".pem", intermediateCertificate, nodeCertificate);
				addOutputFile(getNodeFileName(nodeConfig) + ".key", nodeKeyPair.getPrivate());
			}
		}
		
		if (config.getClients() != null) {
			for (Config.Client clientConfig : config.getClients()) {
				KeyPair clientKeyPair = generateKeyPair(2048); // TODO

				X509CertificateHolder clientCertificate = createClientCert(clientConfig, clientKeyPair, intermediateKeyPair,
						intermediateCertificate);

				addOutputFile(getClientFileName(clientConfig) + ".pem", intermediateCertificate, clientCertificate);
				addOutputFile(getClientFileName(clientConfig) + ".key", clientKeyPair.getPrivate());
				
			}
		}

		fileOutput.saveAllFiles(password);

	}

	private String getNodeFileName(Config.Node node) {
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

		return "node" + (config.getNodes().indexOf(node) + 1);
	}
	
	private String getClientFileName(Config.Client client) {
		if (client.getName() != null) {
			return client.getName();
		}

		if (client.getDn() != null) {
			String name = getSimpleNameFromDn(client.getDn());
			
			if (name != null) {
				return name;
			}
		}

		return "client" + (config.getClients().indexOf(client) + 1);
	}
	
	private String getSimpleNameFromDn(String dnString) {
		try {
			X500Name dn = new X500Name(dnString);
			RDN[] rdns = dn.getRDNs();

			if (rdns != null && rdns.length > 0) {
				return rdns[0].getFirst().getValue().toString();
			}
		} catch (IllegalArgumentException e) {
			// DN was invalid - fall through
		}	
		
		return null;
	}

	private void createSelfSignedCa() throws ToolException {
		Config.Ca.Certificate rootCertificateConfig = config.getCa().getRoot();

		KeyPair rootCaKeyPair = generateKeyPair(rootCertificateConfig.getKeysize());
		rootCaCertificate = createRootCaCertificate(rootCertificateConfig, rootCaKeyPair);

		addOutputFile("root-ca.pem", rootCaCertificate);
		addOutputFile("root-ca.key", rootCaKeyPair.getPrivate());

		Config.Ca.Certificate intermediateCertificateConfig = config.getCa().getIntermediate();

		intermediateKeyPair = generateKeyPair(intermediateCertificateConfig.getKeysize());
		intermediateCertificate = createIntermediateCertificate(intermediateCertificateConfig, intermediateKeyPair,
				rootCaKeyPair, rootCaCertificate);

		addOutputFile("signing-ca.pem", intermediateCertificate);
		addOutputFile("signing-ca.key", intermediateKeyPair.getPrivate());

	}

	private X500Name createDn(String dn, String role) throws ToolException {
		try {
			return new X500Name(dn);
		} catch (IllegalArgumentException e) {
			throw new ToolException("Invalid DN specified for " + role + ": " + dn, e);
		}
	}

	private KeyPair generateKeyPair(int keySize) throws ToolException {
		try {
			KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", securityProvider);
			generator.initialize(keySize);

			KeyPair keyPair = generator.generateKeyPair();
			return keyPair;
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}

	private Date getEndDate(Date startDate, int validityDays) {
		Calendar calendar = Calendar.getInstance();
		calendar.setTime(startDate);
		calendar.add(Calendar.DATE, validityDays);
		return calendar.getTime();
	}

	private X509CertificateHolder createRootCaCertificate(Config.Ca.Certificate rootCertificateConfig, KeyPair keyPair)
			throws ToolException {
		try {
			X500Name rootCaDn = createDn(rootCertificateConfig.getDn(), "root");

			Date validityStartDate = new Date(System.currentTimeMillis());
			Date validityEndDate = getEndDate(validityStartDate, rootCertificateConfig.getValidityDays());
			SubjectPublicKeyInfo subPubKeyInfo = SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());

			X509v3CertificateBuilder builder = new X509v3CertificateBuilder(rootCaDn, BigInteger.valueOf(1),
					validityStartDate, validityEndDate, rootCaDn, subPubKeyInfo);

			JcaX509ExtensionUtils extUtils = getExtUtils();

			// Mark this as root CA
			builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));

			builder.addExtension(Extension.authorityKeyIdentifier, false,
					extUtils.createAuthorityKeyIdentifier(keyPair.getPublic()))
					.addExtension(Extension.subjectKeyIdentifier, false,
							extUtils.createSubjectKeyIdentifier(keyPair.getPublic()))
					.addExtension(Extension.keyUsage, true,
							new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign | KeyUsage.cRLSign));

			X509CertificateHolder cert = builder.build(new JcaContentSignerBuilder("SHA1withRSA")
					.setProvider(securityProvider).build(keyPair.getPrivate()));
			return cert;
		} catch (CertIOException | OperatorCreationException e) {
			throw new ToolException("Error while composing certificate", e);
		}

	}

	private JcaX509ExtensionUtils getExtUtils() {
		try {
			return new JcaX509ExtensionUtils();
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}

	private X509CertificateHolder createIntermediateCertificate(Config.Ca.Certificate intermediateCertificateConfig,
			KeyPair intKey, KeyPair caKey, X509CertificateHolder caCert) throws ToolException {
		try {
			Date validityStartDate = new Date(System.currentTimeMillis());
			Date validityEndDate = getEndDate(validityStartDate, intermediateCertificateConfig.getValidityDays());

			X500Name intermediateDn = createDn(intermediateCertificateConfig.getDn(), "intermediate");

			SubjectPublicKeyInfo subPubKeyInfo = SubjectPublicKeyInfo.getInstance(intKey.getPublic().getEncoded());

			X509v3CertificateBuilder builder = new X509v3CertificateBuilder(caCert.getSubject(), BigInteger.valueOf(2),
					validityStartDate, validityEndDate, intermediateDn, subPubKeyInfo);

			JcaX509ExtensionUtils extUtils = getExtUtils();

			// Allow this certificate only to be used for leaf certificates
			builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(0));

			builder.addExtension(Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(caCert))
					.addExtension(Extension.subjectKeyIdentifier, false,
							extUtils.createSubjectKeyIdentifier(intKey.getPublic()))
					.addExtension(Extension.keyUsage, true,
							new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign | KeyUsage.cRLSign));

			X509CertificateHolder cert = builder.build(
					new JcaContentSignerBuilder("SHA1withRSA").setProvider(securityProvider).build(caKey.getPrivate()));
			return cert;
		} catch (CertIOException | OperatorCreationException e) {
			throw new ToolException("Error while composing certificate", e);
		}
	}

	private X509CertificateHolder createNodeCert(Config.Node nodeConfig, KeyPair nodeKey, KeyPair intKey,
			X509CertificateHolder intCert) throws ToolException {

		try {

			SubjectPublicKeyInfo subPubKeyInfo = SubjectPublicKeyInfo.getInstance(intKey.getPublic().getEncoded());
			X500Name subjectName = createDn(nodeConfig.getDn(), "node");

			X509v3CertificateBuilder builder = new X509v3CertificateBuilder(intCert.getSubject(),
					BigInteger.valueOf(idCounter++), new Date(System.currentTimeMillis()),
					new Date(System.currentTimeMillis() + 730), // TODO
					subjectName, subPubKeyInfo);

			JcaX509ExtensionUtils extUtils = getExtUtils();

			builder.addExtension(Extension.authorityKeyIdentifier, false,
					extUtils.createAuthorityKeyIdentifier(intCert))
					.addExtension(Extension.subjectKeyIdentifier, false,
							extUtils.createSubjectKeyIdentifier(nodeKey.getPublic()))
					.addExtension(Extension.basicConstraints, true, new BasicConstraints(0))
					.addExtension(Extension.keyUsage, true,
							new KeyUsage(
									KeyUsage.digitalSignature | KeyUsage.nonRepudiation | KeyUsage.keyEncipherment))
					.addExtension(Extension.extendedKeyUsage, true, new ExtendedKeyUsage(
							new KeyPurposeId[] { KeyPurposeId.id_kp_serverAuth, KeyPurposeId.id_kp_clientAuth }));

			List<ASN1Encodable> subjectAlternativeNameList = new ArrayList<ASN1Encodable>();

			if (nodeConfig.getOid() != null) {
				for (String oid : nodeConfig.getOid()) {
					subjectAlternativeNameList.add(new GeneralName(GeneralName.registeredID, oid));
				}
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

			builder.addExtension(Extension.subjectAlternativeName, false, new DERSequence(
					subjectAlternativeNameList.toArray(new ASN1Encodable[subjectAlternativeNameList.size()])));

			X509CertificateHolder cert = builder.build(new JcaContentSignerBuilder("SHA1withRSA")
					.setProvider(securityProvider).build(nodeKey.getPrivate()));

			return cert;
		} catch (CertIOException | OperatorCreationException e) {
			throw new ToolException("Error while composing certificate", e);
		}
	}
	
	private X509CertificateHolder createClientCert(Config.Client clientConfig, KeyPair clientKey, KeyPair intKey,
			X509CertificateHolder intCert) throws ToolException {

		try {

			SubjectPublicKeyInfo subPubKeyInfo = SubjectPublicKeyInfo.getInstance(intKey.getPublic().getEncoded());
			X500Name subjectName = createDn(clientConfig.getDn(), "client");

			X509v3CertificateBuilder builder = new X509v3CertificateBuilder(intCert.getSubject(),
					BigInteger.valueOf(idCounter++), new Date(System.currentTimeMillis()),
					new Date(System.currentTimeMillis() + 730), // TODO
					subjectName, subPubKeyInfo);

			JcaX509ExtensionUtils extUtils = getExtUtils();

			builder.addExtension(Extension.authorityKeyIdentifier, false,
					extUtils.createAuthorityKeyIdentifier(intCert))
					.addExtension(Extension.subjectKeyIdentifier, false,
							extUtils.createSubjectKeyIdentifier(clientKey.getPublic()))
					.addExtension(Extension.basicConstraints, true, new BasicConstraints(0))
					.addExtension(Extension.keyUsage, true,
							new KeyUsage(
									KeyUsage.digitalSignature | KeyUsage.nonRepudiation | KeyUsage.keyEncipherment))
					.addExtension(Extension.extendedKeyUsage, true, new ExtendedKeyUsage(
							new KeyPurposeId[] { KeyPurposeId.id_kp_clientAuth }));

			
			X509CertificateHolder cert = builder.build(new JcaContentSignerBuilder("SHA1withRSA")
					.setProvider(securityProvider).build(clientKey.getPrivate()));

			return cert;
		} catch (CertIOException | OperatorCreationException e) {
			throw new ToolException("Error while composing certificate", e);
		}
	}

	private void addOutputFile(String fileName, Object... entries) {
		fileOutput.add(fileName, entries);
	}

}
