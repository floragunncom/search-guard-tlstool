package com.floragunn.searchguard.tools.tlstool.tasks;

import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.x509.GeneralName;

import com.floragunn.searchguard.tools.tlstool.Config;
import com.floragunn.searchguard.tools.tlstool.Context;

public abstract class CreateNodeCertificateBase extends Task {
	private Config.Node nodeConfig;

	public CreateNodeCertificateBase(Context ctx, Config.Node nodeConfig) {
		super(ctx);
		this.nodeConfig = nodeConfig;
	}
	
	protected ASN1Encodable [] createSubjectAlternativeNameList() {
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

}
