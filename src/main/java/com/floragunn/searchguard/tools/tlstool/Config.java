package com.floragunn.searchguard.tools.tlstool;

import java.util.List;

public class Config {
	
	public final static Config DEFAULT = new Config();
	
	private Ca ca;
	private List<Node> nodes;
	private List<Client> clients;
	
	public Ca getCa() {
		return ca;
	}


	public void setCa(Ca ca) {
		this.ca = ca;
	}


	public List<Node> getNodes() {
		return nodes;
	}


	public void setNodes(List<Node> nodes) {
		this.nodes = nodes;
	}



	public List<Client> getClients() {
		return clients;
	}


	public void setClients(List<Client> clients) {
		this.clients = clients;
	}



	public static class Ca {
	
		private Certificate root;
		private Certificate intermediate;
		
		public Certificate getRoot() {
			return root;
		}

		public void setRoot(Certificate root) {
			this.root = root;
		}

		public Certificate getIntermediate() {
			return intermediate;
		}

		public void setIntermediate(Certificate intermediate) {
			this.intermediate = intermediate;
		}

		public static class Certificate {
			private int keysize = 2048;
			private String dn;
			private int validityDays = 36500;
			private int defaultValidityDays = 730;
			private List<String> crlDistributionPoints;
			private String file;
			
			public int getKeysize() {
				return keysize;
			}
			public void setKeysize(int keysize) {
				this.keysize = keysize;
			}
			public String getDn() {
				return dn;
			}
			public void setDn(String dn) {
				this.dn = dn;
			}
			public int getValidityDays() {
				return validityDays;
			}
			public void setValidityDays(int validityDays) {
				this.validityDays = validityDays;
			}
			public int getDefaultValidityDays() {
				return defaultValidityDays;
			}
			public void setDefaultValidityDays(int defaultValidityDays) {
				this.defaultValidityDays = defaultValidityDays;
			}
			public List<String> getCrlDistributionPoints() {
				return crlDistributionPoints;
			}
			public void setCrlDistributionPoints(List<String> crlDistributionPoints) {
				this.crlDistributionPoints = crlDistributionPoints;
			}
			public String getFile() {
				return file;
			}
			public void setFile(String file) {
				this.file = file;
			}
			
			
		}
	}
	
	
	
	public static class Node {
		private String name;
		private String dn;
		private List<String> dns;
		private List<String> ip;
		private List<String> oid;
		private int keysize = 2048;
		
		public String getName() {
			return name;
		}
		public void setName(String name) {
			this.name = name;
		}
		
		public String getDn() {
			return dn;
		}
		public void setDn(String dn) {
			this.dn = dn;
		}
		public List<String> getDns() {
			return dns;
		}
		public void setDns(List<String> dns) {
			this.dns = dns;
		}
		public List<String> getIp() {
			return ip;
		}
		public void setIp(List<String> ip) {
			this.ip = ip;
		}
		public List<String> getOid() {
			return oid;
		}
		public void setOid(List<String> oid) {
			this.oid = oid;
		}
		public int getKeysize() {
			return keysize;
		}
		public void setKeysize(int keysize) {
			this.keysize = keysize;
		}
	}
	
	public static class Client {
		private String name;
		private String dn;
		private int keysize = 2048;

		public String getName() {
			return name;
		}
		public void setName(String name) {
			this.name = name;
		}
		public String getDn() {
			return dn;
		}
		public void setDn(String dn) {
			this.dn = dn;
		}
		public int getKeysize() {
			return keysize;
		}
		public void setKeysize(int keysize) {
			this.keysize = keysize;
		}
	}
}
