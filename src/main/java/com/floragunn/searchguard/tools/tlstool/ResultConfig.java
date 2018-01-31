package com.floragunn.searchguard.tools.tlstool;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;

public class ResultConfig {


	@JsonInclude(Include.NON_NULL)
	public static class Node {
		
		@JsonProperty("searchguard.ssl.transport.pemcert_filepath")
		private String transportPemCertFilePath;
		
		@JsonProperty("searchguard.ssl.transport.pemkey_filepath")
		private String transportPemKeyFilePath;
		
		@JsonProperty("searchguard.ssl.transport.pemkey_password")
		private String transportPemKeyPassword;
		
		@JsonProperty("searchguard.ssl.transport.pemtrustedcas_filepath")
		private String transportPemTrustedCasFilePath;
		
		@JsonProperty("searchguard.ssl.transport.enforce_hostname_verification")
		private boolean transportEnforceHostnameVerification = false;

		@JsonProperty("searchguard.ssl.http.enabled")
		private boolean httpEnabled = true;

		@JsonProperty("searchguard.ssl.http.pemcert_filepath")
		private String httpPemCertFilePath;
		
		@JsonProperty("searchguard.ssl.http.pemkey_filepath")
		private String httpPemKeyFilePath;
		
		@JsonProperty("searchguard.ssl.http.pemkey_password")
		private String httpPemKeyPassword;
		
		@JsonProperty("searchguard.ssl.http.pemtrustedcas_filepath")
		private String httpPemTrustedCasFilePath;
		
		// TODO nicht gebraucht?
		//@JsonProperty("searchguard.allow_unsafe_democertificates")
		//private boolean allowUnsafeDemoCertificates = true;
		
		@JsonProperty("searchguard.nodes_dn")
		private List<String> nodesDn;
		
		@JsonProperty("searchguard.authcz.admin_dn")
		private List<String> authczAdminDn;
		
		@JsonProperty("searchguard.cert.oid")
		private String certOid = null;

		@JsonProperty("searchguard.ssl.http.clientauth_mode")
		private String clientAuthMode = null;
		
		public String getTransportPemCertFilePath() {
			return transportPemCertFilePath;
		}

		public void setTransportPemCertFilePath(String transportPemCertFilePath) {
			this.transportPemCertFilePath = transportPemCertFilePath;
		}

		public String getTransportPemKeyFilePath() {
			return transportPemKeyFilePath;
		}

		public void setTransportPemKeyFilePath(String transportPemKeyFilePath) {
			this.transportPemKeyFilePath = transportPemKeyFilePath;
		}

		public String getTransportPemKeyPassword() {
			return transportPemKeyPassword;
		}

		public void setTransportPemKeyPassword(String transportPemKeyPassword) {
			this.transportPemKeyPassword = transportPemKeyPassword;
		}

		public String getTransportPemTrustedCasFilePath() {
			return transportPemTrustedCasFilePath;
		}

		public void setTransportPemTrustedCasFilePath(String transportPemTrustedCasFilePath) {
			this.transportPemTrustedCasFilePath = transportPemTrustedCasFilePath;
		}

		public boolean isTransportEnforceHostnameVerification() {
			return transportEnforceHostnameVerification;
		}

		public void setTransportEnforceHostnameVerification(boolean transportEnforceHostnameVerification) {
			this.transportEnforceHostnameVerification = transportEnforceHostnameVerification;
		}

		public boolean isHttpEnabled() {
			return httpEnabled;
		}

		public void setHttpEnabled(boolean httpEnabled) {
			this.httpEnabled = httpEnabled;
		}

		public String getHttpPemCertFilePath() {
			return httpPemCertFilePath;
		}

		public void setHttpPemCertFilePath(String httpPemCertFilePath) {
			this.httpPemCertFilePath = httpPemCertFilePath;
		}

		public String getHttpPemKeyFilePath() {
			return httpPemKeyFilePath;
		}

		public void setHttpPemKeyFilePath(String httpPemKeyFilePath) {
			this.httpPemKeyFilePath = httpPemKeyFilePath;
		}

		public String getHttpPemKeyPassword() {
			return httpPemKeyPassword;
		}

		public void setHttpPemKeyPassword(String httpPemKeyPassword) {
			this.httpPemKeyPassword = httpPemKeyPassword;
		}

		public String getHttpPemTrustedCasFilePath() {
			return httpPemTrustedCasFilePath;
		}

		public void setHttpPemTrustedCasFilePath(String httpPemTrustedCasFilePath) {
			this.httpPemTrustedCasFilePath = httpPemTrustedCasFilePath;
		}

		public List<String> getNodesDn() {
			return nodesDn;
		}

		public void setNodesDn(List<String> nodesDn) {
			this.nodesDn = nodesDn;
		}

		public List<String> getAuthczAdminDn() {
			return authczAdminDn;
		}

		public void setAuthczAdminDn(List<String> authczAdminDn) {
			this.authczAdminDn = authczAdminDn;
		}

		public String getCertOid() {
			return certOid;
		}

		public void setCertOid(String certOid) {
			this.certOid = certOid;
		}

		public String getClientAuthMode() {
			return clientAuthMode;
		}

		public void setClientAuthMode(String clientAuthMode) {
			this.clientAuthMode = clientAuthMode;
		}
	}
}

