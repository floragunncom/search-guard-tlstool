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

package com.floragunn.searchguard.tools.util;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.common.base.Strings;
import com.fasterxml.jackson.annotation.JsonInclude.Include;

@JsonInclude(Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class EsNodeConfig {

    @JsonProperty("searchguard.ssl.transport.pemcert_filepath")
    private String transportPemCertFilePath;

    @JsonProperty("searchguard.ssl.transport.pemkey_filepath")
    private String transportPemKeyFilePath;

    @JsonProperty("searchguard.ssl.transport.pemkey_password")
    private String transportPemKeyPassword;

    @JsonProperty("searchguard.ssl.transport.pemtrustedcas_filepath")
    private String transportPemTrustedCasFilePath;

    @JsonProperty("searchguard.ssl.transport.server_pemcert_filepath")
    private String transportServerPemCertFilePath;

    @JsonProperty("searchguard.ssl.transport.server_pemkey_filepath")
    private String transportServerPemKeyFilePath;

    @JsonProperty("searchguard.ssl.transport.server_pemkey_password")
    private String transportServerPemKeyPassword;

    @JsonProperty("searchguard.ssl.transport.server_pemtrustedcas_filepath")
    private String transportServerPemTrustedCasFilePath;

    @JsonProperty("searchguard.ssl.transport.client_pemcert_filepath")
    private String transportClientPemCertFilePath;

    @JsonProperty("searchguard.ssl.transport.client_pemkey_filepath")
    private String transportClientPemKeyFilePath;

    @JsonProperty("searchguard.ssl.transport.client_pemkey_password")
    private String transportClientPemKeyPassword;

    @JsonProperty("searchguard.ssl.transport.client_pemtrustedcas_filepath")
    private String transportClientPemTrustedCasFilePath;

    @JsonProperty("searchguard.ssl.transport.enforce_hostname_verification")
    private boolean transportEnforceHostnameVerification = false;

    @JsonProperty("searchguard.ssl.transport.resolve_hostname")
    private boolean transportResolveDns = false;

    @JsonProperty("searchguard.ssl.http.enabled")
    private boolean httpsEnabled = true;

    @JsonProperty("searchguard.ssl.http.pemcert_filepath")
    private String httpPemCertFilePath;

    @JsonProperty("searchguard.ssl.http.pemkey_filepath")
    private String httpPemKeyFilePath;

    @JsonProperty("searchguard.ssl.http.pemkey_password")
    private String httpPemKeyPassword;

    @JsonProperty("searchguard.ssl.http.pemtrustedcas_filepath")
    private String httpPemTrustedCasFilePath;

    @JsonProperty("searchguard.nodes_dn")
    private List<String> nodesDn;

    @JsonProperty("searchguard.authcz.admin_dn")
    private List<String> authczAdminDn;

    @JsonProperty("searchguard.cert.oid")
    private String certOid = null;

    @JsonProperty("searchguard.ssl.http.clientauth_mode")
    private String clientAuthMode = null;

    @JsonProperty("searchguard.ssl.transport.keystore_filepath")
    private String transportKeystoreFilePath;

    @JsonProperty("searchguard.ssl.transport.truststore_filepath")
    private String transportTruststoreFilepath;

    @JsonProperty("searchguard.ssl.http.keystore_filepath")
    private String httpKeystoreFilepath;

    @JsonProperty("searchguard.ssl.http.truststore_filepath")
    private String httpTruststoreFilepath;

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

    public String getTransportServerPemCertFilePath() {
        return transportServerPemCertFilePath;
    }

    public void setTransportServerPemCertFilePath(String transportServerPemCertFilePath) {
        this.transportServerPemCertFilePath = transportServerPemCertFilePath;
    }

    public String getTransportServerPemKeyFilePath() {
        return transportServerPemKeyFilePath;
    }

    public void setTransportServerPemKeyFilePath(String transportServerPemKeyFilePath) {
        this.transportServerPemKeyFilePath = transportServerPemKeyFilePath;
    }

    public String getTransportServerPemKeyPassword() {
        return transportServerPemKeyPassword;
    }

    public void setTransportServerPemKeyPassword(String transportServerPemKeyPassword) {
        this.transportServerPemKeyPassword = transportServerPemKeyPassword;
    }

    public String getTransportServerPemTrustedCasFilePath() {
        return transportServerPemTrustedCasFilePath;
    }

    public void setTransportServerPemTrustedCasFilePath(String transportServerPemTrustedCasFilePath) {
        this.transportServerPemTrustedCasFilePath = transportServerPemTrustedCasFilePath;
    }

    public String getTransportClientPemCertFilePath() {
        return transportClientPemCertFilePath;
    }

    public void setTransportClientPemCertFilePath(String transportClientPemCertFilePath) {
        this.transportClientPemCertFilePath = transportClientPemCertFilePath;
    }

    public String getTransportClientPemKeyFilePath() {
        return transportClientPemKeyFilePath;
    }

    public void setTransportClientPemKeyFilePath(String transportClientPemKeyFilePath) {
        this.transportClientPemKeyFilePath = transportClientPemKeyFilePath;
    }

    public String getTransportClientPemKeyPassword() {
        return transportClientPemKeyPassword;
    }

    public void setTransportClientPemKeyPassword(String transportClientPemKeyPassword) {
        this.transportClientPemKeyPassword = transportClientPemKeyPassword;
    }

    public String getTransportClientPemTrustedCasFilePath() {
        return transportClientPemTrustedCasFilePath;
    }

    public void setTransportClientPemTrustedCasFilePath(String transportClientPemTrustedCasFilePath) {
        this.transportClientPemTrustedCasFilePath = transportClientPemTrustedCasFilePath;
    }

    public boolean isTransportEnforceHostnameVerification() {
        return transportEnforceHostnameVerification;
    }

    public void setTransportEnforceHostnameVerification(boolean transportEnforceHostnameVerification) {
        this.transportEnforceHostnameVerification = transportEnforceHostnameVerification;
    }

    public boolean isHttpsEnabled() {
        return httpsEnabled;
    }

    public void setHttpsEnabled(boolean httpsEnabled) {
        this.httpsEnabled = httpsEnabled;
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

    public boolean isTransportResolveDns() {
        return transportResolveDns;
    }

    public void setTransportResolveDns(boolean transportResolveDns) {
        this.transportResolveDns = transportResolveDns;
    }

    public String getTransportKeystoreFilePath() {
        return transportKeystoreFilePath;
    }

    public void setTransportKeystoreFilePath(String transportKeystoreFilePath) {
        this.transportKeystoreFilePath = transportKeystoreFilePath;
    }

    public String getTransportTruststoreFilepath() {
        return transportTruststoreFilepath;
    }

    public void setTransportTruststoreFilepath(String transportTruststoreFilepath) {
        this.transportTruststoreFilepath = transportTruststoreFilepath;
    }

    public String getHttpKeystoreFilepath() {
        return httpKeystoreFilepath;
    }

    public void setHttpKeystoreFilepath(String httpKeystoreFilepath) {
        this.httpKeystoreFilepath = httpKeystoreFilepath;
    }

    public String getHttpTruststoreFilepath() {
        return httpTruststoreFilepath;
    }

    public void setHttpTruststoreFilepath(String httpTruststoreFilepath) {
        this.httpTruststoreFilepath = httpTruststoreFilepath;
    }

    @JsonIgnore
    public boolean isKeystoreOrTruststoreAttributeSet() {
        return !Strings.isNullOrEmpty(transportKeystoreFilePath) || !Strings.isNullOrEmpty(transportTruststoreFilepath)
                || !Strings.isNullOrEmpty(httpKeystoreFilepath) || !Strings.isNullOrEmpty(httpTruststoreFilepath);
    }

}