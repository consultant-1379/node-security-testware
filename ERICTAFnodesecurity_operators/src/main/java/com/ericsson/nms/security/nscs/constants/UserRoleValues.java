/*
 * ------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2016
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------
 */

package com.ericsson.nms.security.nscs.constants;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * Set of constants.
 */
public class UserRoleValues {
    public static final String ROLE_OPERATOR = "OPERATOR";
    public static final String ROLE_SECURITY_ADMIN = "SECURITY_ADMIN";
    public static final String ROLE_FIELD_TECHNICIAN = "FIELD_TECHNICIAN";
    public static final String ROLE_NODESECURITY_OPERATOR = "NodeSecurity_Operator";
    public static final String ROLE_NODESECURITY_ADMIN = "NodeSecurity_Administrator";
    public static final String ROLE_AMOS_ADMINISTRATOR = "Amos_Administrator";
    public static final String ROLE_SECURITY_MANAGEMENT = "SecurityManagement";
    public static final String ROLE_CM_NORMAL = "CM-Normal";
    public static final String ROLE_LOGVIEWER_PRIVACY_ADMIN = "LogViewer_Privacy_Administrator";

    public static final String ROLE_CREDENTIAL = "credential_role";
    public static final String ROLE_SSH_KEY = "sshkey_role";
    public static final String ROLE_OAM = "oam_role";
    public static final String ROLE_LDAP = "Ldap_role";
    public static final String ROLE_LDAP_REST = "Ldap_REST";
    public static final String ROLE_GENERATE_ENROLLMENT_INFO_REST = "GenEnrollmentInfo_REST";
    public static final String ROLE_IPSEC = "ipsec_role";
    public static final String ROLE_GET_CREDENTIALS = "get_credentials_role";
    public static final String ROLE_GET_SNMP_CREDENTIALS = "get_credentials_snmp_role";
    public static final String ROLE_UPDATE_SNMP_NBI_CREDENTIALS = "update_credentials_snmp_nbi_role";
    public static final String ROLE_HTTPS = "https_role";
    public static final String ROLE_FTPES = "ftpes_role";
    public static final String ROLE_TRUST_OPERATOR = "trust_role_Operator";
    public static final String ROLE_PKI_EE_ADMIN = "PKI_EE_Administrator";


    private static final List<String> allRoles = new ArrayList<>();

    public UserRoleValues() {
        allRoles.add(ROLE_OPERATOR);
        allRoles.add(ROLE_SECURITY_ADMIN);
        allRoles.add(ROLE_FIELD_TECHNICIAN);
        allRoles.add(ROLE_NODESECURITY_OPERATOR);
        allRoles.add(ROLE_NODESECURITY_ADMIN);
        allRoles.add(ROLE_SECURITY_MANAGEMENT);
        allRoles.add(ROLE_CM_NORMAL);
        allRoles.add(ROLE_CREDENTIAL);
        allRoles.add(ROLE_SSH_KEY);
        allRoles.add(ROLE_OAM);
        allRoles.add(ROLE_IPSEC);
        allRoles.add(ROLE_GET_CREDENTIALS);
        allRoles.add(ROLE_GET_SNMP_CREDENTIALS);
        allRoles.add(ROLE_LDAP);
        allRoles.add(ROLE_LDAP_REST);
        allRoles.add(ROLE_GENERATE_ENROLLMENT_INFO_REST);
        allRoles.add(ROLE_PKI_EE_ADMIN);
    }

    public List<String> removeAll(final Collection<String> c) {
        final List<String> newList = new ArrayList<>(allRoles);
        newList.removeAll(c);
        return newList;
    }
}
