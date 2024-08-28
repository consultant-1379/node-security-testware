/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2012
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/

package com.ericsson.nms.security.nscs.constants;

import java.io.File;

/**
 * CsvDataSourceConstants.
 */
public class CsvDataSourceConstants extends SecurityConstants {
    public static final String SECURITY_NODES_LOCAL = "SecurityNodeList_local";
    public static final String SECURITY_NODES_LOCAL_CSV = FOLDERNAME_NODES_TEST + File.separator + "SecurityNodeList_local.csv";

    public static final String NETSIM_TESTS = "NetsimTest";
    public static final String NETSIM_PATCHES_CSV = FOLDERNAME_NETSIM_TEST + File.separator + "NetsimPatches.csv";

    public static final String USERS_TESTS_CSV = FOLDERNAME_USERS_TEST + File.separator + "usersToCreate.csv";

    public static final String USERS_TO_CREATE_EXT_LDAP_CSV = "extLdap" + File.separator + "usersToCreate.csv";
    public static final String AVAILABLE_USERS_EXT_LDAP_CSV = "extLdap" + File.separator + "availableUsers.csv";
    public static final String EXT_LDAP_USERS_TO_UPDATE_CSV = "extLdap" + File.separator + "usersToUpdate.csv";

    public static final String CUSTOM_ROLES_TESTS_CSV = FOLDERNAME_USERS_TEST + File.separator + "RoleDefinition.csv";

    public static final String CREDENTIAL_POSITIVE_TESTS = "CredentialsCreateTest";
    public static final String CREDENTIAL_POSITIVE_TESTS_CSV = FOLDERNAME_POSITIVE_TEST + File.separator + "CredentialsPositiveTests.csv";

    public static final String CREDENTIAL_SNMP_POSITIVE_TESTS_CSV = FOLDERNAME_POSITIVE_TEST + File.separator + "CredentialsSNMPPositiveTests.csv";
    public static final String CREDENTIAL_SNMP_POSITIVE_TESTS = "CredentialsCreateSNMPTest";
    public static final String ADDED_NODES_WITH_SNMP_CREDENTIALS_CREATE_AND_GET = "addedNodesWithCredentialsSNMPCreate";

    public static final String CREDENTIAL_NEGATIVE_TESTS = "CredentialsNegativeTest";
    public static final String CREDENTIAL_NEGATIVE_TESTS_CSV = FOLDERNAME_NEGATIVE_TEST + File.separator + "CredentialsNegativeTests.csv";

    public static final String SSH_KEY_POSITIVE_TESTS = "SshKeyCreatePositiveTests";
    public static final String SSH_KEY_POSITIVE_TESTS_CSV = FOLDERNAME_POSITIVE_TEST + File.separator + "SshKeyPositiveTests.csv";

    public static final String SSH_KEY_NEGATIVE_TESTS = "SshKeyNegativeTests";
    public static final String SSH_KEY_NEGATIVE_TESTS_CSV = FOLDERNAME_NEGATIVE_TEST + File.separator + "SshKeyNegativeTests.csv";

    public static final String CERTIFICATE_ISSUE_POSITIVE_TESTS = "CertificateIssuePositiveTests";
    public static final String CERTIFICATE_ISSUE_POSITIVE_TESTS_CSV = FOLDERNAME_POSITIVE_TEST + File.separator + "CertificateIssuePositiveTests.csv";
    public static final String CERTIFICATE_ISSUE_POSITIVE_TESTS_RFA250_CSV = FOLDERNAME_POSITIVE_TEST + File.separator
            + "CertificateIssuePositiveTestsRFA250.csv";

    public static final String CERTIFICATE_ISSUE_AXE_POSITIVE_TESTS = "CertificateIssueAxePositiveTests";
    public static final String CERTIFICATE_ISSUE_AXE_POSITIVE_TESTS_CSV = FOLDERNAME_POSITIVE_TEST + File.separator
            + "AxeCertificateIssuePositiveTests.csv";

    public static final String CERTIFICATE_ISSUE_NEGATIVE_TESTS = "CertificateIssueErrorTests";
    public static final String CERTIFICATE_ISSUE_NEGATIVE_TESTS_CSV = FOLDERNAME_NEGATIVE_TEST + File.separator + "CertificateIssueNegativeTests.csv";

    public static final String CERTIFICATE_REISSUE_POSITIVE_TESTS = "CertificateReIssuePositiveTests";
    public static final String CERTIFICATE_REISSUE_POSITIVE_TESTS_CSV = FOLDERNAME_POSITIVE_TEST + File.separator
            + "CertificateReIssuePositiveTests.csv";

    public static final String CERTIFICATE_REISSUE_AXE_POSITIVE_TESTS = "CertificateReIssuePositiveTests";
    public static final String CERTIFICATE_REISSUE_AXE_POSITIVE_TESTS_CSV = FOLDERNAME_POSITIVE_TEST + File.separator
            + "AxeCertificateReIssuePositiveTests.csv";

    public static final String CREDENTIALS_GET_POSITIVE_TESTS = "CredentialsGetPositiveTests";
    public static final String CREDENTIALS_GET_POSITIVE_TESTS_CSV = FOLDERNAME_POSITIVE_TEST + File.separator + "CredentialsGetPositiveTests.csv";
    public static final String CREDENTIALS_GET_POSITIVE_TESTS_WITH_FILE = "CredentialsGetWithFilePositiveTests";
    public static final String CREDENTIALS_GET_POSITIVE_TESTS_WITH_FILE_CSV = FOLDERNAME_POSITIVE_TEST + File.separator
            + "CredentialsGetWithFilePositiveTests.csv";
    public static final String CREDENTIALS_GET_NEGATIVE_TESTS = "CredentialsGetNegativeTests";
    public static final String CREDENTIALS_GET_NEGATIVE_TESTS_CSV = FOLDERNAME_NEGATIVE_TEST + File.separator + "CredentialsGetNegativeTests.csv";

    public static final String CERTIFICATE_REISSUE_NEGATIVE_TESTS = "CertificateReIssueErrorTests";
    public static final String CERTIFICATE_REISSUE_NEGATIVE_TESTS_CSV = FOLDERNAME_NEGATIVE_TEST + File.separator
            + "CertificateReIssueNegativeTests.csv";

    public static final String TRUST_DISTRIBUTE_NEGATIVE_TESTS = "TrustDistributeErrorTests";
    public static final String TRUST_DISTRIBUTE_NEGATIVE_TESTS_CSV = FOLDERNAME_NEGATIVE_TEST + File.separator + "TrustDistributeNegativeTests.csv";

    public static final String TRUST_DISTRIBUTE_POSITIVE_TESTS = "TrustDistributePositiveTests";
    public static final String TRUST_DISTRIBUTE_POSITIVE_TESTS_CSV = FOLDERNAME_POSITIVE_TEST + File.separator + "TrustDistributePositiveTests.csv";

    public static final String TRUST_DISTRIBUTE_AXE_POSITIVE_TESTS = "TrustDistributePositiveTests";
    public static final String TRUST_DISTRIBUTE_AXE_POSITIVE_TESTS_CSV = FOLDERNAME_POSITIVE_TEST + File.separator
            + "AxeTrustDistributePositiveTests.csv";

    public static final String TRUST_REMOVE_POSITIVE_TESTS = "TrustRemovePositiveTests";
    public static final String TRUST_REMOVE_POSITIVE_TESTS_CSV = FOLDERNAME_POSITIVE_TEST + File.separator + "TrustRemovePositiveTests.csv";

    public static final String TRUST_REMOVE_NEGATIVE_TESTS = "TrustRemoveErrorTests";
    public static final String TRUST_REMOVE_NEGATIVE_TESTS_CSV = FOLDERNAME_NEGATIVE_TEST + File.separator + "TrustRemoveNegativeTests.csv";

    public static final String TRUST_PROFILE_CREATION_POSITIVE_TESTS = "TrustProfileCreationPositiveTests";
    public static final String TRUST_PROFILE_CREATION_POSITIVE_TESTS_CSV = FOLDERNAME_POSITIVE_TEST + File.separator
            + "TrustProfileCreationPositiveTests.csv";

    public static final String TRUST_PROFILE_REMOVE_POSITIVE_TESTS = "TrustProfileRemovePositiveTests";
    public static final String TRUST_PROFILE_REMOVE_POSITIVE_TESTS_CSV = FOLDERNAME_POSITIVE_TEST + File.separator
            + "TrustProfileRemovePositiveTests.csv";

    public static final String ENTITY_PROFILE_CREATION_POSITIVE_TESTS = "EntityProfileCreationPositiveTests";
    public static final String ENTITY_PROFILE_CREATION_POSITIVE_TESTS_CSV = FOLDERNAME_POSITIVE_TEST + File.separator
            + "EntityProfileCreatePositiveTests.csv";

    public static final String ENTITY_PROFILE_REMOVE_POSITIVE_TESTS = "EntityProfileRemovePositiveTests";
    public static final String ENTITY_PROFILE_REMOVE_POSITIVE_TESTS_CSV = FOLDERNAME_POSITIVE_TEST + File.separator
            + "EntityProfileRemovePositiveTests.csv";

    public static final String ENTITY_UPDATE_POSITIVE_TESTS = "EntityUpdatePositiveTests";
    public static final String ENTITY_UPDATE_POSITIVE_TESTS_CSV = FOLDERNAME_POSITIVE_TEST + File.separator + "EntityUpdatePositiveTests.csv";

    public static final String SSL_DEFINITION_DATASOURCE = "SslDefinitionDataSource";
    public static final String SSL_DEFINITION_CSV = FOLDERNAME_SSL_DEFINITION_TEST + File.separator + "SslDefinition.csv";

    public static final String SYNTAX_ERROR_ROLE_DEFINITION_TESTS = "syntaxErrorRoleDefinitionTests";
    public static final String SYNTAX_ERROR_ROLE_DEFINITION_TESTS_CSV = FOLDERNAME_NEGATIVE_TEST + File.separator + "ErrorDefinitionRole.csv";

    public static final String SYNTAX_ERROR_CREDENTIAL_TESTS = "syntaxErrorCredentialTests";
    public static final String SYNTAX_ERROR_CREDENTIAL_TESTS_CSV = FOLDERNAME_NEGATIVE_TEST + File.separator + "SyntaxErrorCredentialTests.csv";

    public static final String SYNTAX_ERROR_CREDENTIAL_SNMP_TESTS = "syntaxErrorCredentialSnmpTests";
    public static final String SYNTAX_ERROR_CREDENTIAL_SNMP_TESTS_CSV = FOLDERNAME_NEGATIVE_TEST + File.separator + "SyntaxErrorCredentialSnmpTests.csv";

    public static final String SYNTAX_ERROR_SSH_KEY_TESTS = "syntaxErrorSshKeyTests";
    public static final String SYNTAX_ERROR_SSH_KEY_TESTS_CSV = FOLDERNAME_NEGATIVE_TEST + File.separator + "SyntaxErrorSshKeyTests.csv";

    public static final String SYNTAX_ERROR_CERTIFICATE_ISSUE_TESTS = "syntaxErrorCertificateIssueTests";
    public static final String SYNTAX_ERROR_CERTIFICATE_ISSUE_TESTS_CSV = FOLDERNAME_NEGATIVE_TEST + File.separator
            + "SyntaxErrorCertificateIssueTests.csv";

    public static final String SYNTAX_ERROR_CERTIFICATE_REISSUE_TESTS = "syntaxErrorCertificateReissueTests";
    public static final String SYNTAX_ERROR_CERTIFICATE_REISSUE_TESTS_CSV = FOLDERNAME_NEGATIVE_TEST + File.separator
            + "SyntaxErrorCertificateReissueTests.csv";

    public static final String SYNTAX_ERROR_TRUST_DISTRIBUTE_TESTS = "syntaxErrorTrustDistributeTests";
    public static final String SYNTAX_ERROR_TRUST_DISTRIBUTE_TESTS_CSV = FOLDERNAME_NEGATIVE_TEST + File.separator
            + "SyntaxErrorTrustDistributeTests.csv";

    public static final String SYNTAX_ERROR_TRUST_REMOVE_TESTS = "syntaxErrorTrustRemoveTests";
    public static final String SYNTAX_ERROR_TRUST_REMOVE_TESTS_CSV = FOLDERNAME_NEGATIVE_TEST + File.separator + "SyntaxErrorTrustRemoveTests.csv";

    public static final String JOB_ID_CERTIFICATE_ISSUE_TESTS = "CertificateIssueForJobIdTests";
    public static final String JOB_ID_CERTIFICATE_ISSUE_TESTS_CSV = FOLDERNAME_POSITIVE_TEST + File.separator + "CertificateIssueForJobIdTests.csv";

    public static final String JOB_ID_TRUST_DISTRIBUTE_TESTS = "TrustDistributeForJobIdTests";
    public static final String JOB_ID_TRUST_DISTRIBUTE_TESTS_CSV = FOLDERNAME_POSITIVE_TEST + File.separator + "TrustDistributeForJobIdTests.csv";

    public static final String JOB_ID_TRUST_REMOVE_TESTS = "TrustRemoveForJobIdTests";
    public static final String JOB_ID_TRUST_REMOVE_TESTS_CSV = FOLDERNAME_POSITIVE_TEST + File.separator + "TrustRemoveForJobIdTests.csv";

    public static final String CRLCHECK_POSITIVE_TESTS = "CRLCheckPositiveTests";
    public static final String CRLCHECK_POSITIVE_TESTS_CSV = FOLDERNAME_POSITIVE_TEST + File.separator + "CRLCheckPositiveTests.csv";

    public static final String CRL_CHECK_NEGATIVE_TESTS = "CRLCheckNegativeTests";
    public static final String CRL_CHECK_NEGATIVE_TESTS_CSV = FOLDERNAME_NEGATIVE_TEST + File.separator + "CRLCheckNegativeTests.csv";

    public static final String CRL_CHECK_NO_TRUSTCATEGORY_TESTS = "CRLCheckNoTrustCateegoryTests";
    public static final String CRL_CHECK_NO_TRUSTCATEGORY_TESTS_CSV = FOLDERNAME_NEGATIVE_TEST + File.separator + "CRLCheckNoTrustCategoryTest.csv";

    public static final String CRL_CHECK_NEGATIVE_TESTS_Unsupported_Release_Version = "CRLCheckNegativeUnsuppotedReleaseVersionTests";
    public static final String CRL_CHECK_NEGATIVE_TESTS_Unsupported_Release_Version_CSV = FOLDERNAME_NEGATIVE_TEST + File.separator
            + "CRLCheckNegativeUnsuppotedReleaseVersionTest.csv";

    // G1 nodes CRL Check
    public static final String G1_CRLCHECK_POSITIVE_TESTS = "G1CRLCheckPositiveTests";
    public static final String G1_CRLCHECK_POSITIVE_TESTS_CSV = FOLDERNAME_POSITIVE_TEST + File.separator + "G1CRLCheckPositiveTests.csv";

    public static final String G1_CRLCHECK_NEGATIVE_TESTS = "G1CRLCheckNegativeTests";
    public static final String G1_CRLCHECK_NEGATIVE_TESTS_CSV = FOLDERNAME_NEGATIVE_TEST + File.separator + "G1CRLCheckNegativeTests.csv";

    public static final String CRLCHECK_MULTIPLE_NODES_NEGATIVE_TESTS = "G1CRLCheckMultipleNodesNegativeTests";
    public static final String CRLCHECK_MULTIPLE_NODES_NEGATIVE_TESTS_CSV = FOLDERNAME_NEGATIVE_TEST + File.separator
            + "G1CRLCheckMultipleNodesNegativeTests.csv";

    public static final String SECURITY_NODES_G1_CRLCHECK_LOCAL = "SecurityNodeList_G1_CRLCheck_local";
    public static final String SECURITY_NODES_G1_CRLCHECK_LOCAL_CSV = FOLDERNAME_NODES_TEST + File.separator
            + "SecurityNodeList_G1_CRLCheck_local.csv";

    public static final String SECURITY_NODES_RBAC_LOCAL = "SecurityNodeList_G1_CRLCheck_RBAC_local";
    public static final String SECURITY_NODES_RBAC_LOCAL_CSV = FOLDERNAME_NODES_TEST + File.separator + "SecurityNodeList_G1_CRLCheck_RBAC_local.csv";

    public static final String G1_CRLCHECK_POSITIVE_RBAC_TESTS = "G1CRLCheckPositiveRbacTests";
    public static final String G1_CRLCHECK_POSITIVE_RBAC_TESTS_CSV = FOLDERNAME_POSITIVE_TEST + File.separator + "G1CRLCheckPositiveRbacTests.csv";

    public static final String SECURITY_NODES_CIPHER_MODERNIZATION_LOCAL = "SecurityNodeList_Cipher_Modernization_local.csv";
    public static final String SECURITY_NODES_CIPHER_MODERNIZATION_LOCAL_CSV = FOLDERNAME_NODES_TEST + File.separator
            + "SecurityNodeList_Cipher_Modernization_local.csv";

    // Cipher Modernization - Set Ciphers
    public static final String SET_CIPHERS_POSITIVE_TESTS = "SetCiphersPositiveTests";
    public static final String SET_CIPHERS_POSITIVE_TESTS_CSV = FOLDERNAME_POSITIVE_TEST + File.separator + "SetCiphersPositiveTests.csv";

    // RTSEL
    public static final String SECURITY_NODES_RTSEL_LOCAL = "SecurityNodeList_RTSEL_local";
    public static final String SECURITY_NODES_RTSEL_LOCAL_CSV = FOLDERNAME_NODES_TEST + File.separator + "SecurityNodeList_RTSEL_local.csv";

    public static final String RTSEL_POSITIVE_TESTS = "RTSELPositiveTests";
    public static final String RTSEL_POSITIVE_TESTS_CSV = FOLDERNAME_POSITIVE_TEST + File.separator + "RTSELPositiveTests.csv";

    public static final String RTSEL_NEGATIVE_TESTS = "RTSELNegativeTests";
    public static final String RTSEL_NEGATIVE_TESTS_CSV = FOLDERNAME_NEGATIVE_TEST + File.separator + "RTSELNegativeTests.csv";

    // PIB
    public static final String LDAP_PIB_GET_PARAMS_CSV = "LdapPibGetParameters.csv";
    public static final String LDAP_PIB_SET_PARAMS_CSV = "LdapPibSetParameters.csv";
    public static final String EXTERNAL_LDAP_PIB_SET_PARAMS_CSV = "extLdap" + File.separator + "ExternalLdapPibSetParameters.csv";
}
