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

/**
 * SecurityConstants.
 */
@SuppressWarnings({"PMD.ClassNamingConventions"})
public class SecurityConstants {

    public static final String FOLDERNAME_NETSIM_TEST = "netsim";
    public static final String FOLDERNAME_NEGATIVE_TEST = "negative_tests";
    public static final String FOLDERNAME_POSITIVE_TEST = "positive_tests";
    public static final String FOLDERNAME_NODES_TEST = "nodes";
    public static final String FOLDERNAME_USERS_TEST = "users";
    public static final String FOLDERNAME_SSL_DEFINITION_TEST = "SslDefinition";

    public static final int V_USERS = 1;

    // "PROFILE_*" here are the allowed values of the 'nscs.profiles' property
    // Values of column SUITE_PROFILE in csv files
    public static final String PROFILE_MAINTRACK = "maintrack";
    public static final String PROFILE_EXTRA = "extra";
    public static final String PROFILE_FULL = "full";
    public static final String PROFILE_SETUP = "setup";
    // Name of column SUITE_PROFILE in csv files for positive/negative test, used:
    // 1) in Setup, by loadDataSourcesByProfile()
    // 2) in Tests, by filter "byProfile" to select which rows to run
    public static final String SUITE_PROFILE = "suiteProfile";

    public static final String DELETENODES_DEFAULT = "true";

    public static final int CREDENTIAL_DELAY = 2000;
    public static final int CREDENTIAL_ITERATION = 5;

    public static final String TEST_TYPE = "testType";
    public static final String CERT_TYPE = "certType";

    public static final String STEP = "step";

    public static final String CREATE_RBAC = "createRbac";
    public static final String CERT_ISSUE_RBAC = "certIssueRbac";

    public static final String CERT_TYPE_OAM = "OAM";
    public static final String CERT_TYPE_IPSEC = "IPSEC";

    // cmedit operations
    public static final String NETWORK_ELEMENT_ID = "networkElementId";
    public static final String NETWORK_ELEMENT_RANGE = "networkElementRange";
    public static final String NODE_TYPE = "nodeType";
    public static final String SYNC = "sync";
    public static final String OSS_PREFIX = "ossPrefix";
    public static final String NODE_INDEX = "nodeindex";
    public static final String START = "start";

    // user and password
    public static final String NETSIM_DEFAULT_USER_NAME = "netsim";

    protected SecurityConstants() {
    }
}
