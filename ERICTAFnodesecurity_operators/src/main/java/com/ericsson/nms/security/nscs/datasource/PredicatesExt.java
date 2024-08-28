package com.ericsson.nms.security.nscs.datasource;


import static com.ericsson.nms.security.nscs.constants.SecurityConstants.CERT_ISSUE_RBAC;
import static com.ericsson.nms.security.nscs.constants.SecurityConstants.CERT_TYPE;
import static com.ericsson.nms.security.nscs.constants.SecurityConstants.CERT_TYPE_IPSEC;
import static com.ericsson.nms.security.nscs.constants.SecurityConstants.CERT_TYPE_OAM;
import static com.ericsson.nms.security.nscs.constants.SecurityConstants.CREATE_RBAC;
import static com.ericsson.nms.security.nscs.constants.SecurityConstants.NODE_TYPE;
import static com.ericsson.nms.security.nscs.constants.SecurityConstants.START;
import static com.ericsson.nms.security.nscs.constants.SecurityConstants.STEP;
import static com.ericsson.nms.security.nscs.constants.SecurityConstants.SUITE_PROFILE;
import static com.ericsson.nms.security.nscs.constants.SecurityConstants.SYNC;
import static com.ericsson.nms.security.nscs.constants.SecurityConstants.TEST_TYPE;
import static com.ericsson.nms.security.nscs.constants.UserRoleValues.ROLE_CREDENTIAL;
import static com.ericsson.nms.security.nscs.constants.UserRoleValues.ROLE_GET_CREDENTIALS;
import static com.ericsson.nms.security.nscs.constants.UserRoleValues.ROLE_GET_SNMP_CREDENTIALS;
import static com.ericsson.nms.security.nscs.constants.UserRoleValues.ROLE_IPSEC;
import static com.ericsson.nms.security.nscs.constants.UserRoleValues.ROLE_OAM;
import static com.ericsson.nms.security.nscs.constants.UserRoleValues.ROLE_SSH_KEY;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.cifwk.taf.datasource.DataRecord;
import com.ericsson.nms.security.nscs.constants.SecurityConstants;
import com.ericsson.nms.security.nscs.data.RbacErrorsValue;
import com.ericsson.nms.security.nscs.utils.UtilContext;
import com.ericsson.nms.security.nscs.utils.Utils;
import com.ericsson.oss.testware.enmbase.data.ENMUser;
import com.ericsson.oss.testware.enmbase.data.NodeType;
import com.google.common.base.Predicate;
import com.google.common.collect.Lists;

@SuppressWarnings({"PMD.LawOfDemeter", "PMD.ClassNamingConventions", "PMD.ExcessiveImports", "PMD.TooManyFields", "PMD.UseUtilityClass", "PMD.ExcessivePublicCount"})
public class PredicatesExt {

    private static final Logger log = LoggerFactory.getLogger(PredicatesExt.class);

    public static Predicate cmOperatorUsers = new Predicate<ENMUser>() {
        @Override
        public boolean apply(final ENMUser dataRecord) {
            return containsRole(dataRecord, "OPERATOR");
        }
    };

    public static Predicate cmSecurityAdminUsers = new Predicate<ENMUser>() {
        @Override
        public boolean apply(final ENMUser dataRecord) {
            return containsRole(dataRecord, "SECURITY_ADMIN");
        }
    };

    public static Predicate cmCredentialUsers = new Predicate<ENMUser>() {
        @Override
        public boolean apply(final ENMUser dataRecord) {
            return containsRole(dataRecord, ROLE_CREDENTIAL);
        }
    };

    public static Predicate getCredentialsUsers = new Predicate<ENMUser>() {
        @Override
        public boolean apply(final ENMUser dataRecord) {
            return containsRole(dataRecord, ROLE_GET_CREDENTIALS);
        }
    };

    public static Predicate cmSshkeyUsers = new Predicate<ENMUser>() {
        @Override
        public boolean apply(final ENMUser dataRecord) {
            return containsRole(dataRecord, ROLE_SSH_KEY);
        }
    };

    public static Predicate cmOamUsers = new Predicate<ENMUser>() {
        @Override
        public boolean apply(final ENMUser dataRecord) {
            return containsRole(dataRecord, ROLE_OAM);
        }
    };

    public static Predicate cmIpsecUsers = new Predicate<ENMUser>() {
        @Override
        public boolean apply(final ENMUser dataRecord) {
            return containsRole(dataRecord, ROLE_IPSEC);
        }
    };

    public static Predicate cmFieldTechnicianUsers = new Predicate<ENMUser>() {
        @Override
        public boolean apply(final ENMUser dataRecord) {
            return containsRole(dataRecord, "FIELD_TECHNICIAN");
        }
    };
    public static Predicate<RbacErrorsValue> errorCredentialUsers = new Predicate<RbacErrorsValue>() {
        @Override
        public boolean apply(final RbacErrorsValue dataRecord) {
            return notContainsRole(dataRecord, ROLE_CREDENTIAL);
        }
    };
    public static Predicate<RbacErrorsValue> errorSshkeyUsers = new Predicate<RbacErrorsValue>() {
        @Override
        public boolean apply(final RbacErrorsValue dataRecord) {
            return notContainsRole(dataRecord, ROLE_SSH_KEY);
        }
    };
    public static Predicate<RbacErrorsValue> errorOamUsers = new Predicate<RbacErrorsValue>() {
        @Override
        public boolean apply(final RbacErrorsValue dataRecord) {
            return notContainsRole(dataRecord, ROLE_OAM);
        }
    };
    public static Predicate<RbacErrorsValue> errorIpsecUsers = new Predicate<RbacErrorsValue>() {
        @Override
        public boolean apply(final RbacErrorsValue dataRecord) {
            return notContainsRole(dataRecord, ROLE_IPSEC);
        }
    };
    public static Predicate<DataRecord> createRbac = new Predicate<DataRecord>() {
        @Override
        public boolean apply(final DataRecord dataRecord) {
            return CREATE_RBAC.equals(dataRecord.getFieldValue(TEST_TYPE)) && filterByProfile(dataRecord);
        }
    };

    public static Predicate<DataRecord> certIssueRbacOAM = new Predicate<DataRecord>() {
        @Override
        public boolean apply(final DataRecord dataRecord) {
            return CERT_ISSUE_RBAC.equals(dataRecord.getFieldValue(TEST_TYPE)) && CERT_TYPE_OAM.equals(dataRecord.getFieldValue(CERT_TYPE))
                    && filterByProfile(dataRecord);
        }
    };

    public static Predicate<DataRecord> certIssueRbacIPsec = new Predicate<DataRecord>() {
        @Override
        public boolean apply(final DataRecord dataRecord) {
            return CERT_ISSUE_RBAC.equals(dataRecord.getFieldValue(TEST_TYPE)) && CERT_TYPE_IPSEC.equals(dataRecord.getFieldValue(CERT_TYPE))
                    && filterByProfile(dataRecord);
        }
    };

    public static Predicate<DataRecord> nodesToSyncPico = new Predicate<DataRecord>() {
        @Override
        public boolean apply(final DataRecord dataRecord) {
            final String nodeSync = dataRecord.getFieldValue(SYNC);
            final String nodeType = dataRecord.getFieldValue(NODE_TYPE);
            return nodeSync != null && nodeSync.equals("sync") && NodeType.MSRBS_V1.toString().equals(nodeType) && filterByProfile(dataRecord);
        }
    };

    public static Predicate<DataRecord> nodesToSync = new Predicate<DataRecord>() {
        @Override
        public boolean apply(final DataRecord dataRecord) {
            final String nodeToSync = dataRecord.getFieldValue(SYNC);
            return "sync".equals(nodeToSync) && filterByProfile(dataRecord);
        }
    };

    public static Predicate<DataRecord> nodesToStart = new Predicate<DataRecord>() {
        @Override
        public boolean apply(final DataRecord dataRecord) {
            final String toStart = dataRecord.getFieldValue(START);
            return "start".equals(toStart) && filterByProfile(dataRecord);
        }
    };

    public static Predicate<DataRecord> trustDistrCT = new Predicate<DataRecord>() {
        @Override
        public boolean apply(final DataRecord dataRecord) {
            final String value = dataRecord.getFieldValue(TEST_TYPE);
            return value.startsWith("trustDistrCT_") && filterByProfile(dataRecord);
        }
    };

    public static Predicate<DataRecord> trustDistrCA = new Predicate<DataRecord>() {
        @Override
        public boolean apply(final DataRecord dataRecord) {
            final String value = dataRecord.getFieldValue(TEST_TYPE);
            return value.startsWith("trustDistrCA_") && filterByProfile(dataRecord);
        }
    };

    public static Predicate<DataRecord> createTest = new Predicate<DataRecord>() {
        @Override
        public boolean apply(final DataRecord dataRecord) {
            final String value = dataRecord.getFieldValue(TEST_TYPE);
            return value.equals("create");
        }
    };

    public static Predicate<DataRecord> createSNMPv3Test = new Predicate<DataRecord>() {
        @Override
        public boolean apply(final DataRecord dataRecord) {
            final String value = dataRecord.getFieldValue(TEST_TYPE);
            return value.equals("createSnmp") && filterByProfile(dataRecord);
        }
    };

    public static Predicate<DataRecord> createCredSNMPv3Test = new Predicate<DataRecord>() {
        @Override
        public boolean apply(final DataRecord dataRecord) {
            final String value = dataRecord.getFieldValue(TEST_TYPE);
            return value.equals("createCredSnmp") && filterByProfile(dataRecord);
        }
    };

    public static Predicate<DataRecord> updateTest = new Predicate<DataRecord>() {
        @Override
        public boolean apply(final DataRecord dataRecord) {
            final String value = dataRecord.getFieldValue(TEST_TYPE);
            return value.equals("update");
        }
    };

    public static Predicate<DataRecord> getCredTest = new Predicate<DataRecord>() {
        @Override
        public boolean apply(final DataRecord dataRecord) {
            final String value = dataRecord.getFieldValue(TEST_TYPE);
            return value.equals("get") && filterByProfile(dataRecord);
        }
    };

    public static Predicate<DataRecord> getCredSNMPv3Test = new Predicate<DataRecord>() {
        @Override
        public boolean apply(final DataRecord dataRecord) {
            final String value = dataRecord.getFieldValue(TEST_TYPE);
            return value.equals("getSnmp") && filterByProfile(dataRecord);
        }
    };

    public static Predicate<DataRecord> getCredSNMPv3RbacTest = new Predicate<DataRecord>() {
        @Override
        public boolean apply(final DataRecord dataRecord) {
            final String value = dataRecord.getFieldValue(TEST_TYPE);
            return value.equals("getSnmpRbac") && filterByProfile(dataRecord);
        }
    };

    public static Predicate getCredentialsSNMPUsers = new Predicate<ENMUser>() {
        @Override
        public boolean apply(final ENMUser dataRecord) {
            return containsRole(dataRecord, ROLE_GET_SNMP_CREDENTIALS);
        }
    };

    public static Predicate<DataRecord> credentialAlreadyDefined = new Predicate<DataRecord>() {
        @Override
        public boolean apply(final DataRecord dataRecord) {
            final String value = dataRecord.getFieldValue(TEST_TYPE);
            return value.equals("credentialAlreadyDefined") && filterByProfile(dataRecord);
        }
    };

    public static Predicate<DataRecord> credentialToBeDefined = new Predicate<DataRecord>() {
        @Override
        public boolean apply(final DataRecord dataRecord) {
            final String value = dataRecord.getFieldValue(TEST_TYPE);
            return value.equals("credentialToBeDefined") && filterByProfile(dataRecord);
        }
    };

    public static Predicate<DataRecord> credentialGenericError = new Predicate<DataRecord>() {
        @Override
        public boolean apply(final DataRecord dataRecord) {
            final String value = dataRecord.getFieldValue(TEST_TYPE);
            return value.equals("credentialGenericError") && filterByProfile(dataRecord);
        }
    };

    public static Predicate<DataRecord> deleteNodes = new Predicate<DataRecord>() {
        @Override
        public boolean apply(final DataRecord dataRecord) {
            return filterByDeleteNodes(dataRecord);
        }
    };

    public static Predicate<DataRecord> sshKeyStaticError = new Predicate<DataRecord>() {
        @Override
        public boolean apply(final DataRecord dataRecord) {
            final String value = dataRecord.getFieldValue(TEST_TYPE);
            return value.equals("sshKeyStaticError") && filterByProfile(dataRecord);
        }
    };

    public static Predicate<DataRecord> sshkeyAlreadyGenerated = new Predicate<DataRecord>() {
        @Override
        public boolean apply(final DataRecord dataRecord) {
            final String value = dataRecord.getFieldValue(TEST_TYPE);
            return value.equals("sshkeyAlreadyGenerated") && filterByProfile(dataRecord);
        }
    };

    public static Predicate<DataRecord> sshkeyNotFound = new Predicate<DataRecord>() {
        @Override
        public boolean apply(final DataRecord dataRecord) {
            final String value = dataRecord.getFieldValue(TEST_TYPE);
            return value.equals("sshkeyNotFound") && filterByProfile(dataRecord);
        }
    };

    public static Predicate<DataRecord> testByCertType = new Predicate<DataRecord>() {
        @Override
        public boolean apply(final DataRecord dataRecord) {
            final String value = dataRecord.getFieldValue(TEST_TYPE);
            return value.startsWith("CT_") && filterByProfile(dataRecord);
        }
    };

    public static Predicate<DataRecord> testByCA = new Predicate<DataRecord>() {
        @Override
        public boolean apply(final DataRecord dataRecord) {
            final String value = dataRecord.getFieldValue(TEST_TYPE);
            return value.startsWith("CA_") && filterByProfile(dataRecord);
        }
    };


    public static Predicate<DataRecord> buildNetsimObjectsIpsec = new Predicate<DataRecord>() {
        @Override
        public boolean apply(final DataRecord dataRecord) {
            final String nodeType = dataRecord.getFieldValue(NODE_TYPE);
            return dataRecord.getFieldValue("buildNetsimObjects") != null && nodeType.equals("ERBS") && filterByProfile(dataRecord);
        }
    };

    public static Predicate<DataRecord> buildNetsimObjectsRadioNode = new Predicate<DataRecord>() {
        @Override
        public boolean apply(final DataRecord dataRecord) {
            final String nodeType = dataRecord.getFieldValue(NODE_TYPE);
            return dataRecord.getFieldValue("buildNetsimObjects") != null
                    && ("RadioNode".equals(nodeType) || "VTFRadioNode".equals(nodeType) || "vRM".equals(nodeType) || "MSRBS_V1".equals(nodeType) || "5GRadioNode".equals(nodeType) || "vPP".equals(nodeType)|| "vRC".equals(nodeType))
                    && filterByProfile(dataRecord);
        }
    };

    public static Predicate<DataRecord> erbsByProfile = new Predicate<DataRecord>() {
        @Override
        public boolean apply(final DataRecord dataRecord) {
            final String nodeType = dataRecord.getFieldValue(NODE_TYPE);
            return NodeType.ERBS.toString().equals(nodeType) && filterByProfile(dataRecord);
        }
    };

    public static Predicate<DataRecord> certIssueByProfile = new Predicate<DataRecord>() {
        @Override
        public boolean apply(final DataRecord dataRecord) {
            final String testType = dataRecord.getFieldValue(TEST_TYPE);
            return !testType.contains("Rbac") && filterByProfile(dataRecord);
        }
    };

    public static Predicate<DataRecord> certIssueByProfileErbs = new Predicate<DataRecord>() {
        @Override
        public boolean apply(final DataRecord dataRecord) {
            final String testType = dataRecord.getFieldValue(TEST_TYPE);
            final String nodeType = dataRecord.getFieldValue(NODE_TYPE);
            return !testType.contains("Rbac") && filterByProfile(dataRecord) && NodeType.ERBS.toString().equals(nodeType);
        }
    };

    public static Predicate<DataRecord> certIssueByProfileBsc = new Predicate<DataRecord>() {
        @Override
        public boolean apply(final DataRecord dataRecord) {
            final String testType = dataRecord.getFieldValue(TEST_TYPE);
            final String nodeType = dataRecord.getFieldValue(NODE_TYPE);
            return !testType.contains("Rbac") && filterByProfile(dataRecord) && NodeType.BSC.toString().equals(nodeType);
        }
    };

    public static Predicate<DataRecord> certIssueByProfilePicoNode = new Predicate<DataRecord>() {
        @Override
        public boolean apply(final DataRecord dataRecord) {
            final String testType = dataRecord.getFieldValue(TEST_TYPE);
            final String nodeType = dataRecord.getFieldValue(NODE_TYPE);
            return !testType.contains("Rbac") && filterByProfile(dataRecord) && NodeType.MSRBS_V1.toString().equals(nodeType);
        }
    };

    public static Predicate<DataRecord> byProfile = new Predicate<DataRecord>() {
        @Override
        public boolean apply(final DataRecord dataRecord) {
            log.info("starting byProfile... profile " + UtilContext.makeUtilContext().readSuiteProfile());
            return filterByProfile(dataRecord);
        }
    };

    public static Predicate<DataRecord> beforeStep = new Predicate<DataRecord>() {
        @Override
        public boolean apply(final DataRecord dataRecord) {
            final String step = dataRecord.getFieldValue(STEP);
            return step.contains("before") && filterByProfile(dataRecord);
        }
    };

    public static Predicate<DataRecord> afterStep = new Predicate<DataRecord>() {
        @Override
        public boolean apply(final DataRecord dataRecord) {
            final String step = dataRecord.getFieldValue(STEP);
            return step.contains("after") && filterByProfile(dataRecord);
        }
    };
    public static Predicate<DataRecord> g1CRLCheck = new Predicate<DataRecord>() {
        @Override
        public boolean apply(final DataRecord dataRecord) {
            final String step = dataRecord.getFieldValue("operation");
            return step.contains("nonRead") && filterByProfile(dataRecord);
        }
    };
    public static Predicate<DataRecord> g1CRLCheckRead = new Predicate<DataRecord>() {
        @Override
        public boolean apply(final DataRecord dataRecord) {
            final String step = dataRecord.getFieldValue("operation");
            if (step != null) {
                return step.contains("read") && filterByProfile(dataRecord);
            }
            return false;
        }
    };
    public static Predicate nodeSecurityAdminUsers = new Predicate<ENMUser>() {
        @Override
        public boolean apply(final ENMUser dataRecord) {
            return containsRole(dataRecord, "NodeSecurity_Administrator");
        }
    };
    public static Predicate nodeSecurityOperUsers = new Predicate<ENMUser>() {
        @Override
        public boolean apply(final ENMUser dataRecord) {
            return containsRole(dataRecord, "NodeSecurity_Operator");
        }
    };

    private static boolean containsRole(final ENMUser dataRecord, final String role) {
        final String[] roles = dataRecord.getRoles();
        final String enable = dataRecord.getEnabled().toString();
        return Lists.newArrayList(roles).contains(role) && enable.equals("true");
    }

    private static boolean notContainsRole(final RbacErrorsValue dataRecord, final String role) {
        return !Lists.newArrayList(dataRecord.getRoles()).contains(role);
    }

    public static boolean filterByProfile(final String suiteProfile) {
        return checkProfile(suiteProfile);
    }

    public static boolean filterByProfile(final DataRecord dataRecord) {
        final String value = dataRecord.getFieldValue(SUITE_PROFILE);
        return checkProfile(value);
    }

    private static boolean checkProfile(final String value) {
        if (SecurityConstants.PROFILE_MAINTRACK.equals(UtilContext.makeUtilContext().readSuiteProfile())) {
            return SecurityConstants.PROFILE_MAINTRACK.equals(value);
        } else if (SecurityConstants.PROFILE_EXTRA.equals(UtilContext.makeUtilContext().readSuiteProfile())) {
            return SecurityConstants.PROFILE_EXTRA.equals(value);
        } else if (SecurityConstants.PROFILE_FULL.equals(UtilContext.makeUtilContext().readSuiteProfile())) {
            return SecurityConstants.PROFILE_MAINTRACK.equals(value) || SecurityConstants.PROFILE_EXTRA.equals(value);
        } else {
            return value.equals(SecurityConstants.PROFILE_SETUP);
        }
    }

    private static boolean filterByDeleteNodes(final DataRecord dataRecord) {
        return Boolean.parseBoolean(Utils.getDeleteNodes()) && filterByProfile(dataRecord);
    }

    public static Predicate<DataRecord> rtselActivate = new Predicate<DataRecord>() {
        @Override
        public boolean apply(final DataRecord dataRecord) {
            final String step = dataRecord.getFieldValue("operation");
            return step.equals("activate") && filterByProfile(dataRecord);
        }
    };

    public static Predicate<DataRecord> rtselDeactivateGet = new Predicate<DataRecord>() {
        @Override
        public boolean apply(final DataRecord dataRecord) {
            final String step = dataRecord.getFieldValue("operation");
            return step.equals("deactivate_get") && filterByProfile(dataRecord);
        }
    };

    public static Predicate<DataRecord> rtselDelete = new Predicate<DataRecord>() {
        @Override
        public boolean apply(final DataRecord dataRecord) {
            final String step = dataRecord.getFieldValue("operation");
            return step.equals("delete") && filterByProfile(dataRecord);
        }
    };

    public static Predicate<DataRecord> extLdapContextFilter(final String i) {

        final Predicate<DataRecord> getIthRecord = new Predicate<DataRecord>() {
            @Override
            public boolean apply(final DataRecord dataRecord) {
                final String context = dataRecord.getFieldValue("context");
                return context.equals(i);
            }
        };
        return getIthRecord;
    }
}
