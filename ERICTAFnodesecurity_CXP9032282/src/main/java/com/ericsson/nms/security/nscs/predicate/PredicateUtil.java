/*
 * ------------------------------------------------------------------------------
 * ******************************************************************************
 * COPYRIGHT Ericsson 2016
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 * ******************************************************************************
 * ----------------------------------------------------------------------------
 */

package com.ericsson.nms.security.nscs.predicate;

import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

import javax.inject.Inject;

import com.ericsson.cifwk.taf.TafTestBase;
import com.ericsson.cifwk.taf.TafTestContext;
import com.ericsson.cifwk.taf.TestContext;
import com.ericsson.cifwk.taf.datasource.DataRecord;
import com.ericsson.oss.testware.enmbase.data.NodeType;
import com.ericsson.oss.testware.enmbase.helpers.NodeTypeHelper;
import com.google.common.base.Predicate;
import com.google.common.base.Predicates;
import org.apache.commons.validator.routines.InetAddressValidator;

import static com.ericsson.nms.security.nscs.constants.UserRoleValues.*;


/**
 * SetupAndTearDownUtil necessary operations that must be executed before and after every test suite.
 */
@SuppressWarnings({"PMD.LawOfDemeter"})
public abstract class PredicateUtil extends TafTestBase {

    public static final String COLUMN_NODE_TYPE = "nodeType";
    public static final String COLUMN_IPADDRESS = "ipAddress";

    @Inject
    protected TestContext context;

    //USER PREDICATES

    public static Predicate<DataRecord> passTrue() {
        return new Predicate<DataRecord>() {
            @Override
            public boolean apply(final DataRecord input) {
                return true;
            }
        };
    }

    public static Predicate<DataRecord> nsuLdap() {
        return userRolePredicate("roles", Arrays.asList(ROLE_LDAP));
    }

    public static Predicate<DataRecord> nsuLdapRest() {
        return userRolePredicate("roles", Arrays.asList(ROLE_LDAP_REST));
    }


    public static Predicate<DataRecord> nsuGenEnrollmentInfoRest() {
        return userRolePredicate("roles", Arrays.asList(ROLE_GENERATE_ENROLLMENT_INFO_REST));
    }

    public static Predicate<DataRecord> nsuAdm() {
        return userRolePredicate("roles", Arrays.asList(ROLE_NODESECURITY_ADMIN));
    }

    public static Predicate<DataRecord> rfa250Predicate() {
        return PredicateUtil.genericPredicate("RFA250", Arrays.asList("y"));
    }

    public static Predicate<DataRecord> nsuTrustOperatorRole() {
        return userRolePredicate("roles",
                Arrays.asList(ROLE_TRUST_OPERATOR));
    }


    public static Predicate<DataRecord> nsuCredentialRole() {
        return userRolePredicate("roles",
                Arrays.asList(ROLE_CREDENTIAL));
    }

    public static Predicate<DataRecord> nsuGetCredentialRole() {
        return userRolePredicate("roles",
                Arrays.asList(ROLE_GET_CREDENTIALS));
    }

    public static Predicate<DataRecord> nscsSetupTeardownAdm() {
        return Predicates.and(
                userRolePredicate("roles", Arrays.asList(ROLE_NODESECURITY_ADMIN)),
                userRolePredicate("roles", Arrays.asList("Cmedit_Administrator")));
    }

    public static Predicate<DataRecord> nsuOper() {
        return userRolePredicate("roles", Arrays.asList(ROLE_NODESECURITY_OPERATOR));
    }

    public static Predicate<DataRecord> oper() {
        return userRolePredicate("roles", Arrays.asList(ROLE_OPERATOR));
    }

    public static Predicate<DataRecord> nsuTbac() {
        return genericPredicate("description", Arrays.asList("TBAC user"));
    }

    public static Predicate<DataRecord> nscsTbac() {
        return Predicates.and(nsuAdm(), nsuTbac());
    }

    public static Predicate<DataRecord> nsuLocalRbac() {
        return genericPredicate("description", Arrays.asList("LocalRbacUser"));
    }

    public static Predicate<DataRecord> nscsLocalRbac() {
        return Predicates.and(nscsAdm(), nsuLocalRbac());
    }

    public static Predicate<DataRecord> nscsAdm() {
        return Predicates.and(nsuAdm(), Predicates.not(nsuTbac()));
    }

    public static Predicate<DataRecord> nscsOper() {
        return nsuOper();
    }

    public static Predicate<DataRecord> nsuPrivacyAdm() {
        return Predicates.and(userRolePredicate("roles", Arrays.asList(ROLE_NODESECURITY_ADMIN)),
                userRolePredicate("roles", Arrays.asList(ROLE_LOGVIEWER_PRIVACY_ADMIN)));
    }

    public static Predicate<DataRecord> snmpNbi() {
        return userRolePredicate("roles",
                Arrays.asList("update_credentials_snmp_nbi_role"));
    }

    //NODE PREDICATES
    public static Predicate<DataRecord> netSimTestPredicate() {
        return netSimPredicate("nodeOperatorType", "NETSIM");
    }

    public static Predicate<DataRecord> netArnlPredicate() {
        return netSimPredicate("nodeOperatorType", "REAL_NODE");
    }

    public static Predicate<DataRecord> netSimPredicate(final String columnName, final String columnValues) {
        return new com.google.common.base.Predicate<DataRecord>() {
            @Override
            public boolean apply(final DataRecord input) {
                if (input == null || columnName == null) {
                    return true;
                }
                final Object value = input.getFieldValue(columnName);
                if (value == null) {
                    return true;
                } else if (value instanceof String) {
                    return value.equals(columnValues);
                }
                return true;
            }
        };
    }

    public static Predicate<DataRecord> contextFilter(final String i) {

        final Predicate<DataRecord> getIthRecord = new Predicate<DataRecord>() {
            @Override
            public boolean test(final DataRecord dataRecord) {
                final String context = dataRecord.getFieldValue("context");
                return context.equals(i);
            }
            @Override
            public boolean apply(final DataRecord dataRecord) {
                final String context = dataRecord.getFieldValue("context");
                return context.equals(i);
            }
        };
        return getIthRecord;
    }

    public static Predicate<DataRecord> suiteNamePredicate(final String columnName, final String columnValues) {
        return new com.google.common.base.Predicate<DataRecord>() {
            @Override
            public boolean apply(final DataRecord input) {
                if (input == null || columnName == null) {
                    return true;
                }
                final Object value = input.getFieldValue(columnName);
                if (value == null) {
                    return true;
                } else if (value instanceof String) {
                    if (((String) value).contains(",")) {
                        final String nodeTypeValue = (String) value;
                        final List<String> nodeTypeList = Arrays.asList(nodeTypeValue.split(","));
                        return nodeTypeList.contains(columnValues);
                    } else {
                        return columnValues.equals(value);
                    }
                }
                return true;
            }
        };
    }

    public static Predicate<DataRecord> userRolePredicate(final String columnName, final List<String> columnValues) {
        return new com.google.common.base.Predicate<DataRecord>() {
            @Override
            public boolean apply(final DataRecord input) {
                final boolean find = false;
                if (input == null || columnName == null || columnValues == null || columnValues.isEmpty()) {
                    return find;
                }
                final Object value = input.getFieldValue(columnName);
                //FROM TDM (TDM BUG)
                if (value instanceof String) {
                    for (int i = 0; i < columnValues.size(); i++) {
                        if (((String) value).contains(columnValues.get(i))) {
                            return true;
                        }
                    }
                }
                //FROM LOCAL CSV
                else if (value instanceof String[]) {
                    final List<String> valueValue = Arrays.asList((String[]) value);
                    for (int i = 0; i < valueValue.size(); i++) {
                        for (int ii = 0; ii < columnValues.size(); ii++) {
                            if (valueValue.get(i).contains(columnValues.get(ii))) {
                                return true;
                            }
                        }
                    }
                }
                return find;
            }
        };
    }

    public static Predicate<DataRecord> userRoleSuiteNamePredicate(final String columnName, final List<String> columnValues) {
        return new com.google.common.base.Predicate<DataRecord>() {
            @Override
            public boolean apply(final DataRecord input) {
                final boolean find = false;
                if (input == null || columnName == null || columnValues == null || columnValues.isEmpty()) {
                    return find;
                }
                final Object value = input.getFieldValue(columnName);
                //FROM TDM (TDM BUG)
                if (value instanceof String) {
                    for (int i = 0; i < columnValues.size(); i++) {
                        if (((String) value).contains(columnValues.get(i))) {
                            return true;
                        }
                    }
                }
                //FROM LOCAL CSV
                else if (value instanceof String[]) {
                    final List<String> valueValue = Arrays.asList((String[]) value);
                    for (int i = 0; i < valueValue.size(); i++) {
                        for (int ii = 0; ii < columnValues.size(); ii++) {
                            if (valueValue.get(i).contains(columnValues.get(ii))) {
                                return true;
                            }
                        }
                    }
                }
                return find;
            }
        };
    }

    public static Predicate<DataRecord> genericPredicate(final String columnName, final List<String> columnValues) {
        return new com.google.common.base.Predicate<DataRecord>() {
            @Override
            public boolean apply(final DataRecord input) {
                final boolean find = false;
                if (input == null || columnName == null || columnValues == null || columnValues.isEmpty()) {
                    return find;
                }

                final Object value = input.getFieldValue(columnName);
                if (value instanceof String) {
                    if (!((String) value).contains(",")) {
                        for (int i = 0; i < columnValues.size(); i++) {
                            if (value.equals(columnValues.get(i))) {
                                return true;
                            }
                        }
                    } else {
                        final String[] valueList = ((String) value).split(",");
                        for (int ii = 0; ii < valueList.length; ii++) {
                            for (int i = 0; i < columnValues.size(); i++) {
                                if (valueList[ii].equals(columnValues.get(i))) {
                                    return true;
                                }
                            }
                        }
                    }
                } else if (value instanceof String[]) {
                    final String[] valueList = (String[]) value;
                    for (int ii = 0; ii < valueList.length; ii++) {
                        for (int i = 0; i < columnValues.size(); i++) {
                            if (valueList[ii].equals(columnValues.get(i))) {
                                return true;
                            }
                        }
                    }
                }
                return find;
            }
        };
    }

    public static Predicate<DataRecord> isIpv4Node = new Predicate<DataRecord>() {
        @Override
        public boolean apply(final DataRecord dataRecord) {
            String ipAddress = "";
            if (dataRecord.getFieldValue(COLUMN_IPADDRESS) instanceof String) {
                ipAddress = dataRecord.getFieldValue(COLUMN_IPADDRESS);
                final InetAddressValidator validator = InetAddressValidator.getInstance();
                return validator.isValidInet4Address(ipAddress);
            }
            return false;
        }
    };

    public static Predicate<DataRecord> isIpv6Node = new Predicate<DataRecord>() {
        @Override
        public boolean apply(final DataRecord dataRecord) {
            String ipAddress = "";
            if (dataRecord.getFieldValue(COLUMN_IPADDRESS) instanceof String) {
                ipAddress = dataRecord.getFieldValue(COLUMN_IPADDRESS);
                final InetAddressValidator validator = InetAddressValidator.getInstance();
                return validator.isValidInet6Address(ipAddress);
            }
            return false;
        }
    };


    public static Predicate<DataRecord> isCppNode = new Predicate<DataRecord>() {
        @Override
        public boolean apply(final DataRecord dataRecord) {
            boolean find = false;
            final NodeTypeHelper nodeTypeHelper = new NodeTypeHelper();
            String nodeType = null;
            if (dataRecord.getFieldValue(COLUMN_NODE_TYPE) instanceof String) {
                nodeType = dataRecord.getFieldValue(COLUMN_NODE_TYPE);
                final NodeType nodeTypeEnum = NodeType.getType(nodeType);
                find = nodeTypeHelper.isCppNode(nodeTypeEnum);
                return find;
            }
            return find;
        }
    };

    public static Predicate<DataRecord> isComEcimNode = new Predicate<DataRecord>() {
        @Override
        public boolean apply(final DataRecord dataRecord) {
            boolean find = false;
            final NodeTypeHelper nodeTypeHelper = new NodeTypeHelper();
            String nodeType = null;
            if (dataRecord.getFieldValue(COLUMN_NODE_TYPE) instanceof String) {
                nodeType = dataRecord.getFieldValue(COLUMN_NODE_TYPE);
                final NodeType nodeTypeEnum = NodeType.getType(nodeType);
                find = nodeTypeHelper.isComEcimNode(nodeTypeEnum);
                return find;
            }
            return find;
        }
    };

    public static Predicate<DataRecord> isCRLNonApplicableNodes = new Predicate<DataRecord>() {
        @Override
        public boolean apply(final DataRecord dataRecord) {
            boolean find = true;
            String nodeType = null;
            if (dataRecord.getFieldValue(COLUMN_NODE_TYPE) instanceof String) {
                nodeType = dataRecord.getFieldValue(COLUMN_NODE_TYPE);
                if (!nodeType.equals("RNC")) {
                    return find;
                } else {
                    find = false;
                }
            }
            return find;
        }
    };

    public static Predicate<DataRecord> isCbpoiNodeIpv4 = new Predicate<DataRecord>() {
        @Override
        public boolean apply(final DataRecord dataRecord) {
            boolean find = false;
            final NodeTypeHelper nodeTypeHelper = new NodeTypeHelper();
            String nodeType = null;
            String ipAddress = null;
            if (dataRecord.getFieldValue(COLUMN_NODE_TYPE) instanceof String && dataRecord.getFieldValue(COLUMN_IPADDRESS) instanceof String) {
                nodeType = dataRecord.getFieldValue(COLUMN_NODE_TYPE);
                ipAddress = dataRecord.getFieldValue(COLUMN_IPADDRESS);
                final InetAddressValidator validator = InetAddressValidator.getInstance();
                final NodeType nodeTypeEnum = NodeType.getType(nodeType);
                find = nodeTypeHelper.isCbpoiNode(nodeTypeEnum) && validator.isValidInet4Address(ipAddress);
                return find;
            }
            return find;
        }
    };


    public static Predicate<DataRecord> isCbpoiNodeIpv6 = new Predicate<DataRecord>() {
        @Override
        public boolean apply(final DataRecord dataRecord) {
            boolean find = false;
            final NodeTypeHelper nodeTypeHelper = new NodeTypeHelper();
            String nodeType = null;
            String ipAddress = null;
            if (dataRecord.getFieldValue(COLUMN_NODE_TYPE) instanceof String && dataRecord.getFieldValue(COLUMN_IPADDRESS) instanceof String) {
                nodeType = dataRecord.getFieldValue(COLUMN_NODE_TYPE);
                ipAddress = dataRecord.getFieldValue(COLUMN_IPADDRESS);
                final InetAddressValidator validator = InetAddressValidator.getInstance();
                final NodeType nodeTypeEnum = NodeType.getType(nodeType);
                find = nodeTypeHelper.isCbpoiNode(nodeTypeEnum) && validator.isValidInet6Address(ipAddress);
                return find;
            }
            return find;
        }
    };


    public static void removeAndCreateTestDataSource(final String dataSourceName, final Iterable<DataRecord> nodesFiltered) {
        TafTestContext.getContext().removeDataSource(dataSourceName);
        final Iterator<DataRecord> localNameIterator = nodesFiltered.iterator();
        while (localNameIterator.hasNext()) {
            final DataRecord node = localNameIterator.next();
            TafTestContext.getContext().dataSource(dataSourceName).addRecord().setFields(node);
        }
    }

}
