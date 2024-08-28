/*
 * ------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2018
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------
 */

package com.ericsson.nms.security.nscs.arnlrfa250scenario;

import static com.ericsson.cifwk.taf.datasource.TafDataSources.fromCsv;
import static com.ericsson.nms.security.nscs.arnlrfa250scenario.SetupAndTeardownScenarioFtpes.NODES_TO_ADD_NOT_EXIST;
import static com.ericsson.nms.security.nscs.constants.UserRoleValues.ROLE_GET_SNMP_CREDENTIALS;
import static com.ericsson.nms.security.nscs.constants.UserRoleValues.ROLE_NODESECURITY_ADMIN;
import static com.ericsson.nms.security.nscs.constants.UserRoleValues.ROLE_NODESECURITY_OPERATOR;
import static com.ericsson.nms.security.nscs.constants.UserRoleValues.ROLE_SSH_KEY;
import static com.ericsson.nms.security.nscs.constants.UserRoleValues.ROLE_UPDATE_SNMP_NBI_CREDENTIALS;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.testng.ITestContext;
import org.testng.annotations.AfterSuite;
import org.testng.annotations.BeforeSuite;
import org.testng.annotations.Optional;
import org.testng.annotations.Parameters;

import com.ericsson.cifwk.taf.data.DataHandler;
import com.ericsson.cifwk.taf.datasource.DataRecord;
import com.ericsson.cifwk.taf.datasource.TestDataSource;
import com.ericsson.nms.security.nscs.predicate.PredicateUtil;
import com.google.common.base.Predicate;
import com.google.common.collect.Iterables;

/**
 * SetupAndTeardownScenarioRealNodeShm contains necessary operations that must be executed before and after SHM test suite.
 */
@SuppressWarnings({ "PMD.LawOfDemeter" })
public class SetupAndTeardownScenarioCredentialSnmpV3 extends SetupAndTeardownScenario {

    public static final String nodeTypes = DataHandler.getConfiguration().getProperty("credentialSnmpV3.nodeTypes",
            "MINI-LINK-Indoor,MINI-LINK-6352,MINI-LINK-6351,MINI-LINK-PT2020,SGSN-MME,RadioNode,Controller6610,SCU,ESC", String.class);

    public static final String CRED_SL_AUTHPRIV = "SLAuthPriv";
    public static final String CRED_SL_AUTHNOPRIV = "SLAuthNoPriv";
    public static final String CRED_SL_AUTHPRIV_NEGATIVE = "SLAuthPrivNegative";
    public static final String CRED_SL_AUTHNOPRIV_NEGATIVE = "SLAutoNoPrivNegative";
    public static final String CRED_SL_AUTHNOPRIV_NOT_EXIST = "SLAutoNoPrivNENotExisting";
    public static final String GET_CREDENTIAL_POSITIVE_WITHFILE_DATASOURCE = "GetCredentialPositiveWithFileDataSource";

    public static List<String> positiveCustomRolesList() {
        return Arrays.asList(ROLE_GET_SNMP_CREDENTIALS);
    }

    public static List<String> positiveNbiCustomRolesList() {
        return Arrays.asList(ROLE_UPDATE_SNMP_NBI_CREDENTIALS);
    }

    public static List<String> negativeNbiCustomRolesList() {
        return Arrays.asList(ROLE_NODESECURITY_OPERATOR, ROLE_SSH_KEY);
    }

    public static List<String> negativeCustomRolesList() {
        return Arrays.asList(ROLE_NODESECURITY_ADMIN, ROLE_NODESECURITY_OPERATOR, ROLE_SSH_KEY);
    }

    @Override
    public List<String> rbacCustomRolesList() {
        getLogger().debug("\n SetupAndTeardownScenarioCredential rbacCustomRoles \n");
        final List<String> newList = new ArrayList<String>();
        newList.addAll(positiveCustomRolesList());
        newList.addAll(negativeCustomRolesList());
        newList.addAll(positiveNbiCustomRolesList());
        return newList;
    }

    @Override
    public Predicate<DataRecord> correctNodeType() {
        getLogger().debug("\n SetupAndTeardownScenarioCredential correctNodeType \n");
        return PredicateUtil.genericPredicate("nodeType", Arrays.asList(nodeTypes.split(",")));
    }

    @Override
    protected boolean isSynchNodeRequested() {
        return false;
    }

    @Override
    protected boolean isFmSupervisionRequested() {
        return false;
    }

    /**
     * Overriding super class method, since more specific DataSources are needed.
     */
    @Override
    protected void setupSpecificDataSource() {
        final String path = "data" + File.separator + "feature" + File.separator + "credential" + File.separator;
        final TestDataSource<DataRecord> autoPriv = fromCsv(path + "SnmpSecurityLevelAutoPriv.csv");
        ScenarioUtility.debugScope(getLogger(), autoPriv);
        final TestDataSource<DataRecord> autoNoPriv = fromCsv(path + "SnmpSecurityLevelAutoNoPriv.csv");
        ScenarioUtility.debugScope(getLogger(), autoNoPriv);
        context.addDataSource(CRED_SL_AUTHPRIV, autoPriv);
        context.addDataSource(CRED_SL_AUTHNOPRIV, autoNoPriv);

        final TestDataSource<DataRecord> autoPrivNegative = fromCsv(path + "SnmpSecurityLevelAutoPrivNegative.csv");
        ScenarioUtility.debugScope(getLogger(), autoPrivNegative);
        final TestDataSource<DataRecord> autoNoPrivNegative = fromCsv(path + "SnmpSecurityLevelAutoNoPrivNegative.csv");
        ScenarioUtility.debugScope(getLogger(), autoNoPrivNegative);
        context.addDataSource(CRED_SL_AUTHPRIV_NEGATIVE, autoPrivNegative);
        context.addDataSource(CRED_SL_AUTHNOPRIV_NEGATIVE, autoNoPrivNegative);

        final TestDataSource<DataRecord> notExistNodename = fromCsv(path + "NotExistingNodeName.csv");
        ScenarioUtility.debugScope(getLogger(), notExistNodename);
        final TestDataSource<DataRecord> autoNoPrivNotExistingNe = fromCsv(path + "SnmpSecurityLevelAutoNoPrivNotExistingNE.csv");
        ScenarioUtility.debugScope(getLogger(), autoNoPrivNotExistingNe);
        context.addDataSource(NODES_TO_ADD_NOT_EXIST, notExistNodename);
        context.addDataSource(CRED_SL_AUTHNOPRIV_NOT_EXIST, autoNoPrivNotExistingNe);
    }

    @BeforeSuite(alwaysRun = true, groups = { "Functional", "NSS", "RFA250", "ARNL" })
    @Parameters({ "agat" })
    public void onBeforeSuite(final ITestContext suiteContext, @Optional final String agat) {
        onBeforeSuiteMethod(suiteContext, agat);
    }

    @AfterSuite(alwaysRun = true, groups = { "Functional", "NSS", "RFA250", "ARNL" })
    public void onAfterSuite() {
        onAfterSuiteMethod();
    }

    protected boolean isRbacRequested() {
        getLogger().info("Rbac is enabled for Long loop and RFA250");
        return true;
    }

    @Override
    public Iterable<DataRecord> filterUsers(final Iterable<DataRecord> userList) {
        return Iterables.filter(userList, userMngCustomRole());
    }

    private Predicate<DataRecord> userMngCustomRole() {
        return PredicateUtil.userRoleSuiteNamePredicate("roles", rbacCustomRolesList());
    }
}
