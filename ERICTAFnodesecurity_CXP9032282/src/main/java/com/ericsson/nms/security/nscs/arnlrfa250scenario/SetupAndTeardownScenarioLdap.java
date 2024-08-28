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

package com.ericsson.nms.security.nscs.arnlrfa250scenario;

import static com.ericsson.cifwk.taf.datasource.TafDataSources.fromCsv;
import static com.ericsson.cifwk.taf.datasource.TafDataSources.merge;
import static com.ericsson.nms.security.nscs.constants.UserRoleValues.*;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.ROLE_TO_CREATE;

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

/**
 * SetupAndTeardownScenarioRealNodeShm contains necessary operations that must be executed before and after SHM test suite.
 */
@SuppressWarnings({"PMD.LawOfDemeter"})
public class SetupAndTeardownScenarioLdap extends SetupAndTeardownScenario {

    public static final String nodeTypes = DataHandler.getConfiguration().getProperty("ldap.nodeTypes", "RadioNode,Router6x71,5GRadioNode,VTFRadioNode,vPP,vRC,vTIF,Router6672,Controller6610",
            String.class);

    public static final String ISSUE_OAM = "ISSUE_OAM";
    public static final String ISSUE_OAM_EXPMSG = "ISSUE_OAM_EXPMSG";
    public static final String LDAP_CONFIG_DATA_SOURCE = "Ldap_Config_DataSource";
    public static final String LDAP_RESTORE_ADMIN_STATE_DATA_SOURCE = "Ldap_Restore_Admin_State_DataSource";
    public static final String LDAP_RENEW_PROXY_NOT_CONFIGURED_DATA_SOURCE = "Ldap_Renew_Proxy_Not_Configured_DataSource";
    public static final String LDAP_RENEW_PROXY_ALREADY_CONFIGURED__DATA_SOURCE = "Ldap_Renew_Proxy_Already_Configured_DataSource";
    public static final String LDAP_RENEW_NEGATIVE_DATA_SOURCE = "Ldap_Renew_Negative_DataSource";
    public static final String LDAP_CLEANUP_PROXY_DATA_SOURCE = "Ldap_Remove_ProxyAccount_DataSource";
    public static final String SET_LDAP_PARAM = "Set Ldap Params";

    @Override
    protected boolean isFmSupervisionRequested() {
        return false;
    }

    @Override
    public Predicate<DataRecord> correctNodeType() {
        getLogger().debug("\n SetupAndTeardownScenarioLdap correctNodeType \n");
        return PredicateUtil.genericPredicate("nodeType", Arrays.asList(nodeTypes.split(",")));
    }

    public static List<String> positiveCustomRolesList() {
        return Arrays.asList(ROLE_NODESECURITY_ADMIN, ROLE_LDAP);
    }

    public static List<String> negativeCustomRolesList() {
        return Arrays.asList(ROLE_NODESECURITY_OPERATOR);
    }

    public static List<String> positiveLdapRoleList() {
        return Arrays.asList(ROLE_LDAP);
    }

    @Override
    public List<String> rbacCustomRolesList() {
        getLogger().debug("\n SetupAndTeardownScenarioCredential rbacCustomRoles \n");
        final List<String> newList = new ArrayList<String>();
        newList.addAll(positiveCustomRolesList());
        newList.addAll(negativeCustomRolesList());
        return newList;
    }

    private static final String basePath = "data" + File.separator + "feature" + File.separator;
    public static final String PATH_ISSUE = basePath + "issueReIssue" + File.separator;
    public static final String PATH_LDAP = basePath + "ldap" + File.separator;

    protected void setupSpecificDataSource() {

        final TestDataSource<DataRecord> oam = fromCsv(PATH_ISSUE + "ISSUE_OAM.csv");
        context.addDataSource(ISSUE_OAM, oam);
        final TestDataSource<DataRecord> expmsg = fromCsv(PATH_ISSUE + "ExpectedMessage.csv");
        context.addDataSource(ISSUE_OAM_EXPMSG, merge(oam, expmsg));

        final TestDataSource<DataRecord> ldapConfig = fromCsv(PATH_LDAP + "LdapConfig.csv");
        context.addDataSource(LDAP_CONFIG_DATA_SOURCE, ldapConfig);
        final TestDataSource<DataRecord> ldapRestoreAdminState = fromCsv(PATH_LDAP + "LdapRestoreAdminState.csv");
        context.addDataSource(LDAP_RESTORE_ADMIN_STATE_DATA_SOURCE, ldapRestoreAdminState);
        final TestDataSource<DataRecord> ldapRenewProxyNotConfigured = fromCsv(PATH_LDAP + "LdapRenewCheckLog_NoProxyConfigured.csv");
        context.addDataSource(LDAP_RENEW_PROXY_NOT_CONFIGURED_DATA_SOURCE,ldapRenewProxyNotConfigured);
        final TestDataSource<DataRecord> ldapRenewNegative = fromCsv(PATH_LDAP + "LdapRenewNegative.csv");
        context.addDataSource(LDAP_RENEW_NEGATIVE_DATA_SOURCE,ldapRenewNegative);
        final TestDataSource<DataRecord> ldapRenewProxyAlreadyConfigured = fromCsv(PATH_LDAP + "LdapRenewCheckLog_ProxyConfigured.csv");
        context.addDataSource(LDAP_RENEW_PROXY_ALREADY_CONFIGURED__DATA_SOURCE,ldapRenewProxyAlreadyConfigured);
        final TestDataSource<DataRecord> ldapRemoveProxyAccount = fromCsv(PATH_LDAP + "Ldap_RemoveProxyAccount.csv");
        context.addDataSource(LDAP_CLEANUP_PROXY_DATA_SOURCE, merge(ldapRemoveProxyAccount, ScenarioUtility.buildProxyAccountSpecificDataSource()));

        ScenarioUtility.dumpDataSource();
        ScenarioUtility.debugScope(getLogger(), ROLE_TO_CREATE);
        ScenarioUtility.debugScope(getLogger(), ISSUE_OAM);
        ScenarioUtility.debugScope(getLogger(), ISSUE_OAM_EXPMSG);
        ScenarioUtility.debugScope(getLogger(), LDAP_RENEW_PROXY_NOT_CONFIGURED_DATA_SOURCE);
        ScenarioUtility.debugScope(getLogger(), LDAP_RENEW_NEGATIVE_DATA_SOURCE);
        ScenarioUtility.debugScope(getLogger(), LDAP_RENEW_PROXY_ALREADY_CONFIGURED__DATA_SOURCE);
        ScenarioUtility.debugScope(getLogger(), LDAP_CONFIG_DATA_SOURCE);
        ScenarioUtility.debugScope(getLogger(), LDAP_RESTORE_ADMIN_STATE_DATA_SOURCE);
    }

    @BeforeSuite(alwaysRun = true, groups = { "Functional", "NSS" })
    @Parameters({ "agat" })
    public void onBeforeSuite(final ITestContext suiteContext, @Optional final String agat) {
        onBeforeSuiteMethod(suiteContext, agat);
    }

    @AfterSuite(alwaysRun = true, groups = { "Functional", "NSS" })
    public void onAfterSuite() {
        onAfterSuiteMethod();
    }
}
