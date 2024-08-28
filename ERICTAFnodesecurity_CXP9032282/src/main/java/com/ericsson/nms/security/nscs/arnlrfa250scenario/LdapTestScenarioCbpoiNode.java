/*******************************************************************************
 * COPYRIGHT Ericsson 2016
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/

package com.ericsson.nms.security.nscs.arnlrfa250scenario;

import com.ericsson.cifwk.taf.TestContext;
import com.ericsson.cifwk.taf.annotations.TestSuite;
import com.ericsson.cifwk.taf.datasource.DataRecord;
import com.ericsson.cifwk.taf.datasource.TestDataSource;
import com.ericsson.cifwk.taf.scenario.TestScenario;
import com.ericsson.cifwk.taf.scenario.api.ScenarioExceptionHandler;
import com.ericsson.nms.security.nscs.predicate.PredicateUtil;
import com.ericsson.oss.testware.nodesecurity.flows.LdapFlows;
import com.ericsson.oss.testware.nodesecurity.flows.ProxyAccountFlows;
import com.ericsson.oss.testware.nodesecurity.steps.LdapTestSteps;
import com.google.common.base.Predicate;
import com.google.common.collect.Iterables;

import org.testng.ITestContext;
import org.testng.annotations.*;

import javax.inject.Inject;

import static com.ericsson.cifwk.taf.datasource.TafDataSources.fromCsv;
import static com.ericsson.cifwk.taf.datasource.TafDataSources.merge;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.*;
import static com.ericsson.nms.security.nscs.arnlrfa250scenario.SetupAndTeardownScenario.isRealNode;
import static com.ericsson.nms.security.nscs.arnlrfa250scenario.SetupAndTeardownScenarioCbpoiNode.LDAP_CONFIG_DATA_SOURCE;
import static com.ericsson.nms.security.nscs.arnlrfa250scenario.SetupAndTeardownScenarioCbpoiNode.PATH_LDAP;
import static com.ericsson.nms.security.nscs.arnlrfa250scenario.SetupAndTeardownScenarioLdap.LDAP_CLEANUP_PROXY_DATA_SOURCE;
import static com.ericsson.nms.security.nscs.predicate.PredicateUtil.userRoleSuiteNamePredicate;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.ADDED_NODES;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.AVAILABLE_USERS;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.NODES_TO_ADD;
import static com.ericsson.oss.testware.nodesecurity.steps.LdapTestSteps.StoreBindDnMode.*;

import java.lang.reflect.Method;

@SuppressWarnings({"PMD.LawOfDemeter"})
public class LdapTestScenarioCbpoiNode extends ScenarioUtility {

    public static final String LOGINFO_WRONG_NODETYPE_OR_SETUP = "%s is not applicable: wrong node type.";

    @Inject
    private TestContext context;

    @Inject
    private LdapFlows ldapFlows;

    @Inject
    private SetupAndTeardownScenarioCbpoiNode setupAndTeardownScenarioCbpoi;

    @Inject
    private ProxyAccountFlows proxyAccountFlows;

    private Boolean skipAllTests = false;

    @BeforeClass(groups = { "Functional", "NSS", "RFA250", "ARNL", "ENM_EXTERNAL_TESTWARE" })
    @Parameters({ "agat" })
    public void beforeClass(final ITestContext suiteContext, @Optional final String agat) {
        final Predicate<DataRecord> predicatePositiveLdap = userRoleSuiteNamePredicate("roles",
                SetupAndTeardownScenarioCbpoiNode.positiveLdapRoleList());
        final Predicate<DataRecord> predicatePositive = userRoleSuiteNamePredicate("roles",
                SetupAndTeardownScenarioLdap.positiveCustomRolesList());

        SetupAndTeardownScenario.setAgat(agat);
        if (SetupAndTeardownScenario.isAgat()) {
            setupAndTeardownScenarioCbpoi.onBeforeSuite(suiteContext, SetupAndTeardownScenario.getAgat());
        }
        skipAllTests = Iterables.isEmpty(context.dataSource(NODES_TO_ADD));
        LOGGER.info("\n isNodeDataSourceEmpty - Result = [{}] \n", skipAllTests);
        if(!skipAllTests){
            super.beforeClassCustomLdap(predicatePositive, predicatePositiveLdap);
        }
    }

    @AfterClass(groups = { "Functional", "NSS", "RFA250", "ARNL", "ENM_EXTERNAL_TESTWARE" })
    public void afterClass() {
        if (SetupAndTeardownScenario.isAgat()) {
            setupAndTeardownScenarioCbpoi.onAfterSuite();
        }
    }

    @BeforeMethod(groups = { "Functional", "NSS", "RFA250", "ARNL", "ENM_EXTERNAL_TESTWARE" })
    public void beforeMethod(final Method method) {
        if (skipAllTests) {
            LOGGER.debug(String.format(LOGINFO_WRONG_NODETYPE_OR_SETUP, method.getName()));
        }
    }

    @Test(enabled = true, priority = 1 ,groups = { "Functional", "NSS", "RFA250" })
    @TestSuite
    public void LdapRenew() {
        if (!skipAllTests) {
            doParallelNodesBase(INPUT_DATASOURCE, "TORF-613998_Ldap_Renew_Shared-CNF_node_type",
                    context.dataSource(LDAP_CONFIG_DATA_SOURCE),
                    context.dataSource(ADDED_NODES), userList);
            final TestScenario scenario = dataDrivenScenario("Ldap Renew ")
                    .addFlow(loginLogoutRestFlows.loginBuilder())
                    .addFlow(utilityFlows.verifySyncNodes())
                    .addFlow(ldapFlows.retrieveProxyAccountBindDnFromLdapMOSharedCnf(STORE_WITH_NODE_REF))
                    .addFlow(ldapFlows.ldapRenewFlowBasic())
                    .addFlow(ldapFlows.checkLdapRenewSharedCnf(LDAP_CONFIG_DATA_SOURCE))
                    .addFlow(loginLogoutRestFlows.logoutBuilder())
                    .alwaysRun()
                    .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(AVAILABLE_USERS).bindTo(ADDED_NODES)
                            .bindTo(LdapTestSteps.DataSource.LDAP_DATASOURCE))
                    .doParallel(vUser).build();
            startScenario(scenario);
        }
    }

    @Test(enabled = true, priority = 2 ,groups = { "Functional", "NSS", "RFA250", "ARNL", "ENM_EXTERNAL_TESTWARE" })
    @TestSuite
    public void LdapConfigPositiveTest() {
        if (!skipAllTests) {
            doParallelNodesBase(INPUT_DATASOURCE, "NSCS_LDAP_CONFIGURE_FILE_CorrectUserRole",
                    context.dataSource(LDAP_CONFIG_DATA_SOURCE),
                    //context.dataSource(ADDED_NODES), userListPositiveLdap, vUser);
                    context.dataSource(ADDED_NODES), userList);
            final TestScenario scenario = dataDrivenScenario("LDAP Config - Positive Scenario")
                    .addFlow(loginLogoutRestFlows.loginBuilder())
                    .addFlow(utilityFlows.verifySyncNodes())
                    .addFlow(ldapFlows.retrieveProxyAccountBindDnFromLdapMOSharedCnf(ADD_TO_LIST))// add to list in order to delete it in tearDown
                    .addFlow(ldapFlows.setLdapConfigFlowBasic())
                    .addFlow(ldapFlows.retrieveProxyAccountBindDnFromLdapMOSharedCnf(GET))
                    .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                    .withScenarioDataSources(dataSource(INPUT_DATASOURCE)
                            .bindTo(AVAILABLE_USERS)
                            .bindTo(ADDED_NODES)
                            .bindTo(LdapTestSteps.DataSource.LDAP_DATASOURCE))
                    .doParallel(vUser).build();
            startScenario(scenario);
        }
    }

    @AfterMethod(groups = { "Functional", "NSS", "RFA250"})
    public void afterMethod(final ITestContext suiteContext, final Method method) {
        if (method.getName().equals("LdapConfigPositiveTest") && (!skipAllTests) && (!suiteContext.getFailedTests().toString().contains("LdapConfigPositiveTest"))) {
            LOGGER.info("\n\nAFTER Method 'LdapConfigPositiveTest' - CleanUp Proxy Accounts - START");
            final TestDataSource<DataRecord> ldapRemoveProxyAccount = fromCsv(PATH_LDAP + "Ldap_RemoveProxyAccount.csv");
            context.addDataSource(LDAP_CLEANUP_PROXY_DATA_SOURCE, merge(ldapRemoveProxyAccount, ScenarioUtility.buildProxyAccountSpecificDataSource()));
            debugScope(LOGGER, LDAP_CLEANUP_PROXY_DATA_SOURCE);
            final TestScenario cleanUpProxyAccounts = scenario("CleanUp Proxy Accounts")
                    .addFlow(utilityFlows.login(PredicateUtil.nsuLdap(), vUser))
                    .addFlow(proxyAccountFlows.cleanUpProxyAccount(LDAP_CLEANUP_PROXY_DATA_SOURCE))
                    .addFlow(utilityFlows.logout(PredicateUtil.nsuLdap(), 1))
                    .alwaysRun().withExceptionHandler(ScenarioExceptionHandler.LOGONLY)
                    .build();
            startScenario(cleanUpProxyAccounts);
            LOGGER.info("\nAFTER Method 'LdapConfigPositiveTest' - CleanUp Proxy Accounts - - END\n");
        }
    }
}

