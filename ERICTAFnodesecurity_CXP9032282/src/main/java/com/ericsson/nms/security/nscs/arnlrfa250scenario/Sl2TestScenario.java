/*------------------------------------------------------------------------------
 *******************************************************************************
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

import static com.ericsson.cifwk.taf.scenario.TestScenarios.dataDrivenScenario;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.dataSource;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.flow;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.scenario;
import static com.ericsson.nms.security.nscs.arnlrfa250scenario.SetupAndTeardownScenarioSl2.SL2_GET_MULTI_NODES;
import static com.ericsson.nms.security.nscs.predicate.PredicateUtil.userRoleSuiteNamePredicate;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.ADDED_NODES;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.AVAILABLE_USERS;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.NODES_TO_ADD;

import java.lang.reflect.Method;
import java.util.concurrent.TimeUnit;
import javax.inject.Inject;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testng.ITestContext;
import org.testng.annotations.AfterClass;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Optional;
import org.testng.annotations.Parameters;
import org.testng.annotations.Test;
import com.ericsson.cifwk.taf.TestContext;
import com.ericsson.cifwk.taf.annotations.TestSuite;
import com.ericsson.cifwk.taf.datasource.DataRecord;
import com.ericsson.cifwk.taf.scenario.TestScenario;
import com.ericsson.cifwk.taf.scenario.TestScenarioRunner;
import com.ericsson.nms.security.pki.flows.ConfigMngFlows;
import com.ericsson.oss.testware.nodesecurity.flows.Sl2Flows;
import com.google.common.base.Predicate;
import com.google.common.collect.Iterables;

@SuppressWarnings({ "PMD.LawOfDemeter", "PMD.ExcessiveImports" })
public class Sl2TestScenario extends LogScenarioUtility {

    private static final Logger LOGGER = LoggerFactory.getLogger(Sl2TestScenario.class);

    private static final String TITLE_SL_GET_MULTINODES = "Get Security Level status on multiple nodes";
    private static final String TITLE_SL_SL2_ON = "Security Level 2 Activation";
    private static final String TITLE_SL_SL2_OFF = "Security Level 2 Deactivation";
    public static final String LOGINFO_WRONG_NODETYPE_OR_SETUP = "%s is not applicable: wrong node type.";

    private static final String LOG_SCENARIO_TAG_01 = "SL2ON";
    private static final String LOG_SCENARIO_TAG_02 = "SL2OFF";

    private Boolean skipAllTests = false;

    @Inject
    private TestContext context;
    @Inject
    private Sl2Flows sl2Flows;
    @Inject
    private ConfigMngFlows configMngFlows;

    @Inject
    SetupAndTeardownScenarioSl2 setupAndTeardownScenarioSl2;

    @BeforeClass(alwaysRun = true, groups = { "Functional", "NSS", "RFA250", "ARNL", "ENM_EXTERNAL_TESTWARE" })
    @Parameters({ "agat" })
    public void beforeClass(final ITestContext suiteContext, @Optional final String agat) {
        SetupAndTeardownScenario.setAgat(agat);
        if (SetupAndTeardownScenario.isAgat()) {
            setupAndTeardownScenarioSl2.onBeforeSuite(suiteContext, SetupAndTeardownScenario.getAgat());
        }
        skipAllTests = Iterables.isEmpty(context.dataSource(NODES_TO_ADD));
        LOGGER.info("\n isNodeDataSourceEmpty - Result = [{}] \n", skipAllTests);
        if (skipAllTests) {
            return;
        }
        final Predicate<DataRecord> predicatePositive = userRoleSuiteNamePredicate("roles",
                setupAndTeardownScenarioSl2.positiveCustomRolesList());
        final Predicate<DataRecord> predicateNegative = userRoleSuiteNamePredicate("roles",
                setupAndTeardownScenarioSl2.negativeCustomRolesList());
        super.beforeClass(predicatePositive, predicateNegative);
        LOGGER.info("\n   BEFORE CLASS SL2 TEST - START \n");
        dumpDataSource();
        LOGGER.info("\n   BEFORE CLASS SL2 TEST - END \n");
        final TestScenario beforeClassScenario = scenario("Before Class SL2 Scenario")
                .addFlow(loginLogoutRestFlows.loginDefaultUser())
                .addFlow(configMngFlows.updateAlgorithmsFlow())
                .addFlow(loginLogoutRestFlows.logout()).alwaysRun()
                .build();
        final TestScenarioRunner runner = SetupAndTearDownUtil.getScenarioRunner();
        runner.start(beforeClassScenario);
    }

    @AfterClass(alwaysRun = true, groups = { "Functional", "NSS", "RFA250", "ARNL", "ENM_EXTERNAL_TESTWARE" })
    public void afterClass() {
        if (SetupAndTeardownScenario.isAgat()) {
            setupAndTeardownScenarioSl2.onAfterSuite();
        }
    }

    @Test(enabled = true, priority = 1, groups = { "Functional", "NSS", "RFA250", "ARNL", "ENM_EXTERNAL_TESTWARE" })
    @TestSuite
    public void sl2Activation() {
        if (skipAllTests) {
            return;
        }
        doParallelNodesBase(INPUT_DATASOURCE, "NSCS_SL2_ON_CorrectUserRole", TITLE_SL_SL2_ON,
                context.dataSource(SetupAndTeardownScenarioSl2.SL2_ON), context.dataSource(ADDED_NODES), userListPositive);
        ScenarioUtility.debugScope(LOGGER, INPUT_DATASOURCE);
        final TestScenario scenario = dataDrivenScenario("SL2 Activation Test Scenario")
                .addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(utilityFlows.recursiveCheckSyncNodeStatusCmFm())
                .addFlow(sl2Flows.setStatusSlFlowBuilder())
                .addFlow(flow("Wait").pause((SetupAndTeardownScenario.isRealNode()) ? 480 : 180, TimeUnit.SECONDS))
                .addFlow(utilityFlows.recursiveVerifySyncNode())
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(AVAILABLE_USERS).bindTo(ADDED_NODES).bindTo(NODES_TO_ADD))
                .doParallel(vUser).build();
        final TestScenarioRunner runner = SetupAndTearDownUtil.getScenarioRunner();
        runner.start(scenario);
    }

    @Test(enabled = true, priority = 2, groups = { "Functional", "NSS", "RFA250", "ARNL", "ENM_EXTERNAL_TESTWARE" })
    @TestSuite
    public void sl2DeActivation() {
        if (skipAllTests) {
            return;
        }
        doParallelNodesBase(INPUT_DATASOURCE, "NSCS_SL2_OFF_CorrectUserRole", TITLE_SL_SL2_OFF,
                context.dataSource(SetupAndTeardownScenarioSl2.SL2_OFF), context.dataSource(ADDED_NODES), userListPositive);
        ScenarioUtility.debugScope(LOGGER, INPUT_DATASOURCE);
        final TestScenario scenario = dataDrivenScenario("SL2 Deactivation Test Scenario")
                .addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(utilityFlows.recursiveCheckSyncNodeStatusCmFm())
                .addFlow(sl2Flows.setStatusSlFlowBuilder())
                .addFlow(flow("Wait").pause((SetupAndTeardownScenario.isRealNode()) ? 480 : 180, TimeUnit.SECONDS))
                .addFlow(utilityFlows.recursiveVerifySyncNode())
                .addFlow(utilityFlows.recursiveCheckSyncNodeStatusCmFm())
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(AVAILABLE_USERS).bindTo(ADDED_NODES).bindTo(NODES_TO_ADD))
                .doParallel(vUser).build();
        final TestScenarioRunner runner = SetupAndTearDownUtil.getScenarioRunner();
        runner.start(scenario);
    }

    @BeforeMethod(groups = { "Functional", "NSS", "RFA250", "ARNL", "ENM_EXTERNAL_TESTWARE" })
    public void beforeMethod(final Method method) {
        LOGGER.trace("Executing Before Method: {} ({})", method.getName(), method.getName().equalsIgnoreCase("sl2Activation"));
        if (skipAllTests) {
            LOGGER.debug(String.format(LOGINFO_WRONG_NODETYPE_OR_SETUP, method.getName()));
            return;
        } else if (method.getName().equalsIgnoreCase("sl2Activation")) {
            enableLogManagement(LOG_ENABLE_SCRIPT_FILENAME, LOG_SCENARIO_TAG_01);
        } else if(method.getName().equalsIgnoreCase("sl2DeActivation")) {
            enableLogManagement(LOG_ENABLE_SCRIPT_FILENAME, LOG_SCENARIO_TAG_02);
        }
        //NODES_TO_ADD_MULTINODES dataSource generator
        if (method.getName().startsWith("sl2GetMultiNodes")) {
            super.setupMultiNodes();
        }
    }

    @AfterMethod(groups = { "Functional", "NSS", "RFA250", "ARNL", "ENM_EXTERNAL_TESTWARE" })
    public void afterMethod(final Method method) {
        LOGGER.trace("Executing After Method: {} ({})", method.getName(), method.getName().equalsIgnoreCase("sl2Activation"));
        if (method.getName().equalsIgnoreCase("sl2Activation")) {
            disableLogManagement(LOG_DISABLE_SCRIPT_FILENAME, LOG_SCENARIO_TAG_01);
        } else if (method.getName().equalsIgnoreCase("sl2DeActivation")) {
            disableLogManagement(LOG_DISABLE_SCRIPT_FILENAME, LOG_SCENARIO_TAG_02);
        }
    }

    @Test(enabled = true, priority = 3, groups = { "Functional", "NSS", "RFA250", "ARNL", "ENM_EXTERNAL_TESTWARE" })
    @TestSuite
    public void sl2GetMultiNodes() {
        if (skipAllTests) {
            return;
        }
        doParallelNodesBase(INPUT_DATASOURCE, "NSCS_SL2_GET_MultiNodes_CorrectUserRole", TITLE_SL_GET_MULTINODES,
                context.dataSource(SL2_GET_MULTI_NODES), context.dataSource(NODES_TO_ADD_MULTINODES), userListPositive);
        ScenarioUtility.debugScope(LOGGER, INPUT_DATASOURCE);
        //SL2_GET_MULTI_NODES
        final TestScenario scenario = dataDrivenScenario("SL2 Get MultiNodes Test Scenario")
                .addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(sl2Flows.getFileStatusSlBasicFlowBuilder())
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(AVAILABLE_USERS).bindTo(ADDED_NODES).bindTo(NODES_TO_ADD))
                .doParallel(1).build();
        final TestScenarioRunner runner = SetupAndTearDownUtil.getScenarioRunner();
        runner.start(scenario);
    }

    @Test(enabled = true, priority = 3, groups = { "Functional", "NSS" })
    @TestSuite
    public void sl2ActivationWrongUser() {
        if (skipAllTests) {
            return;
        }
        doParallelNodesBase(INPUT_DATASOURCE, "NSCS_SL2_ON_WrongUserRole",
                context.dataSource(SetupAndTeardownScenarioSl2.SL2_ON_WRONG_USER), context.dataSource(ADDED_NODES),
                userListNegative);
        ScenarioUtility.debugScope(LOGGER, INPUT_DATASOURCE);
        final TestScenario scenario = dataDrivenScenario("Set SL2 Activation Test Scenario Wrong User")
                .addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(sl2Flows.setStatusSlBasicFlowBuilder())
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(AVAILABLE_USERS).bindTo(ADDED_NODES))
                .doParallel(vUser).build();
        final TestScenarioRunner runner = SetupAndTearDownUtil.getScenarioRunner();
        // Execute 'scenario'
        runner.start(scenario);
    }

    @Test(enabled = true, priority = 3, groups = { "Functional", "NSS" })
    @TestSuite
    public void sl2DeActivationWrongUser() {
        if (skipAllTests) {
            return;
        }
        doParallelNodesBase(INPUT_DATASOURCE, "NSCS_SL2_OFF_WrongUserRole",
                context.dataSource(SetupAndTeardownScenarioSl2.SL2_OFF_WRONG_USER), context.dataSource(ADDED_NODES),
                userListNegative);
        ScenarioUtility.debugScope(LOGGER, INPUT_DATASOURCE);
        final TestScenario scenario = dataDrivenScenario("Set SL2 Deactivation Test Scenario Wrong User")
                .addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(sl2Flows.setStatusSlBasicFlowBuilder())
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(AVAILABLE_USERS).bindTo(ADDED_NODES))
                .doParallel(vUser).build();
        final TestScenarioRunner runner = SetupAndTearDownUtil.getScenarioRunner();
        // Execute 'scenario'
        runner.start(scenario);
    }
}
