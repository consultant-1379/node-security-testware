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
import static com.ericsson.cifwk.taf.scenario.TestScenarios.scenario;
import static com.ericsson.nms.security.nscs.predicate.PredicateUtil.userRoleSuiteNamePredicate;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.ADDED_NODES;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.AVAILABLE_USERS;

import javax.inject.Inject;

import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.ericsson.cifwk.taf.TestContext;
import com.ericsson.cifwk.taf.annotations.TestSuite;
import com.ericsson.cifwk.taf.datasource.DataRecord;
import com.ericsson.cifwk.taf.scenario.TestScenario;
import com.ericsson.cifwk.taf.scenario.TestScenarioRunner;
import com.ericsson.nms.security.pki.flows.ConfigMngFlows;
import com.ericsson.oss.testware.nodesecurity.flows.RtSelFlows;
import com.google.common.base.Predicate;

@SuppressWarnings({"PMD.LawOfDemeter"})
public class RtSelTestScenario extends ScenarioUtility {

    @Inject
    private TestContext context;

    @Inject
    private RtSelFlows rtSelFlows;

    @Inject
    private ConfigMngFlows configMngFlows;

    @BeforeClass(groups = { "Functional", "NSS", "RFA250", "ARNL" })
    public void beforeClass() {
        final Predicate<DataRecord> predicatePositive =  userRoleSuiteNamePredicate("roles",
                SetupAndTeardownScenarioRtSel.positiveCustomRolesList());
        final Predicate<DataRecord> predicateNegative = userRoleSuiteNamePredicate("roles",
                SetupAndTeardownScenarioRtSel.negativeCustomRolesList());
        super.beforeClass(predicatePositive, predicateNegative);
        LOGGER.info("\n   BEFORE CLASS RTSEL TEST - START \n");
        dumpDataSource();
        LOGGER.info("\n   BEFORE CLASS RTSEL TEST - END \n");
        final TestScenario beforeClassScenario = scenario("Before Class RTSEL Scenario")
                .addFlow(loginLogoutRestFlows.loginDefaultUser())
                .addFlow(configMngFlows.updateAlgorithmsFlow())
                .addFlow(loginLogoutRestFlows.logout()).alwaysRun()
                .build();
        final TestScenarioRunner runner = SetupAndTearDownUtil.getScenarioRunner();
        runner.start(beforeClassScenario);
    }

    @Test(enabled = true, priority = 1, groups = { "Functional", "NSS", "RFA250" })
    @TestSuite
    public void activeRtSelPositive() {
        doParallelNodesBase(INPUT_DATASOURCE, "MR33789_Q2_Activate_RTSEL_positivecases_eNodeB_ERBS",
                context.dataSource(SetupAndTeardownScenarioRtSel.RTSEL_ACTIVATE_CORRECT_USER), context.dataSource(ADDED_NODES), userListPositive);
        final TestScenario scenario = dataDrivenScenario("RtSel Activation Test Scenario - Correct user")
                .addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(utilityFlows.verifySyncNodes())
                .addFlow(rtSelFlows.activateRtSel(false))
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(AVAILABLE_USERS).bindTo(ADDED_NODES))
                .doParallel(vUser).build();
        startScenario(scenario);
    }

    @Test(enabled = true, priority = 2, groups = { "Functional", "NSS", "RFA250" })
    @TestSuite
    public void deactivateRtSelPositive() {
        doParallelNodesBase(INPUT_DATASOURCE, "MR33789_Q2_Deactivate_RTSEL_positivecases_eNodeB_ERBS",
                context.dataSource(SetupAndTeardownScenarioRtSel.RTSEL_DEACTIVATE_CORRECT_USER), context.dataSource(ADDED_NODES), userListPositive);
        final TestScenario scenario = dataDrivenScenario("RtSel Deactivation Test Scenario - Correct user")
                .addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(utilityFlows.verifySyncNodes())
                .addFlow(rtSelFlows.deActivateRtSel(false))
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(AVAILABLE_USERS).bindTo(ADDED_NODES))
                .doParallel(vUser).build();
        startScenario(scenario);
    }

    @Test(enabled = true, priority = 3, groups = { "Functional", "NSS", "RFA250" })
    @TestSuite
    public void deleteRtSelPositive() {
        doParallelNodesBase(INPUT_DATASOURCE, "MR33789_Q2_Delete_SyslogServer_of_RTSEL_positivecases_eNodeB_ERBS",
                context.dataSource(SetupAndTeardownScenarioRtSel.RTSEL_DELETE_CORRECT_USER), context.dataSource(ADDED_NODES), userListPositive);
        final TestScenario scenario = dataDrivenScenario("RtSel Deletion Test Scenario - Correct user")
                .addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(utilityFlows.verifySyncNodes())
                .addFlow(rtSelFlows.deleteRtSel(false))
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(AVAILABLE_USERS).bindTo(ADDED_NODES))
                .doParallel(vUser).build();
        startScenario(scenario);
    }

    //RBAC
    @Test(enabled = true, groups = { "Functional", "NSS" })
    @TestSuite
    public void activeRtSelNegative() {
        doParallelNodesBase(INPUT_DATASOURCE, "MR33789_Q2_Activate_RTSEL_negativecases_eNodeB_ERBS",
                context.dataSource(SetupAndTeardownScenarioRtSel.RTSEL_ACTIVATE_WRONG_USER), context.dataSource(ADDED_NODES), userListNegative);
        final TestScenario scenario = dataDrivenScenario("RtSel Activation Test Scenario - Wrong user")
                .addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(rtSelFlows.activateRtSel(true))
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(AVAILABLE_USERS).bindTo(ADDED_NODES))
                .doParallel(vUser).build();
        startScenario(scenario);
    }

    @Test(enabled = true, groups = { "Functional", "NSS" })
    @TestSuite
    public void deactivateRtSelNegative() {
        doParallelNodesBase(INPUT_DATASOURCE, "MR33789_Q2_Deactivate_RTSEL_negativecases_eNodeB_ERBS",
                context.dataSource(SetupAndTeardownScenarioRtSel.RTSEL_DEACTIVATE_WRONG_USER), context.dataSource(ADDED_NODES), userListNegative);
        final TestScenario scenario = dataDrivenScenario("RtSel Deactivation Test Scenario - Wrong user")
                .addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(rtSelFlows.deActivateRtSel(true))
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(AVAILABLE_USERS).bindTo(ADDED_NODES))
                .doParallel(vUser).build();
        startScenario(scenario);
    }

    @Test(enabled = true, groups = { "Functional", "NSS" })
    @TestSuite
    public void deleteRtSelNegative() {
        doParallelNodesBase(INPUT_DATASOURCE, "MR33789_Q2_Delete_SyslogServer_of_RTSEL_negativecases_eNodeB_ERBS",
                context.dataSource(SetupAndTeardownScenarioRtSel.RTSEL_DELETE_WRONG_USER), context.dataSource(ADDED_NODES), userListNegative);
        final TestScenario scenario = dataDrivenScenario("RtSel Deletion Test Scenario - Wrong user")
                .addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(rtSelFlows.deleteRtSel(true))
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(AVAILABLE_USERS).bindTo(ADDED_NODES))
                .doParallel(vUser).build();
        startScenario(scenario);
    }

}

