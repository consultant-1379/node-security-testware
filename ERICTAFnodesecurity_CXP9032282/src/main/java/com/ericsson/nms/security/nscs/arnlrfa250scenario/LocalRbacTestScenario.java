/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2018
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
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.NODES_TO_ADD;

import javax.inject.Inject;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.ericsson.cifwk.taf.annotations.TestSuite;
import com.ericsson.cifwk.taf.datasource.DataRecord;
import com.ericsson.cifwk.taf.scenario.TestScenario;
import com.ericsson.nms.security.pki.flows.ConfigMngFlows;
import com.ericsson.oss.testware.nodesecurity.data.Commands;
import com.ericsson.oss.testware.nodesecurity.flows.LocalRbacFlows;
import com.google.common.base.Predicate;

@SuppressWarnings({"PMD.LawOfDemeter"})
public class LocalRbacTestScenario extends ScenarioUtilityAgat {
    private static final Logger LOGGER = LoggerFactory.getLogger(LocalRbacTestScenario.class);

    private static final String TITLE_LOCAL_RBAC_ENABLE = "Activate the Local AA on the node";
    private static final String TITLE_LOCAL_RBAC_DISABLE = "Deactivate the Local AA on the node";

    @Inject
    private LocalRbacFlows localRbacFlows;

    @Inject
    private ConfigMngFlows configMngFlows;

    @BeforeClass(groups = { "Functional", "NSS", "RFA250", "ARNL", "ENM_EXTERNAL_TESTWARE" })
    public void beforeClass() {
        LOGGER.info("\n   BEFORE CLASS LOCAL RBAC TEST - START \n");
        final Predicate<DataRecord> predicatePositive = userRoleSuiteNamePredicate("roles",
                SetupAndTeardownScenarioLocalRbac.positiveCustomRolesList());
        final Predicate<DataRecord> predicateNegative = userRoleSuiteNamePredicate("roles",
                SetupAndTeardownScenarioLocalRbac.negativeCustomRolesList());
        super.beforeClass(predicatePositive, predicateNegative);
        LOGGER.info("\n   BEFORE CLASS LOCAL RBAC TEST - END \n");
        final TestScenario beforeClassScenario = scenario("Before Class Local Rbac Scenario")
                .addFlow(loginLogoutRestFlows.loginDefaultUser())
                .addFlow(configMngFlows.updateAlgorithmsFlow())
                .addFlow(loginLogoutRestFlows.logout()).alwaysRun()
                .build();
        startScenario(beforeClassScenario);
    }

    @Test(enabled = true, priority = 1, groups = { "Functional", "NSS", "RFA250", "ARNL", "ENM_EXTERNAL_TESTWARE"})
    @TestSuite
    public void localRbacEnableTest() {
        doParallelNodesBase(INPUT_DATASOURCE, "NSCS_LOCAL_RBAC_ENABLE_CorrectUserRole", TITLE_LOCAL_RBAC_ENABLE,
                context.dataSource(SetupAndTeardownScenarioLocalRbac.EXPECTED_STATUS_ENABLE), context.dataSource(ADDED_NODES), userListPositive);
        ScenarioUtility.debugScope(LOGGER, INPUT_DATASOURCE);
        final TestScenario scenario = dataDrivenScenario("Local Rbac Enable Positive Test Scenario")
                .addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(utilityFlows.verifySyncNodes())
                .addFlow(localRbacFlows.laadDistributeFlowBuilder())
                .addFlow(
                        localRbacFlows.setLocalRbacStatusFlowBuilder(
                                context.dataSource(SetupAndTeardownScenarioLocalRbac.COMMAND_DATASOURCE_ENABLE, Commands.class),
                                context.dataSource(SetupAndTeardownScenarioLocalRbac.LOCAL_RBAC_USERS_DATASOURCE)))
                .addFlow(utilityFlows.verifySyncNodes())
                .addFlow(localRbacFlows.getLocalRbacStatusFlowBuilder())
                .addFlow(loginLogoutRestFlows.logoutBuilder())
                .alwaysRun().withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(AVAILABLE_USERS).bindTo(ADDED_NODES).bindTo(NODES_TO_ADD))
                .doParallel(vUser).build();
        startScenario(scenario);
    }

    @Test(enabled = true, priority = 2, groups = { "Functional", "NSS", "RFA250", "ARNL", "ENM_EXTERNAL_TESTWARE"})
    @TestSuite
    public void localRbacDisableTest() {
        doParallelNodesBase(INPUT_DATASOURCE, "NSCS_LOCAL_RBAC_DISABLE_CorrectUserRole", TITLE_LOCAL_RBAC_DISABLE,
                context.dataSource(SetupAndTeardownScenarioLocalRbac.EXPECTED_STATUS_DISABLE), context.dataSource(ADDED_NODES), userListPositive);
        ScenarioUtility.debugScope(LOGGER, INPUT_DATASOURCE);
        final TestScenario scenario = dataDrivenScenario("Local Rbac Disable Positive Test Scenario")
                .addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(utilityFlows.verifySyncNodes())
                .addFlow(
                        localRbacFlows.setLocalRbacStatusFlowBuilder(
                                context.dataSource(SetupAndTeardownScenarioLocalRbac.COMMAND_DATASOURCE_DISABLE, Commands.class),
                                context.dataSource(SetupAndTeardownScenarioLocalRbac.LOCAL_RBAC_USERS_DATASOURCE)))
                .addFlow(utilityFlows.verifySyncNodes())
                .addFlow(localRbacFlows.getLocalRbacStatusFlowBuilder())
                .addFlow(loginLogoutRestFlows.logoutBuilder())
                .alwaysRun().withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(AVAILABLE_USERS).bindTo(ADDED_NODES).bindTo(NODES_TO_ADD))
                .doParallel(vUser).build();
        startScenario(scenario);
    }

    @Test(enabled = true, priority = 3, groups = { "Functional", "NSS" })
    @TestSuite
    public void laadDistributeNegativeTest() {
        doParallelNodesBase(INPUT_DATASOURCE, "NSCS_LAAD_DISTRIBUTE_Wrong_UserRole",
                context.dataSource(SetupAndTeardownScenarioLocalRbac.LAAD_DISTRIBUTE_WRONG_USER),
                context.dataSource(ADDED_NODES), userListNegative);
        ScenarioUtility.debugScope(LOGGER, INPUT_DATASOURCE);
        final TestScenario scenario = dataDrivenScenario("Laad Distribute Test Scenario Wrong User")
                .addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(localRbacFlows.laadDistributeFlowBuilder())
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(AVAILABLE_USERS).bindTo(ADDED_NODES))
                .doParallel(vUser).build();
        startScenario(scenario);
    }
}
