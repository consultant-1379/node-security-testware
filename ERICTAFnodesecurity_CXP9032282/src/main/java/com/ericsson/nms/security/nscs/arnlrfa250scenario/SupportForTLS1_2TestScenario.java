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
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.NODES_TO_ADD;
import static com.ericsson.oss.testware.nodesecurity.constant.AgnosticConstants.READPIB;
import static com.ericsson.oss.testware.nodesecurity.constant.AgnosticConstants.UPDATEPIB;
import static com.ericsson.oss.testware.nodesecurity.pibcommands.PibCommandConfigurator.TLS_PIB;

import java.util.ArrayList;
import java.util.List;

import javax.inject.Inject;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.ericsson.cifwk.taf.TestContext;
import com.ericsson.cifwk.taf.annotations.TestSuite;
import com.ericsson.cifwk.taf.datasource.DataRecord;
import com.ericsson.cifwk.taf.scenario.TestScenario;
import com.ericsson.cifwk.taf.scenario.TestScenarioRunner;
import com.ericsson.nms.security.pki.flows.ConfigMngFlows;
import com.ericsson.oss.testware.nodesecurity.flows.PibParametersReadUpdateFlow;
import com.ericsson.oss.testware.nodesecurity.flows.Sl2Flows;
import com.google.common.base.Predicate;

@SuppressWarnings({"PMD.LawOfDemeter", "PMD.ClassNamingConventions", "PMD.ExcessiveImports"})
public class SupportForTLS1_2TestScenario extends ScenarioUtility {

    private static final Logger LOGGER = LoggerFactory.getLogger(SupportForTLS1_2TestScenario.class);

    @Inject
    private TestContext context;

    @Inject
    private Sl2Flows sl2Flows;
    @Inject
    private ConfigMngFlows configMngFlows;

    @Inject
    private PibParametersReadUpdateFlow pibParameterReadUpdateFlow;

    public static final String ENABLED_TLS_PROTOCOLS_CPP = "enabledTLSProtocolsCPP";

    public static final List<String> algorithmsvalueList = new ArrayList<String>();
    public static final List<String> cppPibParam = new ArrayList<String>();

    @BeforeClass(groups = { "Functional", "NSS", "RFA250" })
    public void beforeClass() {
        final Predicate<DataRecord> predicatePositive =  userRoleSuiteNamePredicate("roles",
                SetupAndTeardownScenarioTLSversion.positiveCustomRolesList());
        final Predicate<DataRecord> predicateNegative = userRoleSuiteNamePredicate("roles",
                SetupAndTeardownScenarioTLSversion.negativeCustomRolesList());
        super.beforeClass(predicatePositive, predicateNegative);
        LOGGER.info("\n   BEFORE CLASS SL2 in TLS1_2 TEST - START \n");
        dumpDataSource();
        LOGGER.info("\n   BEFORE CLASS SL2 in TLS1_2 TEST - END \n");
        final TestScenario beforeClassScenario = scenario("Before Class SL2 in TLS1_2 Scenario")
                .addFlow(loginLogoutRestFlows.loginDefaultUser())
                .addFlow(configMngFlows.updateAlgorithmsFlow())
                .addFlow(loginLogoutRestFlows.logout()).alwaysRun()
                .build();
        final TestScenarioRunner runner = SetupAndTearDownUtil.getScenarioRunner();
        runner.start(beforeClassScenario);
    }

    @Test(enabled = true, priority = 1, groups = { "Functional", "NSS", "RFA250" })
    @TestSuite
    public void sl2Activation_tls() {
        doParallelNodesBase(INPUT_DATASOURCE, "SL2activation for TLSv1.2",
                context.dataSource(SetupAndTeardownScenarioTLSversion.SL2_ON), context.dataSource(ADDED_NODES), userListPositive);
        ScenarioUtility.debugScope(LOGGER, INPUT_DATASOURCE);
        cppPibParam.add(ENABLED_TLS_PROTOCOLS_CPP);
        final TestScenario scenario = dataDrivenScenario("SL2 Activation Test for TLSv1.2 Scenario")
                .addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(utilityFlows.verifySyncNodes())
                .addFlow(pibParameterReadUpdateFlow.pibCommandFlow("readTlsPibCommandFlow", READPIB, TLS_PIB, cppPibParam))
                .addFlow(sl2Flows.setStatusSlFlowBuilder())
                .addFlow(utilityFlows.verifySyncNodes())
                .addFlow(pibParameterReadUpdateFlow.pibCommandFlow("updateTlsPibCommandFlow", UPDATEPIB, TLS_PIB, cppPibParam))
                .addFlow(utilityFlows.actionSyncNodeOnNodes(vUser))
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(AVAILABLE_USERS).bindTo(ADDED_NODES))
                .doParallel(vUser).build();
        final TestScenarioRunner runner = SetupAndTearDownUtil.getScenarioRunner();
        runner.start(scenario);
    }

    @Test(enabled = true, priority = 2, groups = { "Functional", "NSS", "RFA250" })
    @TestSuite
    public void sl2DeActivation_tls() {
        doParallelNodesBase(INPUT_DATASOURCE, "SL2deactivation for TLSv1.2",
                context.dataSource(SetupAndTeardownScenarioTLSversion.SL2_OFF), context.dataSource(ADDED_NODES), userListPositive);
        ScenarioUtility.debugScope(LOGGER, INPUT_DATASOURCE);
        final TestScenario scenario = dataDrivenScenario("SL2 Deactivation Test for TLSv1.2 Scenario")
                .addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(utilityFlows.recursiveVerifySyncNode())
                .addFlow(sl2Flows.setStatusSlFlowBuilder())
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(AVAILABLE_USERS).bindTo(ADDED_NODES).bindTo(NODES_TO_ADD))
                .doParallel(vUser).build();
        final TestScenarioRunner runner = SetupAndTearDownUtil.getScenarioRunner();
        runner.start(scenario);
    }
}
