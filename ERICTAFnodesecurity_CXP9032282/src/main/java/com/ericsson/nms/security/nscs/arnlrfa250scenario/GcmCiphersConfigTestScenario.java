/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2019
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
import static com.ericsson.cifwk.taf.scenario.TestScenarios.flow;
import static com.ericsson.nms.security.nscs.predicate.PredicateUtil.userRoleSuiteNamePredicate;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.ADDED_NODES;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.AVAILABLE_USERS;
import static com.ericsson.nms.security.nscs.arnlrfa250scenario.SetupAndTeardownScenarioGcmCiphersConfig.SET_CIPHERS;

import java.util.concurrent.TimeUnit;

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
import com.ericsson.oss.testware.nodesecurity.flows.CiphersConfigurationFlows;
import com.ericsson.oss.testware.nodesecurity.flows.HttpsFlows;
import com.ericsson.oss.testware.nodesecurity.flows.Sl2Flows;
import com.google.common.base.Predicate;

@SuppressWarnings({"PMD.LawOfDemeter"})
public class GcmCiphersConfigTestScenario extends ScenarioUtility {

    private static final Logger LOGGER = LoggerFactory.getLogger(GcmCiphersConfigTestScenario.class);
    public static final String GCM_CIPHER = "ECDHE-RSA-AES256-GCM-SHA384";

    @Inject
    private TestContext context;
    @Inject
    private Sl2Flows sl2Flows;
    @Inject
    private HttpsFlows httpsFlows;
    @Inject
    CiphersConfigurationFlows ciphersConfigurationFlows;
    @Inject
    private ConfigMngFlows configMngFlows;

    @BeforeClass(groups = { "Functional", "NSS" })
    public void beforeClass() {
        final Predicate<DataRecord> predicatePositive =  userRoleSuiteNamePredicate("roles",
                SetupAndTeardownScenarioGcmCiphersConfig.positiveCustomRolesList());
        final Predicate<DataRecord> predicateNegative = userRoleSuiteNamePredicate("roles",
                SetupAndTeardownScenarioGcmCiphersConfig.negativeCustomRolesList());
        super.beforeClass(predicatePositive, predicateNegative);
        LOGGER.info("\n   BEFORE CLASS  GCM Ciphers configuration TEST - START \n");
        dumpDataSource();
        LOGGER.info("\n   BEFORE CLASS  GCM Ciphers configuration TEST - END \n");
        final TestScenario beforeClassScenario = scenario("Before class GCM Ciphers Scenario")
                .addFlow(loginLogoutRestFlows.loginDefaultUser())
                .addFlow(configMngFlows.updateAlgorithmsFlow())
                .addFlow(loginLogoutRestFlows.logout()).alwaysRun()
                .build();
        final TestScenarioRunner runner = SetupAndTearDownUtil.getScenarioRunner();
        runner.start(beforeClassScenario);
    }

    @Test(enabled = true, priority = 1, groups = { "Functional", "NSS" })
    @TestSuite
    public void setGcmCiphersTest() {
        doParallelNodesBase(INPUT_DATASOURCE, "NSCS_GCM_CIPHERSCONFIG_ENABLE_GCM_CIPHER",
                context.dataSource(SET_CIPHERS), context.dataSource(ADDED_NODES), userListPositive);
        ScenarioUtility.debugScope(LOGGER, INPUT_DATASOURCE);
        final TestScenario scenario = dataDrivenScenario("GCM ciphers configuration")
                .addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(utilityFlows.verifySyncNodes())
                .addFlow(sl2Flows.setStatusSlFlowBuilder())
                .addFlow(flow("Wait").pause(3, TimeUnit.MINUTES))
                .addFlow(utilityFlows.verifySyncNodes())
                .addFlow(httpsFlows.activateHttps(false))
                .addFlow(flow("Wait").pause(8, TimeUnit.MINUTES))
                .addFlow(utilityFlows.verifySyncNodes())
                .addFlow(ciphersConfigurationFlows.setSelectedCipherFlow("Set GCM Cipher Positive Test Scenario", GCM_CIPHER))
                .addFlow(ciphersConfigurationFlows.getSelectedCipherFlow("Get GCM Cipher Positive Test Scenario", GCM_CIPHER))
                .addFlow(utilityFlows.actionSyncNodeOnNodes(vUser))
                .addFlow(utilityFlows.verifySyncNodes())
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(AVAILABLE_USERS).bindTo(ADDED_NODES))
                .doParallel(vUser).build();
        final TestScenarioRunner runner = SetupAndTearDownUtil.getScenarioRunner();
        runner.start(scenario);
    }
}
