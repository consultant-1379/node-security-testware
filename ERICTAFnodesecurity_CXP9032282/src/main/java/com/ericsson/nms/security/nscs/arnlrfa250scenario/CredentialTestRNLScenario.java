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

import com.ericsson.cifwk.taf.annotations.TestSuite;
import com.ericsson.cifwk.taf.data.DataHandler;
import com.ericsson.cifwk.taf.datasource.DataRecord;
import com.ericsson.cifwk.taf.scenario.TestScenario;
import com.ericsson.cifwk.taf.scenario.api.ScenarioExceptionHandler;
import com.ericsson.nms.security.nscs.predicate.PredicateUtil;
import com.ericsson.oss.testware.nodesecurity.flows.CredentialsFlows;
import com.google.common.base.Predicate;
import org.testng.ITestContext;
import org.testng.annotations.AfterClass;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Optional;
import org.testng.annotations.Parameters;
import org.testng.annotations.Test;

import javax.inject.Inject;
import java.lang.reflect.Method;
import java.util.concurrent.TimeUnit;

import static com.ericsson.cifwk.taf.scenario.TestScenarios.dataDrivenScenario;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.dataSource;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.flow;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.scenario;
import static com.ericsson.nms.security.nscs.predicate.PredicateUtil.userRoleSuiteNamePredicate;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.ADDED_NODES;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.AVAILABLE_USERS;

@SuppressWarnings({"PMD.LawOfDemeter", "PMD.ExcessiveImports"})
public class CredentialTestRNLScenario extends LogScenarioUtility {

    private static final String TITLE_CRED_CREATE_NODELIST = "NSCS CREDENTIALS GET and CREATE with Correct UserRole on Real Node";
    private static final String TITLE_CRED_UPDATE_NODELIST = "NSCS CREDENTIALS UPDATE with Correct UserRole on Real Node";

    private static final String LOG_SCENARIO_TAG = "CREDENTIAL_CREATE_UPDATE";
    private String scenario = "";

    @Inject
    final static String NODETYPE_CM_SYNC = "credential.nodeType.skip.cm_sync";

    final String nodeTypeFilterValue = DataHandler.getConfiguration().getProperty(NODETYPE_CM_SYNC, "nodeType =='Router6672'", String.class);

    @Inject
    private CredentialsFlows credentialsFlows;

    @Inject
    private SetupAndTeardownScenarioCredential setupAndTeardownScenarioCredential;


    @BeforeClass(groups = { "ARNL", "ENM_EXTERNAL_TESTWARE" })
    @Parameters({ "agat" })
    public void beforeClass(final ITestContext suiteContext, @Optional final String agat) {
        SetupAndTeardownScenario.setAgat(agat);
        if (SetupAndTeardownScenario.isAgat()) {
            setupAndTeardownScenarioCredential.onBeforeSuite(suiteContext, SetupAndTeardownScenario.getAgat());
        }
        final Predicate<DataRecord> predicatePositive = userRoleSuiteNamePredicate("roles",
                SetupAndTeardownScenarioCredential.positiveCustomRolesList());
        final Predicate<DataRecord> predicateNegative = userRoleSuiteNamePredicate("roles",
                SetupAndTeardownScenarioCredential.negativeCustomRolesList());
        super.beforeClass(predicatePositive, predicateNegative);
        scenario = suiteContext.getName();
        enableLogManagement(LOG_ENABLE_SCRIPT_FILENAME, LOG_SCENARIO_TAG);
        final TestScenario beforeClassScenario = scenario("Before Class Credential Scenario - check node Sync")
                .addFlow(utilityFlows.login(PredicateUtil.nsuAdm(), vUser))
                .addFlow(utilityFlows.checkSyncNodeStatusOnce(vUser)).withExceptionHandler(ScenarioExceptionHandler.LOGONLY)
                .build();
        startScenario(beforeClassScenario);
    }

    @AfterClass(groups = { "ARNL", "ENM_EXTERNAL_TESTWARE" })
    public void afterClass() {
        final TestScenario afterClassScenario = scenario("After Class Credential Scenario - check node Sync")
                .addFlow(utilityFlows.login(PredicateUtil.nsuAdm(), vUser))
                .addFlow(utilityFlows.recursiveCheckSyncNodeStatus(vUser)).withExceptionHandler(ScenarioExceptionHandler.LOGONLY)
                .build();
        startScenario(afterClassScenario);
        disableLogManagement(LOG_DISABLE_SCRIPT_FILENAME, LOG_SCENARIO_TAG);
        if (SetupAndTeardownScenario.isAgat()) {
            setupAndTeardownScenarioCredential.onAfterSuite();
        }
    }

     @BeforeMethod(groups = {"ARNL", "ENM_EXTERNAL_TESTWARE"})  // Reduced list, to execute it only in RNL/Agat
    public void beforeMethodRouterDisableSync(final Method method) {
        if (method.getName().startsWith("credentialCreatePositive")) {
            final TestScenario beforeMethodScenario = scenario("Before Method CM Sync Disable Scenario")
                    .addFlow(utilityFlows.login(PredicateUtil.nscsAdm(), vUser))
                    .addFlow(nodeIntegrationFlows.disableCMSupervision().withDataSources(dataSource(ADDED_NODES).withFilter(nodeTypeFilterValue).allowEmpty()))
                    .withExceptionHandler(ScenarioExceptionHandler.LOGONLY)
                    .addFlow(utilityFlows.logout(PredicateUtil.nscsAdm(), vUser)).build();
            startScenario(beforeMethodScenario);
            LOGGER.info("CM Supervision has been disabled successfully");
        }
    }

    @AfterMethod(groups = {"ARNL", "ENM_EXTERNAL_TESTWARE"})  // Reduced list, to execute it only in RNL/Agat
    public void afterMethodRouterEnableSync(final Method method) {
        if (method.getName().startsWith("credentialUpdatePositive")) {
            final TestScenario afterMethodScenario = scenario("After Method CM Sync Enable Scenario")
                    .addFlow(utilityFlows.login(PredicateUtil.nscsAdm(), vUser))
                    .addFlow(nodeIntegrationFlows.enableCMSupervision().withDataSources(dataSource(ADDED_NODES).withFilter(nodeTypeFilterValue).allowEmpty()))
                    .addFlow(nodeIntegrationFlows.verifySynchNodeBuilder().withDataSources(dataSource(ADDED_NODES).withFilter(nodeTypeFilterValue).allowEmpty()))
                    .withExceptionHandler(ScenarioExceptionHandler.LOGONLY)
                    .addFlow(utilityFlows.logout(PredicateUtil.nscsAdm(), vUser)).build();
            startScenario(afterMethodScenario);
            LOGGER.info("CM Supervision has been Enabled successfully");
        }
    }

    @Test(enabled = true, priority = 1, groups = {"ARNL", "ENM_EXTERNAL_TESTWARE"})
    @TestSuite
    public void credentialCreatePositive_RNL() {
        doParallelNodesBase(INPUT_DATASOURCE, "NSCS_CREDENTIAL_GET_CREATE_CorrectUserRole_REAL_NODE", TITLE_CRED_CREATE_NODELIST, context.dataSource(ADDED_NODES),
                userListPositive);
        final TestScenario scenario = dataDrivenScenario("Credential Create Test Scenario_RNL")
                //Pre-Condition Start
                .addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(credentialsFlows.getCredentialsAndCreate(SetupAndTeardownScenarioCredential.CRED_GET))
                .addFlow(flow("Wait").pause(20, TimeUnit.SECONDS))
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(AVAILABLE_USERS).bindTo(ADDED_NODES)).doParallel(vUser).build();
        startScenario(scenario);
    }

    @Test(enabled = true, priority = 2, groups = {"ARNL", "ENM_EXTERNAL_TESTWARE"})
    @TestSuite
    public void credentialUpdatePositive_RNL() {
        doParallelNodesBase(INPUT_DATASOURCE, "NSCS_CREDENTIAL_UPDATE_CorrectUserRole_REAL_NODE", TITLE_CRED_UPDATE_NODELIST, context.dataSource(ADDED_NODES),
                userListPositive);
        final TestScenario scenario = dataDrivenScenario("Credential Update Test Scenario").addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(credentialsFlows.credentialsUpdateBasic()).alwaysRun()
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(AVAILABLE_USERS).bindTo(ADDED_NODES)).doParallel(vUser).build();
        startScenario(scenario);
    }
}
