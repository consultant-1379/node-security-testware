/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2017
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/

package com.ericsson.nms.security.nscs.arnlrfa250scenario;

import static com.ericsson.cifwk.taf.scenario.TestScenarios.*;
import static com.ericsson.nms.security.nscs.arnlrfa250scenario.SetupAndTeardownScenarioHttps.*;
import static com.ericsson.nms.security.nscs.constants.UserRoleValues.ROLE_NODESECURITY_OPERATOR;
import static com.ericsson.nms.security.nscs.predicate.PredicateUtil.userRoleSuiteNamePredicate;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.ADDED_NODES;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.AVAILABLE_USERS;
import static com.ericsson.oss.testware.nodesecurity.steps.HttpsTestSteps.HttpsOperation.ACTIVATE;
import static com.ericsson.oss.testware.nodesecurity.steps.HttpsTestSteps.HttpsOperation.DEACTIVATE;
import static com.ericsson.oss.testware.nodesecurity.steps.HttpsTestSteps.MISMATCH;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import javax.inject.Inject;

import com.ericsson.cifwk.taf.datasource.TestDataSourceFactory;
import com.ericsson.cifwk.taf.scenario.api.ScenarioExceptionHandler;
import com.ericsson.nms.security.nscs.predicate.PredicateUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.ericsson.cifwk.taf.annotations.TestSuite;
import com.ericsson.cifwk.taf.datasource.DataRecord;
import com.ericsson.cifwk.taf.datasource.TestDataSource;
import com.ericsson.cifwk.taf.scenario.TestScenario;
import com.ericsson.oss.testware.nodesecurity.flows.HttpsFlows;
import com.google.common.base.Predicate;
import com.google.common.collect.Iterables;

@SuppressWarnings({"PMD.LawOfDemeter", "PMD.ExcessiveImports"})
public class HttpsTestScenario extends ScenarioUtility {

    private static final String HTTPS_FUNCT_VERIFICATION_IS_PRE_COND_NEEDED = "httpsVerificationPreconditionNeeded";
    private static final Logger LOGGER = LoggerFactory.getLogger(CredentialTestScenario.class);
    private static final String SINGLE_NODE_DATA_SOURCE = "singleNodeDataSource";
    private static final String HTTPS_VERIFICATION_PRE_COND_DATA_SOURCES = "httpsVerificationPrecondDataSource";
    private static final String COMPARE = "Compare";
    private static boolean isHttpsActionRequest;
    private static boolean HttpsDeactivatePreCond = false;
    private static boolean HttpsActivatePreCond = true;

    @Inject
    private HttpsFlows httpsFlows;

    Predicate<DataRecord> getPredicatePositive;
    Predicate<DataRecord> getPredicateNegative;
    Iterable<DataRecord> getUserListPositive;
    Iterable<DataRecord> getUserListNegative;

    @BeforeClass(groups = { "Functional", "NSS", "RFA250", "ARNL", "KGB" })
    public void beforeClass() {
        final Predicate<DataRecord> predicatePositive = userRoleSuiteNamePredicate("roles",
                SetupAndTeardownScenarioHttps.positiveCustomRolesList());
        final Predicate<DataRecord> predicateNegative = userRoleSuiteNamePredicate("roles",
                SetupAndTeardownScenarioHttps.negativeCustomRolesList());
        //DEBUG
        LOGGER.debug(Iterables.toString(context.dataSource(AVAILABLE_USERS)));
        final Iterable<DataRecord> availableUserFilteredList = availableUserFiltered(predicatePositive);
        LOGGER.debug(Iterables.toString(availableUserFilteredList));
        //
        super.beforeClass(predicatePositive, predicateNegative);
        //GET TEST CASES
        final List<String> getPositiveUserRoles = new ArrayList<String>(SetupAndTeardownScenarioHttps.positiveCustomRolesList());
        getPositiveUserRoles.add(ROLE_NODESECURITY_OPERATOR);
        final List<String> getNegativeUserRoles = new ArrayList<String>(SetupAndTeardownScenarioHttps.negativeCustomRolesList());
        getNegativeUserRoles.remove(ROLE_NODESECURITY_OPERATOR);
        getPredicatePositive = userRoleSuiteNamePredicate("roles", getPositiveUserRoles);
        getPredicateNegative = userRoleSuiteNamePredicate("roles", getNegativeUserRoles);
        getUserListPositive = availableUserFiltered(getPredicatePositive);
        getUserListNegative = availableUserFiltered(getPredicateNegative);
        singlenode(SINGLE_NODE_DATA_SOURCE, context.dataSource(ADDED_NODES));
        super.setupMultiNodes();
    }

    @BeforeMethod(groups = { "Functional", "NSS", "RFA250", "ARNL", "KGB" })
    public void beforeMethodHttpCommandsUnsupportedNodes(final Method method) {
        if (method.getName().startsWith("httpCommandsUnsupportedNodes")) {
            super.setupKgbOnly();
        }
    }

    @BeforeMethod(groups = { "Functional", "NSS", "RFA250", "ARNL", "KGB" })
    public void beforeMethodHttpsApplicationVerification(final Method method) {
        final String methodName = method.getName();
        if (methodName.startsWith("httpsApplicationVerification")) {
            LOGGER.info("\n\nSTART BEFORE Method [{}] - Checking HTTPS status on the target node", methodName);
            final TestScenario checkHttpsStatus = scenario("check HTTPS status")
                    .addFlow(utilityFlows.login(PredicateUtil.nsuAdm(), 1))
                    .addFlow(httpsFlows.checkHttpsActivation(SINGLE_NODE_DATA_SOURCE))
                    .addFlow(utilityFlows.logout(PredicateUtil.nsuAdm(), 1))
                    .alwaysRun()
                    .build();
            startScenario(checkHttpsStatus);
            evaluatePrecondition();
                // perform HTTPS activation on the node as precondition to execute "httpsApplicationVerification" use cases
                if (isHttpsActionRequest) {
                final TestScenario executePrecondition = scenario("Execute Https Applications Verification Test PreConditions")
                        .addFlow(utilityFlows.login(PredicateUtil.nsuAdm(), 1))
                        .addFlow(HttpsDeactivatePreCond ? (httpsFlows.httpsDeactivatePrecondition()) : flow (""))
                        .addFlow(HttpsActivatePreCond ? (httpsFlows.httpsActivatePrecondition()) : flow (""))
                        .addFlow(utilityFlows.logout(PredicateUtil.nsuAdm(), 1))
                        .alwaysRun()
                        .build();
                startScenario(executePrecondition);
            }
            LOGGER.info("\nEND BEFORE Method - Checking HTTPS status on the target node\n");
        }
    }

    @AfterMethod(groups = { "Functional", "NSS", "RFA250", "ARNL", "KGB" })
    public void afterMethod(final Method method) {
        if (method.getName().startsWith("httpCommandsUnsupportedNodes")) {
            super.teardownKgbOnly();
        }
    }

    /*---------------------------------------*/
    /*---- POSITIVE USER ROLE TEST START ----*/
    /*---------------------------------------*/

    /*---------------------------------------*/
    /*------- MULTINODE TEST START --------*/
    /*---------------------------------------*/
    @Test(enabled = true, priority = 1, groups = { "Functional", "NSS", "KGB" })
    @TestSuite
    public void httpCommandsMultiNodes() {
        final Iterable<DataRecord> userMultiNode = availableUserFiltered(PredicateUtil.nscsAdm());
        final int skipped = (Iterables.size(userMultiNode) >= 1) ? Iterables.size(userMultiNode) - 1 : 1;
        doParallelNodesBase(INPUT_DATASOURCE, "NSCS_HTTPS_COMMANDS_MULTINODES",
                context.dataSource(HTTPS_POSITIVE_NODESBASE_TESTS), context.dataSource(NODES_TO_ADD_MULTINODES),
                Iterables.skip(userMultiNode, skipped));
        final TestScenario scenario = dataDrivenScenario("HTTPS command multi nodes positive scenario")
                .addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(utilityFlows.recursiveCheckFmStatus(1))
                .addFlow(utilityFlows.recursiveCheckSyncNodeStatusWithAssertion(1))
                .addFlow(httpsFlows.activateHttps(false))
                .addFlow(flow("Wait").pause(1, TimeUnit.MINUTES))
                .addFlow(utilityFlows.recursiveCheckSyncNodeStatusWithAssertion(1))
                .addFlow(httpsFlows.getHttpsStatus(ACTIVATE))
                .addFlow(httpsFlows.deActivateHttps(false))
                .addFlow(flow("Wait").pause(1, TimeUnit.MINUTES))
                .addFlow(utilityFlows.recursiveCheckSyncNodeStatusWithAssertion(1))
                .addFlow(httpsFlows.getHttpsStatus(DEACTIVATE))
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(AVAILABLE_USERS).bindTo(ADDED_NODES))
                .doParallel(vUser).build();
        startScenario(scenario);
    }

    @BeforeMethod(groups = { "Functional", "NSS", "KGB" })
    public void beforeMethodHttpsTests(final Method method) {
        final String methodName = method.getName();
        final boolean startBeforeMethodScenario = methodName.startsWith("httpCommandsMultiNodes") 
                || methodName.startsWith("httpsActivatePositive")
                || methodName.startsWith("httpsDeactivatePositive");
        if (startBeforeMethodScenario) {
            LOGGER.info("\n\nSTART BEFORE Method [{}] - Checking HTTPS status on the target node", methodName);
            final TestScenario scenario = scenario("Verify HTTPS status on node ")
                    .addFlow(utilityFlows.login(PredicateUtil.nsuAdm(), vUser))
                    .addFlow(httpsFlows.checkHttpsStatus(methodName.startsWith("httpCommandsMultiNodes") ? ADDED_NODES : SINGLE_NODE_DATA_SOURCE))
                    .addFlow(utilityFlows.logout(PredicateUtil.nsuAdm(), vUser))
                    .withExceptionHandler(ScenarioExceptionHandler.LOGONLY)
                    .alwaysRun()
                    .build();
            startScenario(scenario);
        }
    }

    /*---------------------------------------*/
    /*-------- MULTINODE TEST END   ---------*/
    /*---------------------------------------*/

    @Test(enabled = true, priority = 2, groups = { "Functional", "NSS", "RFA250", "ARNL", "KGB" })
    @TestSuite
    public void httpsActivatePositive() {
        debugScope(LOGGER, SINGLE_NODE_DATA_SOURCE);
        doParallelNodesBase(INPUT_DATASOURCE, "NSCS_HTTPS_ACTIVATE_CorrectUserRole",
                context.dataSource(HTTPS_POSITIVE_FILESBASE_TESTS), context.dataSource(SINGLE_NODE_DATA_SOURCE), userListPositive);
        final TestScenario scenario = dataDrivenScenario("HTTPS Activation Positive Scenario")
                .addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(utilityFlows.recursiveCheckSyncNodeStatusCmFm())
                .addFlow(httpsFlows.activateHttps(false))
                .addFlow(flow("Wait").pause(1, TimeUnit.MINUTES))
                .addFlow(utilityFlows.verifySyncNodes())
                .addFlow(httpsFlows.getHttpsStatus(ACTIVATE))
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(AVAILABLE_USERS).bindTo(ADDED_NODES))
                .doParallel(vUser).build();
        startScenario(scenario);
    }

    @Test(enabled = true, priority = 3, groups = { "Functional", "NSS", "RFA250", "ARNL", "KGB" })
    @TestSuite
    public void httpsGetPositive() {
        doParallelNodesBase(INPUT_DATASOURCE, "NSCS_HTTPS_GET_CorrectUserRole",
                context.dataSource(HTTPS_POSITIVE_FILESBASE_TESTS), context.dataSource(SINGLE_NODE_DATA_SOURCE), userListPositive);
        final TestScenario scenario = dataDrivenScenario("HTTPS Get Positive Scenario")
                .addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(utilityFlows.verifySyncNodes())
                .addFlow(httpsFlows.getHttpsStatus(ACTIVATE))
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(AVAILABLE_USERS).bindTo(ADDED_NODES))
                .doParallel(vUser).build();
        startScenario(scenario);
    }

    @Test(enabled = true, priority = 4, groups = { "Functional", "NSS", "RFA250", "ARNL", "KGB" })
    @TestSuite
    public void httpsApplicationVerificationWithPM() {
        debugScope(LOGGER, SINGLE_NODE_DATA_SOURCE);
        doParallelNodesBase(INPUT_DATASOURCE, "TORF-667648_HTTPS_Application_Verification_PM_test",
                context.dataSource(HTTPS_POSITIVE_FILESBASE_TESTS), context.dataSource(SINGLE_NODE_DATA_SOURCE), userListPositive);
        final TestScenario scenario = dataDrivenScenario("HTTPS Application Verification with PM")
                .addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(utilityFlows.verifySyncNodes())
                .addFlow(httpsFlows.getHttpsStatus(ACTIVATE))
                .addFlow(httpsFlows.httpsApplicationVerificationPM())
                .addFlow(utilityFlows.verifySyncNodes())
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(AVAILABLE_USERS).bindTo(ADDED_NODES))
                .doParallel(vUser).build();
        startScenario(scenario);
    }

    @Test(enabled = true, priority = 5, groups = { "Functional", "NSS", "RFA250", "ARNL", "KGB" })
    @TestSuite
    public void httpsApplicationVerificationWithFM() {
        debugScope(LOGGER, SINGLE_NODE_DATA_SOURCE);
        doParallelNodesBase(INPUT_DATASOURCE, "TORF-667648_HTTPS_Application_Verification_FM_test",
                context.dataSource(HTTPS_POSITIVE_FILESBASE_TESTS), context.dataSource(SINGLE_NODE_DATA_SOURCE), userListPositive);
        final TestScenario scenario = dataDrivenScenario("HTTPS Application Verification with FM")
                .addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(utilityFlows.verifySyncNodes())
                .addFlow(httpsFlows.getHttpsStatus(ACTIVATE))
                .addFlow(httpsFlows.httpsApplicationVerificationFM())
                .addFlow(utilityFlows.verifySyncNodes())
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(AVAILABLE_USERS).bindTo(ADDED_NODES))
                .doParallel(vUser).build();
        startScenario(scenario);
    }

    @Test(enabled = true, priority = 6, groups = { "Functional", "NSS", "RFA250", "ARNL", "KGB" })
    @TestSuite
    public void httpsApplicationVerificationWithSHM() {
        debugScope(LOGGER, SINGLE_NODE_DATA_SOURCE);
        doParallelNodesBase(INPUT_DATASOURCE, "TORF-667648_HTTPS_Application_Verification_SHM_test",
                context.dataSource(HTTPS_POSITIVE_FILESBASE_TESTS), context.dataSource(SINGLE_NODE_DATA_SOURCE), userListPositive);
        final TestScenario scenario = dataDrivenScenario("HTTPS Application Verification with SHM")
                .addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(utilityFlows.verifySyncNodes())
                .addFlow(httpsFlows.getHttpsStatus(ACTIVATE))
                .addFlow(httpsFlows.httpsApplicationVerificationSHM())
                .addFlow(utilityFlows.verifySyncNodes())
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(AVAILABLE_USERS).bindTo(ADDED_NODES))
                .doParallel(vUser).build();
        startScenario(scenario);
    }

    @Test(enabled = true, priority = 7, groups = { "Functional", "NSS", "RFA250", "ARNL", "KGB" })
    @TestSuite
    public void httpsApplicationVerificationWithCM() {
        debugScope(LOGGER, SINGLE_NODE_DATA_SOURCE);
        doParallelNodesBase(INPUT_DATASOURCE, "TORF-667648_HTTPS_Application_Verification_CM_test",
                context.dataSource(HTTPS_POSITIVE_FILESBASE_TESTS), context.dataSource(SINGLE_NODE_DATA_SOURCE), userListPositive);
        final TestScenario scenario = dataDrivenScenario("HTTPS Application Verification with CM")
                .addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(utilityFlows.verifySyncNodes())
                .addFlow(httpsFlows.getHttpsStatus(ACTIVATE))
                .addFlow(httpsFlows.httpsApplicationVerificationCM())
                .addFlow(utilityFlows.verifySyncNodes())
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(AVAILABLE_USERS).bindTo(ADDED_NODES))
                .doParallel(vUser).build();
        startScenario(scenario);
    }

    @Test(enabled = true, priority = 8, groups = { "Functional", "NSS", "RFA250", "ARNL", "KGB" })
    @TestSuite
    public void httpsDeactivatePositive() {
        debugScope(LOGGER, SINGLE_NODE_DATA_SOURCE);
        doParallelNodesBase(INPUT_DATASOURCE, "NSCS_HTTPS_DEACTIVATE_CorrectUserRole",
                context.dataSource(HTTPS_POSITIVE_FILESBASE_TESTS), context.dataSource(SINGLE_NODE_DATA_SOURCE), userListPositive);
        final TestScenario scenario = dataDrivenScenario("HTTPS Deactivation Positive Scenario")
                .addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(utilityFlows.verifySyncNodes())
                .addFlow(httpsFlows.deActivateHttps(false))
                .addFlow(flow("Wait").pause(1, TimeUnit.MINUTES))
                .addFlow(utilityFlows.verifySyncNodes())
                .addFlow(httpsFlows.getHttpsStatus(DEACTIVATE))
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(AVAILABLE_USERS).bindTo(ADDED_NODES))
                .doParallel(vUser).build();
        startScenario(scenario);
    }

    /*---------------------------------------*/
    /*---- POSITIVE USER ROLE TEST END  -----*/
    /*---------------------------------------*/

    /*---------------------------------------*/
    /*--- NEGATIVE USER ROLE TEST START  ----*/
    /*---------------------------------------*/

    @Test(enabled = true, priority = 9, groups = { "Functional", "NSS", "KGB" })
    @TestSuite
    public void httpsActivateNegative() {
        doParallelNodesBase(INPUT_DATASOURCE, "NSCS_HTTPS_ACTIVATE_WrongUserRole",
                context.dataSource(HTTPS_NEGATIVE_WRONGROLE_TESTS), context.dataSource(SINGLE_NODE_DATA_SOURCE), userListNegative);
        final TestScenario scenario = dataDrivenScenario("HTTPS Activate Negative Scenario for a single node")
                .addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(httpsFlows.activateHttps(true))
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(AVAILABLE_USERS).bindTo(ADDED_NODES))
                .doParallel(vUser).build();
        startScenario(scenario);
    }

    @Test(enabled = true, priority = 10, groups = { "Functional", "NSS", "KGB" })
    @TestSuite
    public void httpsDeactivateNegative() {
        doParallelNodesBase(INPUT_DATASOURCE, "NSCS_HTTPS_DEACTIVATE_WrongUserRole",
                context.dataSource(HTTPS_NEGATIVE_WRONGROLE_TESTS), context.dataSource(SINGLE_NODE_DATA_SOURCE), userListNegative);
        final TestScenario scenario = dataDrivenScenario("HTTPS Deactivate Negative Scenario for a single node")
                .addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(httpsFlows.deActivateHttps(true))
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(AVAILABLE_USERS).bindTo(ADDED_NODES))
                .doParallel(vUser).build();
        startScenario(scenario);
    }

    @Test(enabled = true, priority = 11, groups = { "Functional", "NSS", "KGB" })
    @TestSuite
    public void httpsGetNegative() {
        doParallelNodesBase(INPUT_DATASOURCE, "NSCS_HTTPS_GET_WrongUserRole",
                context.dataSource(HTTPS_NEGATIVE_WRONGROLE_TESTS), context.dataSource(SINGLE_NODE_DATA_SOURCE), getUserListNegative);
        final TestScenario scenario = dataDrivenScenario("HTTPS Get Negative Scenario for a single node")
                .addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(httpsFlows.getHttpBasic())
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(AVAILABLE_USERS).bindTo(ADDED_NODES))
                .doParallel(vUser).build();
        startScenario(scenario);
    }
    /*---------------------------------------*/
    /*---- NEGATIVE USER ROLE TEST END  -----*/
    /*---------------------------------------*/

    /*---------------------------------------*/
    /*--------- UNSUPPORTED TEST START ------*/
    /*---------------------------------------*/
    @Test(enabled = true, priority = 8, groups = { "KGB" })
    @TestSuite
    public void httpCommandsUnsupportedNodes() {
        final DataRecord firstUser = Iterables.filter(context.dataSource(AVAILABLE_USERS), PredicateUtil.nscsAdm()).iterator().next();
        doParallelNodesBase(INPUT_DATASOURCE, "NSCS_HTTPS_COMMANDS_UNSUPPORTED_NODES",
                context.dataSource(HTTPS_NEGATIVE_NOTSUPPORTEDNODES_TESTS), context.dataSource(ADDED_NODES),
                TestDataSourceFactory.createDataSource(firstUser.getAllFields()));
        final TestScenario scenario = dataDrivenScenario("HTTPS command Unsupported nodes Negative scenario")
                .addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(httpsFlows.getHttpBasic())
                .addFlow(httpsFlows.activateHttps(false))
                .addFlow(httpsFlows.deActivateHttps(false))
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(AVAILABLE_USERS).bindTo(ADDED_NODES))
                .doParallel(vUserKgbOnly).build();
        startScenario(scenario);
    }
    /*---------------------------------------*/
    /*-------- UNSUPPORTED TEST END   -------*/
    /*---------------------------------------*/

    /*---------------------------------------*/
    /*------- NOT EXIST TEST START ----------*/
    /*---------------------------------------*/
   @Test(enabled = true, priority = 12, groups = { "Functional", "NSS", "KGB" })
    @TestSuite
    public void httpCommandsNotExistingNodes() {
        doParallelNodesBase(INPUT_DATASOURCE, "NSCS_HTTPS_COMMANDS_NOT_EXISTING_NODES", context.dataSource(HTTPS_NEGATIVE_NOTEXISTNODES_TESTS),
                context.dataSource(NODES_TO_ADD_NOT_EXIST), availableUserFiltered(PredicateUtil.nscsAdm()));
        final TestScenario scenario = dataDrivenScenario("HTTPS command not exist nodes Negative scenario")
                .addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(httpsFlows.getHttpBasic())
                .addFlow(httpsFlows.activateHttps(false))
                .addFlow(httpsFlows.deActivateHttps(false))
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(AVAILABLE_USERS).bindTo(ADDED_NODES))
                .doParallel(vUser).build();
        startScenario(scenario);
    }

    /*---------------------------------------*/
    /*-------- NOT EXIST TEST END   ---------*/
    /*---------------------------------------*/

    /*---------------------------------------*/
    /*--------- UNSYNCH TEST START ----------*/
    /*---------------------------------------*/
   @Test(enabled = true, priority = 13, groups = { "Functional", "NSS", "KGB" })
    @TestSuite
    public void httpCommandsUnsyncNodes() {
        doParallelNodesBase(INPUT_DATASOURCE, "NSCS_HTTPS_COMMANDS_UNSYNCH_NODES",
                context.dataSource(HTTPS_NEGATIVE_UNSYNCHNODES_TESTS), context.dataSource(SINGLE_NODE_DATA_SOURCE),
                availableUserFiltered(PredicateUtil.nscsAdm()));
        final TestScenario scenario = dataDrivenScenario("HTTPS command Unsynch nodes Negative scenario")
                .addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(utilityFlows.disableSupervision())
                .addFlow(httpsFlows.activateHttps(false))
                .addFlow(httpsFlows.deActivateHttps(false))
                .addFlow(httpsFlows.getHttpBasic())
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(AVAILABLE_USERS).bindTo(ADDED_NODES))
                .doParallel(vUser).build();
        startScenario(scenario);
    }
    /*---------------------------------------*/
    /*--------- UNSYNCH TEST END   ----------*/
    /*---------------------------------------*/

    private boolean httpsApplicationsVerificationPreCondIsNeeded(final TestDataSource<DataRecord> originalDataSource) {
        final DataRecord first = Iterables.getLast(originalDataSource, null);
        return first.getFieldValue(HTTPS_FUNCT_VERIFICATION_IS_PRE_COND_NEEDED);
    }

    private boolean httpsVerificationCompareStatus(final TestDataSource<DataRecord> originalDataSource) {
        final DataRecord first = Iterables.getLast(originalDataSource, null);
        final String compare = first.getFieldValue(COMPARE).toString();
        return compare.equals(MISMATCH);
    }

    private void evaluatePrecondition() {
        isHttpsActionRequest = httpsApplicationsVerificationPreCondIsNeeded(context.dataSource(HTTPS_VERIFICATION_PRE_COND_DATA_SOURCES));
        HttpsDeactivatePreCond = isHttpsActionRequest && httpsVerificationCompareStatus(context.dataSource(HTTPS_VERIFICATION_PRE_COND_DATA_SOURCES));
        HttpsActivatePreCond = isHttpsActionRequest;
        LOGGER.info("\n HTTPS Applications verification Test - PreCondition flags: \n HttpsDeactivatePreCond = " + HttpsDeactivatePreCond + "\n HttpsActivatePreCond = " + HttpsActivatePreCond);
    }
}
