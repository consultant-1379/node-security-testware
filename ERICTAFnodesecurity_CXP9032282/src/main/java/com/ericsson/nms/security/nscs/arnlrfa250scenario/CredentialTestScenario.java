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
import static com.ericsson.nms.security.nscs.arnlrfa250scenario.SetupAndTeardownScenarioCredential.SYNTAX_NEGATIVE_DATASOURCE;
import static com.ericsson.nms.security.nscs.predicate.PredicateUtil.userRoleSuiteNamePredicate;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.ADDED_NODES;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.AVAILABLE_USERS;

import java.lang.reflect.Method;
import java.util.concurrent.TimeUnit;

import javax.inject.Inject;

import org.testng.ITestContext;
import org.testng.annotations.AfterClass;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Optional;
import org.testng.annotations.Parameters;
import org.testng.annotations.Test;

import com.ericsson.cifwk.taf.annotations.TestSuite;
import com.ericsson.cifwk.taf.datasource.DataRecord;
import com.ericsson.cifwk.taf.scenario.TestScenario;
import com.ericsson.cifwk.taf.data.DataHandler;
import com.ericsson.cifwk.taf.scenario.api.ScenarioExceptionHandler;
import com.ericsson.nms.security.nscs.predicate.PredicateUtil;
import com.ericsson.oss.testware.nodesecurity.flows.CredentialsFlows;
import com.ericsson.oss.testware.nodesecurity.flows.SyntaxFlowsGeneric;
import com.ericsson.oss.testware.nodesecurity.steps.SyntaxTestSteps;
import com.google.common.base.Preconditions;
import com.google.common.base.Predicate;
import com.google.common.collect.Iterables;

@SuppressWarnings({"PMD.LawOfDemeter", "PMD.ExcessiveImports"})
public class CredentialTestScenario extends ScenarioUtilityAgat {

    private static final String TITLE_CRED_CREATE_NODELIST = "Credentials Create with node list";
    private static final String TITLE_CRED_UPDATE_NODELIST = "Credentials Update with node list";

    @Inject
    final static String NODETYPE_CM_SYNC = "credential.nodeType.skip.cm_sync";

    final String nodeTypeFilterValue = DataHandler.getConfiguration().getProperty(NODETYPE_CM_SYNC, "nodeType =='Router6672'", String.class);

    @Inject
    private CredentialsFlows credentialsFlows;

    @Inject
    private SyntaxFlowsGeneric syntaxFlowsGeneric;

    @Inject
    private SetupAndTeardownScenarioCredential setupAndTeardownScenarioCredential;

    @BeforeClass(groups = { "Functional", "NSS", "RFA250", "ARNL", "ENM_EXTERNAL_TESTWARE" })
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
    }

    @AfterClass(groups = { "Functional", "NSS", "RFA250", "ARNL", "ENM_EXTERNAL_TESTWARE" })
    public void afterClass() {
        if (SetupAndTeardownScenario.isAgat()) {
            setupAndTeardownScenarioCredential.onAfterSuite();
        }
    }

    @Test(enabled = true, priority = 1, groups = { "Functional", "NSS", "RFA250", "ARNL", "ENM_EXTERNAL_TESTWARE" })
    @TestSuite
    public void credentialCreatePositive() {
        doParallelNodesBase(INPUT_DATASOURCE, "NSCS_CREDENTIAL_CREATE_CorrectUserRole", TITLE_CRED_CREATE_NODELIST, context.dataSource(ADDED_NODES),
                userListPositive);
        final TestScenario scenario = dataDrivenScenario("Credential Create Test Scenario")
                //Pre-Condition Start
                .addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(credentialsFlows.credentialsDeleteFlow().withExceptionHandler(ScenarioExceptionHandler.LOGONLY))
                //Pre-Condition End
                .addFlow(flow("Wait").pause(20, TimeUnit.SECONDS))
                //Test Start
                .addFlow(credentialsFlows.credentialsCreate(SetupAndTeardownScenarioCredential.CRED_CREATE))
                //Test End
                .addFlow(flow("Wait").pause(20, TimeUnit.SECONDS))
                //Post-Condition Start
                .addFlow(credentialsFlows.credentialsUpdateBasic()).alwaysRun()
                //Post-Condition End
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(AVAILABLE_USERS).bindTo(ADDED_NODES)).doParallel(vUser).build();
        startScenario(scenario);
    }

    @Test(enabled = true, priority = 2, groups = { "Functional", "NSS", "RFA250", "ARNL", "ENM_EXTERNAL_TESTWARE" })
    @TestSuite
    public void credentialUpdatePositive() {
        doParallelNodesBase(INPUT_DATASOURCE, "NSCS_CREDENTIAL_UPDATE_CorrectUserRole", TITLE_CRED_UPDATE_NODELIST, context.dataSource(ADDED_NODES),
                userListPositive);
        final TestScenario scenario = dataDrivenScenario("Credential Update Test Scenario").addFlow(loginLogoutRestFlows.loginBuilder())
                //Test Start
                .addFlow(credentialsFlows.credentialsUpdate(SetupAndTeardownScenarioCredential.CRED_UPDATE))
                //Test End
                .addFlow(flow("Wait").pause(20, TimeUnit.SECONDS))
                //Post-Condition Start
                .addFlow(credentialsFlows.credentialsUpdateBasic()).alwaysRun()
                //Post-Condition End
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(AVAILABLE_USERS).bindTo(ADDED_NODES)).doParallel(vUser).build();
        startScenario(scenario);
    }

    @Test(enabled = true, priority = 3, groups = { "Functional", "NSS" })
    @TestSuite
    public void credentialCreateWrongUser() {
        doParallelNodesBase(INPUT_DATASOURCE, "NSCS_CREDENTIAL_CREATE_WrongUserRole",
                context.dataSource(SetupAndTeardownScenarioCredential.CRED_CREATE_WRONG_USER), context.dataSource(ADDED_NODES), userListNegative);
        final TestScenario scenario = dataDrivenScenario("Credential Create Test Scenario Wrong User").addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(credentialsFlows.credentialsCreateBasic()).addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(AVAILABLE_USERS).bindTo(ADDED_NODES)).doParallel(vUser).build();
        startScenario(scenario);
    }

    @Test(enabled = true, priority = 4, groups = { "Functional", "NSS" })
    @TestSuite
    public void credentialUpdateWrongUser() {
        doParallelNodesBase(INPUT_DATASOURCE, "NSCS_CREDENTIAL_UPDATE_WrongUserRole",
                context.dataSource(SetupAndTeardownScenarioCredential.CRED_UPDATE_WRONG_USER), context.dataSource(ADDED_NODES), userListNegative);
        final TestScenario scenario = dataDrivenScenario("Credential Update Test Scenario Wrong User").addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(credentialsFlows.credentialsUpdateBasic()).addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(AVAILABLE_USERS).bindTo(ADDED_NODES)).doParallel(vUser).build();
        startScenario(scenario);
    }

    @Test(enabled = true, priority = 5, groups = { "Functional", "NSS" })
    @TestSuite
    public void credentialsNegativeSyntax() {
        final Predicate<DataRecord> predicate = PredicateUtil.nsuAdm();
        final Iterable<DataRecord> userList = Iterables.filter(context.dataSource(AVAILABLE_USERS), predicate);
        Preconditions.checkArgument(!Iterables.isEmpty(userList), String.format(DATASOURCE_ERROR, AVAILABLE_USERS));
        dataDrivenDataSourceSyntax(INPUT_DATASOURCE, "NSCS_CREDENTIALS_NEGATIVE_SYNTAX", context.dataSource(SYNTAX_NEGATIVE_DATASOURCE),
                context.dataSource(ADDED_NODES), userList);
        ScenarioUtility.debugScope(LOGGER, context.dataSource(INPUT_DATASOURCE));
        final TestScenario scenario = dataDrivenScenario("Credential negative syntax")
                .addFlow(loginLogoutRestFlows.loginBuilder()).addFlow(syntaxFlowsGeneric.syntaxCommandBasic())
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun().withScenarioDataSources(dataSource(INPUT_DATASOURCE)
                        .bindTo(SyntaxTestSteps.DataSource.SYNTAX_INFO_DATASOURCE).bindTo(AVAILABLE_USERS).bindTo(ADDED_NODES))
                .doParallel(vUser).build();
        startScenario(scenario);
    }

    @BeforeMethod(groups = {"ARNL", "ENM_EXTERNAL_TESTWARE"})  // Reduced list, so as to execute it only in RNL/Agat
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

    @AfterMethod(groups = {"ARNL", "ENM_EXTERNAL_TESTWARE"})  // Reduced list, so as to execute it only in RNL/Agat
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

   @BeforeMethod(groups = { "Functional", "NSS", "RFA250", "ARNL", "KGB" })
    public void beforeMethod(final Method method) {
        if (method.getName().startsWith("credentialsNegativeSyntax")) {
            super.setupMultiNodes();
        }
    }
}
