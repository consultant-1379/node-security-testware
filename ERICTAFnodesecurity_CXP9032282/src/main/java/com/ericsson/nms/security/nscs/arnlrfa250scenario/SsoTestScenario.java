/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2020
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
import com.ericsson.oss.testware.nodesecurity.flows.SsoFlows;
import com.google.common.base.Predicate;

@SuppressWarnings({ "PMD.LawOfDemeter" })
public class SsoTestScenario extends ScenarioUtilityAgat {

    private static final String SSO_ENABLE_CORRECT_USER = "SSO Enabling with correct user";
    private static final String SSO_DISABLE_CORRECT_USER = "SSO Disabling with correct user";
    private static final String SSO_ENABLE_WRONG_USER = "SSO Enabling with wrong user";
    private static final String SSO_DISABLE_WRONG_USER = "SSO Disabling with wrong user";

    @Inject
    private TestContext context;

    @Inject
    private SsoFlows ssoFlows;

    @Override
    @BeforeClass(groups = { "Functional", "NSS", "RFA250", "ARNL" })
    public void beforeClass() {
        final Predicate<DataRecord> predicatePositive = userRoleSuiteNamePredicate("roles",
                SetupAndTeardownScenarioSso.positiveCustomRolesList());
        final Predicate<DataRecord> predicateNegative = userRoleSuiteNamePredicate("roles",
                SetupAndTeardownScenarioSso.negativeCustomRolesList());
        super.beforeClass(predicatePositive, predicateNegative);
    }

    @Test(enabled = true, priority = 1, groups = { "Functional", "NSS", "RFA250" })
    @TestSuite
    public void enableSsoPositive() {
        doParallelNodesBase(INPUT_DATASOURCE, "MR44689_SSO_ENABLING_WITH_CORRECT_USER", SSO_ENABLE_CORRECT_USER,
                context.dataSource(SetupAndTeardownScenarioSso.SSO_ENABLE_CORRECT_USER), context.dataSource(ADDED_NODES), userListPositive);
        final TestScenario scenario = dataDrivenScenario("SSO Enabling Test Scenario - Correct user")
                .addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(ssoFlows.enableSso())
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(AVAILABLE_USERS).bindTo(ADDED_NODES))
                .doParallel(vUser).build();
        startScenario(scenario);
    }

    @Test(enabled = true, priority = 2, groups = { "Functional", "NSS", "RFA250" })
    @TestSuite
    public void disableSsoPositive() {
        doParallelNodesBase(INPUT_DATASOURCE, "MR44689_SSO_DISABLING_WITH_CORRECT_USER", SSO_DISABLE_CORRECT_USER,
                context.dataSource(SetupAndTeardownScenarioSso.SSO_DISABLE_CORRECT_USER), context.dataSource(ADDED_NODES), userListPositive);
        final TestScenario scenario = dataDrivenScenario("SSO Disabling Test Scenario - Correct user")
                .addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(ssoFlows.disableSso())
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(AVAILABLE_USERS).bindTo(ADDED_NODES))
                .doParallel(vUser).build();
        startScenario(scenario);
    }

    @Test(enabled = true, priority = 3, groups = { "Functional", "NSS", "RFA250" })
    @TestSuite
    public void enableSsoNegative() {
        doParallelNodesBase(INPUT_DATASOURCE, "MR44689_SSO_ENABLING_WITH_WRONG_USER", SSO_ENABLE_WRONG_USER,
                context.dataSource(SetupAndTeardownScenarioSso.SSO_ENABLE_WRONG_USER), context.dataSource(ADDED_NODES), userListNegative);
        final TestScenario scenario = dataDrivenScenario("SSO Enabling Test Scenario - Wrong user")
                .addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(ssoFlows.enableSso())
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(AVAILABLE_USERS).bindTo(ADDED_NODES))
                .doParallel(vUser).build();
        startScenario(scenario);
    }

    @Test(enabled = true, priority = 4, groups = { "Functional", "NSS", "RFA250" })
    @TestSuite
    public void disableSsoNegative() {
        doParallelNodesBase(INPUT_DATASOURCE, "MR44689_SSO_DISABLING_WITH_WRONG_USER", SSO_DISABLE_WRONG_USER,
                context.dataSource(SetupAndTeardownScenarioSso.SSO_DISABLE_WRONG_USER), context.dataSource(ADDED_NODES), userListNegative);
        final TestScenario scenario = dataDrivenScenario("SSO Disabling Test Scenario - Wrong user")
                .addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(ssoFlows.disableSso())
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(AVAILABLE_USERS).bindTo(ADDED_NODES))
                .doParallel(vUser).build();
        startScenario(scenario);
    }
}
