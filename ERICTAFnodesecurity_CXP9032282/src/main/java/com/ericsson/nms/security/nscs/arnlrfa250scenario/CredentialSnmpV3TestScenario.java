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
import static com.ericsson.nms.security.nscs.arnlrfa250scenario.SetupAndTeardownScenarioCredentialSnmpV3.CRED_SL_AUTHNOPRIV;
import static com.ericsson.nms.security.nscs.arnlrfa250scenario.SetupAndTeardownScenarioCredentialSnmpV3.CRED_SL_AUTHNOPRIV_NOT_EXIST;
import static com.ericsson.nms.security.nscs.arnlrfa250scenario.SetupAndTeardownScenarioCredentialSnmpV3.CRED_SL_AUTHPRIV;
import static com.ericsson.nms.security.nscs.arnlrfa250scenario.SetupAndTeardownScenarioCredentialSnmpV3.CRED_SL_AUTHPRIV_NEGATIVE;
import static com.ericsson.nms.security.nscs.arnlrfa250scenario.SetupAndTeardownScenarioFtpes.NODES_TO_ADD_NOT_EXIST;
import static com.ericsson.nms.security.nscs.predicate.PredicateUtil.userRoleSuiteNamePredicate;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.ADDED_NODES;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.AVAILABLE_USERS;

import javax.inject.Inject;

import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.ericsson.cifwk.taf.annotations.TestSuite;
import com.ericsson.cifwk.taf.datasource.DataRecord;
import com.ericsson.cifwk.taf.scenario.TestScenario;
import com.ericsson.oss.testware.nodesecurity.flows.CredentialsFlows;
import com.google.common.base.Predicate;

@SuppressWarnings({"PMD.LawOfDemeter"})
public class CredentialSnmpV3TestScenario extends ScenarioUtility {

    @Inject
    private CredentialsFlows credentialsFlows;

    @BeforeClass(groups = { "Functional", "NSS", "RFA250", "ARNL" })
    public void beforeClass() {
        final Predicate<DataRecord> predicatePositive = userRoleSuiteNamePredicate("roles",
                SetupAndTeardownScenarioCredentialSnmpV3.positiveCustomRolesList());
        final Predicate<DataRecord> predicateNegative = userRoleSuiteNamePredicate("roles",
                SetupAndTeardownScenarioCredentialSnmpV3.negativeCustomRolesList());
        super.beforeClass(predicatePositive, predicateNegative);
    }

    @Test(enabled = true, priority = 1, groups = { "Functional", "NSS", "RFA250" })
    @TestSuite
    public void credentialAuthNoPrivPositive() {
        doParallelNodesBase(INPUT_DATASOURCE, "NSCS_CREDENTIAL_AUTHONOPRIV_CorrectUserRole",
                context.dataSource(CRED_SL_AUTHNOPRIV), context.dataSource(ADDED_NODES),
                userListPositive);
        final TestScenario scenario = dataDrivenScenario("Credential AuthNoPriv Test Scenario")
                //Pre-Condition Start
                .addFlow(loginLogoutRestFlows.loginBuilder())
                //Test Start
                .addFlow(credentialsFlows.credentialsSnmpV3CommandBasic())
                .addFlow(credentialsFlows.credentialsGetSnmpV3StateBasic("show"))
                .addFlow(credentialsFlows.credentialsGetSnmpV3StateBasic("hide"))
                //Test End
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(AVAILABLE_USERS).bindTo(ADDED_NODES))
                .doParallel(vUser).build();
        startScenario(scenario);
    }

    @Test(enabled = true, priority = 2, groups = { "Functional", "NSS", "RFA250" })
    @TestSuite
    public void credentialAuthPrivPositive() {
        doParallelNodesBase(INPUT_DATASOURCE, "NSCS_CREDENTIAL_AUTHPRIV_CorrectUserRole",
                context.dataSource(CRED_SL_AUTHPRIV), context.dataSource(ADDED_NODES),
                userListPositive);
        final TestScenario scenario = dataDrivenScenario("Credential AuthPriv Test Scenario")
                // Pre-Condition Start
                .addFlow(loginLogoutRestFlows.loginBuilder())
                // Test Start
                .addFlow(credentialsFlows.credentialsSnmpV3CommandBasic())
                .addFlow(credentialsFlows.credentialsGetSnmpV3StateBasic("show"))
                .addFlow(credentialsFlows.credentialsGetSnmpV3StateBasic("hide"))
                // Test End
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(AVAILABLE_USERS).bindTo(ADDED_NODES))
                .doParallel(vUser).build();
        startScenario(scenario);
    }

    @Test(enabled = true, priority = 3, groups = { "Functional", "NSS", "RFA250" })
    @TestSuite
    public void credentialNBIAuthPrivPositive() {
        final Predicate<DataRecord> predicateNbiPositive = userRoleSuiteNamePredicate("roles",
                SetupAndTeardownScenarioCredentialSnmpV3.positiveNbiCustomRolesList());
        userListNbiPositive = availableUserFiltered(predicateNbiPositive);
        doParallelNodesBase(INPUT_NBI_DATASOURCE, "NSCS_CREDENTIAL_AUTH_PRIV_NBI_CorrectUserRole",
                context.dataSource(CRED_SL_AUTHPRIV), context.dataSource(ADDED_NODES),
                userListNbiPositive);
        final TestScenario scenario = dataDrivenScenario("Credential NBI AuthPriv Test Scenario")
                // Pre-Condition Start
                .addFlow(loginLogoutRestFlows.loginBuilder())
                // Test Start
                .addFlow(credentialsFlows.credentialsNbiUpdateBasic())
                // Test End
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_NBI_DATASOURCE).bindTo(AVAILABLE_USERS).bindTo(ADDED_NODES))
                .doParallel(vUser).build();
        startScenario(scenario);
    }

    @Test(enabled = true, priority = 4, groups = { "Functional", "NSS", "RFA250" })
    @TestSuite
    public void credentialNBIAuthPrivNegative() {
        final Predicate<DataRecord> predicateNbiNegative = userRoleSuiteNamePredicate("roles",
                SetupAndTeardownScenarioCredentialSnmpV3.negativeNbiCustomRolesList());
        userListNbiNegative = availableUserFiltered(predicateNbiNegative);
        doParallelNodesBase(INPUT_NBI_DATASOURCE_NEGATIVE, "NSCS_CREDENTIAL_AUTHPRIV_Nbi_WrongRole",
                context.dataSource(CRED_SL_AUTHPRIV_NEGATIVE), context.dataSource(ADDED_NODES),
                userListNbiNegative);
        final TestScenario scenario = dataDrivenScenario("Credential NBI AuthPriv Negative Test Scenario")
                // Pre-Condition Start
                .addFlow(loginLogoutRestFlows.loginBuilder())
                // Test Start
                .addFlow(credentialsFlows.credentialsNbiUpdateBasic())
                // Test End
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_NBI_DATASOURCE_NEGATIVE).bindTo(AVAILABLE_USERS).bindTo(ADDED_NODES))
                .doParallel(vUser).build();
        startScenario(scenario);
    }

    @Test(enabled = true, priority = 5, groups = { "Functional", "NSS", "RFA250" })
    @TestSuite
    public void credentialNBIAuthNoPrivPositive() {
        final Predicate<DataRecord> predicateNbiPositive = userRoleSuiteNamePredicate("roles",
                SetupAndTeardownScenarioCredentialSnmpV3.positiveNbiCustomRolesList());
        userListNbiPositive = availableUserFiltered(predicateNbiPositive);
        doParallelNodesBase(INPUT_NBI_DATASOURCE, "NSCS_CREDENTIAL_AUTH_NO_PRIV_NBI_CorrectUserRole",
                context.dataSource(CRED_SL_AUTHNOPRIV), context.dataSource(ADDED_NODES),
                userListNbiPositive);
        final TestScenario scenario = dataDrivenScenario("Credential NBI AuthNoPriv Test Scenario")
                // Pre-Condition Start
                .addFlow(loginLogoutRestFlows.loginBuilder())
                // Test Start
                .addFlow(credentialsFlows.credentialsNbiUpdateBasic())
                // Test End
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_NBI_DATASOURCE).bindTo(AVAILABLE_USERS).bindTo(ADDED_NODES))
                .doParallel(vUser).build();
        startScenario(scenario);
    }

    @Test(enabled = true, priority = 5, groups = { "Functional", "NSS", "RFA250" })
    @TestSuite
    public void credentialNBIAuthNoPrivNegative() {
        final Predicate<DataRecord> predicateNbiPositive = userRoleSuiteNamePredicate("roles",
                SetupAndTeardownScenarioCredentialSnmpV3.positiveNbiCustomRolesList());
        userListNbiPositive = availableUserFiltered(predicateNbiPositive);
        doParallelNodesBase(INPUT_NBI_DATASOURCE, "NSCS_CREDENTIAL_AUTH_NO_PRIV_NBI_NotExistingNE",
                context.dataSource(CRED_SL_AUTHNOPRIV_NOT_EXIST),
                context.dataSource(NODES_TO_ADD_NOT_EXIST),
                userListNbiPositive);
        final TestScenario scenario = dataDrivenScenario("Credential NBI AuthNoPriv not existing NE Test Scenario")
                // Pre-Condition Start
                .addFlow(loginLogoutRestFlows.loginBuilder())
                // Test Start
                .addFlow(credentialsFlows.credentialsNbiUpdateBasic())
                // Test End
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_NBI_DATASOURCE).bindTo(AVAILABLE_USERS).bindTo(ADDED_NODES))
                .doParallel(vUser).build();
        startScenario(scenario);
    }

}

