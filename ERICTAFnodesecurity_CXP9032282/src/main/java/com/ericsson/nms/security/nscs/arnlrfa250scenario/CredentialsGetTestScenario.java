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
import static com.ericsson.nms.security.nscs.arnlrfa250scenario.SetupAndTeardownScenarioCredential.GET_CREDENTIAL_NEGATIVE_DATASOURCE;
import static com.ericsson.nms.security.nscs.arnlrfa250scenario.SetupAndTeardownScenarioCredential.GET_CREDENTIAL_POSITIVE_DATASOURCE;
import static com.ericsson.nms.security.nscs.arnlrfa250scenario.SetupAndTeardownScenarioCredential.GET_CREDENTIAL_POSITIVE_WITHFILE_DATASOURCE;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.ADDED_NODES;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.AVAILABLE_USERS;

import javax.inject.Inject;

import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.ericsson.cifwk.taf.annotations.TestSuite;
import com.ericsson.cifwk.taf.datasource.DataRecord;
import com.ericsson.cifwk.taf.scenario.TestScenario;
import com.ericsson.nms.security.nscs.predicate.PredicateUtil;
import com.ericsson.oss.testware.nodesecurity.flows.SyntaxFlowsGeneric;
import com.ericsson.oss.testware.nodesecurity.steps.SyntaxTestSteps;
import com.google.common.base.Preconditions;
import com.google.common.base.Predicate;
import com.google.common.collect.Iterables;

@SuppressWarnings({"PMD.LawOfDemeter"})
public class CredentialsGetTestScenario extends ScenarioUtility {

    //Test Titles contants
    private static final String DATASOURCE_ERROR = "No Data in Data Source: %s";
    private static final String GET_POSITIVE_CRED = "Get Credential Positive Test Scenario";
    private static final String GET_NEGATIVE_CRED = "Get Credential Negative Test Scenario";
    private static final String GET_POSITIVE_CRED_WITH_FILE = "Get Credential Positive with file Test Scenario";

    // TODO If the test case should move to AGAT consider to pass these test case titles to dataDrivenDataSourceSyntax method changing signature
    //    private static final String TITLE_TMS_GET_POSITIVE_CRED = "Node Security commands to get nodes credentials with password encrypted - positive scenarios";
    //    private static final String TITLE_TMS_GET_NEGATIVE_CRED = "Node Security commands to get nodes credentials with password encrypted - negative scenarios";

    @Inject
    private SyntaxFlowsGeneric syntaxFlowsGeneric;

    @BeforeClass(groups = { "Functional", "NSS" })
    public void beforeClass() {
        super.beforeClass();
    }

    @Test(enabled = true, priority = 1, groups = { "Functional", "NSS" })
    @TestSuite
    public void getCredentialPositive() {
        final Predicate<DataRecord> predicate = PredicateUtil.nsuGetCredentialRole();
        final Iterable<DataRecord> userList = Iterables.filter(context.dataSource(AVAILABLE_USERS), predicate);
        Preconditions.checkArgument(!Iterables.isEmpty(userList),
                String.format(DATASOURCE_ERROR, AVAILABLE_USERS));
        dataDrivenDataSourceSyntax(INPUT_DATASOURCE, "TORF-129036_1",
                context.dataSource(GET_CREDENTIAL_POSITIVE_DATASOURCE), context.dataSource(ADDED_NODES),
                userList);
        ScenarioUtility.debugScope(LOGGER, context.dataSource(INPUT_DATASOURCE));
        final TestScenario scenario = dataDrivenScenario(GET_POSITIVE_CRED)
                .addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(syntaxFlowsGeneric.getSyntaxInfoBasic())
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE)
                        .bindTo(SyntaxTestSteps.DataSource.SYNTAX_INFO_DATASOURCE).bindTo(AVAILABLE_USERS).bindTo(ADDED_NODES))
                .doParallel(vUser).build();
        startScenario(scenario);
    }

    @Test(enabled = true, priority = 2, groups = { "Functional", "NSS" })
    @TestSuite
    public void getCredentialsPositiveWithFile() {
        final Predicate<DataRecord> predicate = PredicateUtil.nsuAdm();
        final Iterable<DataRecord> userList = Iterables.filter(context.dataSource(AVAILABLE_USERS), predicate);
        Preconditions.checkArgument(!Iterables.isEmpty(userList),
                String.format(DATASOURCE_ERROR, AVAILABLE_USERS));
        dataDrivenDataSourceSyntax(INPUT_DATASOURCE, "TORF-129036_1", context.dataSource(GET_CREDENTIAL_POSITIVE_WITHFILE_DATASOURCE),
                context.dataSource(ADDED_NODES),
                userList);
        ScenarioUtility.debugScope(LOGGER, context.dataSource(INPUT_DATASOURCE));
        final TestScenario scenario = dataDrivenScenario(GET_POSITIVE_CRED_WITH_FILE)
                .addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(syntaxFlowsGeneric.getSyntaxInfoBasic())
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE)
                        .bindTo(SyntaxTestSteps.DataSource.SYNTAX_INFO_DATASOURCE).bindTo(AVAILABLE_USERS).bindTo(ADDED_NODES))
                .doParallel(vUser).build();
        startScenario(scenario);
    }

    @Test(enabled = true, priority = 3, groups = { "Functional", "NSS" })
    @TestSuite
    public void getCredentialsNegative() {
        final Predicate<DataRecord> predicate = PredicateUtil.nsuGetCredentialRole();
        final Iterable<DataRecord> userList = Iterables.filter(context.dataSource(AVAILABLE_USERS), predicate);
        Preconditions.checkArgument(!Iterables.isEmpty(userList),
                String.format(DATASOURCE_ERROR, AVAILABLE_USERS));
        dataDrivenDataSourceSyntax(INPUT_DATASOURCE, "TORF-129036_2", context.dataSource(GET_CREDENTIAL_NEGATIVE_DATASOURCE),
                context.dataSource(ADDED_NODES),
                userList);
        ScenarioUtility.debugScope(LOGGER, context.dataSource(INPUT_DATASOURCE));
        final TestScenario scenario = dataDrivenScenario(GET_NEGATIVE_CRED)
                .addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(syntaxFlowsGeneric.getSyntaxInfoBasic())
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE)
                        .bindTo(SyntaxTestSteps.DataSource.SYNTAX_INFO_DATASOURCE).bindTo(AVAILABLE_USERS).bindTo(ADDED_NODES))
                .doParallel(vUser).build();
        startScenario(scenario);
    }

}
