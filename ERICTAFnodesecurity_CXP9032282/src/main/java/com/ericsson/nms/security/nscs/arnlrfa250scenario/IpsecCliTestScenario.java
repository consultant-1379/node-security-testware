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
import com.ericsson.nms.security.nscs.predicate.PredicateUtil;
import com.ericsson.nms.security.pki.flows.ConfigMngFlows;
import com.ericsson.oss.testware.nodesecurity.flows.IpsecCliFlows;
import com.ericsson.oss.testware.nodesecurity.steps.IpsecCliTestSteps;
import com.google.common.base.Preconditions;
import com.google.common.base.Predicate;
import com.google.common.collect.Iterables;

@SuppressWarnings({"PMD.LawOfDemeter"})
public class IpsecCliTestScenario extends ScenarioUtility {

    private static final Logger LOGGER = LoggerFactory.getLogger(IpsecCliTestScenario.class);

    @Inject
    private IpsecCliFlows ipsecCliFlows;
    
    @Inject
    private ConfigMngFlows configMngFlows;

    @BeforeClass(groups = { "Functional", "NSS", "RFA250" })
    public void beforeClass() {
        super.beforeClass();
        LOGGER.info("\n   BEFORE CLASS IPSEC CLI TEST - START \n");
        dumpDataSource();
        LOGGER.info("\n   BEFORE CLASS IPSEC CLI TEST - END \n");
        Preconditions.checkArgument(!Iterables.isEmpty(context.dataSource(AVAILABLE_USERS)),
                String.format(DATASOURCE_ERROR, AVAILABLE_USERS));
        final TestScenario beforeClassScenario = scenario("Before Class IPSEC CLI Scenario")
                .addFlow(utilityFlows.login(PredicateUtil.nscsAdm(), vUser))
                .addFlow(configMngFlows.updateAlgorithmsFlow())
                .addFlow(ipsecCliFlows.ipSecFreeIpFlow())
                .addFlow(utilityFlows.logout(PredicateUtil.nscsAdm(), vUser)).alwaysRun()
                .build();
        startScenario(beforeClassScenario);
    }

    @Test(enabled = true, priority = 1, groups = { "Functional", "NSS", "RFA250" })
    @TestSuite
    public void ipsecActivatePositiveTest() {
        final Predicate<DataRecord> predicate = PredicateUtil.nsuAdm();
        Preconditions.checkArgument(!Iterables.isEmpty(Iterables.filter(context.dataSource(AVAILABLE_USERS), PredicateUtil.nsuAdm())),
                String.format(DATASOURCE_ERROR, AVAILABLE_USERS));
        dataDrivenDataSource(INPUT_DATASOURCE, "NSCS_IPSEC_ON_CorrectUserRole",
                context.dataSource(ADDED_NODES));
        final TestScenario scenario = dataDrivenScenario("Ipsec Activation Test Scenario - Correct user")
                .addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(utilityFlows.verifySyncNodes())
                .addFlow(ipsecCliFlows.changeIpsec("IPSEC ACTIVATION", SetupAndTeardownScenarioIpsecCli.IPSEC_ACTIVATE, IpsecCliTestSteps.FREE_IP))
                .addFlow(utilityFlows.recursiveVerifySyncNode())
                .addFlow(ipsecCliFlows.generateNetworkMapFlow()).alwaysRun()
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(ADDED_NODES).bindTo(NODES_TO_ADD),
                        dataSource(AVAILABLE_USERS).withFilter(predicate))
                .doParallel(vUser).build();
        startScenario(scenario);
    }

    @Test(enabled = true, priority = 2, groups = { "Functional", "NSS", "RFA250" })
    @TestSuite
    public void ipsecDeActivatePositiveTest() {
        final Predicate<DataRecord> predicate = PredicateUtil.nsuAdm();
        Preconditions.checkArgument(!Iterables.isEmpty(Iterables.filter(context.dataSource(AVAILABLE_USERS), PredicateUtil.nsuAdm())),
                String.format(DATASOURCE_ERROR, AVAILABLE_USERS));
        dataDrivenDataSource(INPUT_DATASOURCE, "NSCS_IPSEC_OFF_CorrectUserRole",
                context.dataSource(ADDED_NODES));
        final TestScenario scenario = dataDrivenScenario("Ipsec Deactivation Test Scenario")
                .addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(utilityFlows.recursiveVerifySyncNode())
                .addFlow(ipsecCliFlows.changeIpsec("IPSEC DEACTIVATION", SetupAndTeardownScenarioIpsecCli.IPSEC_DEACTIVATE, IpsecCliTestSteps.FREE_IP))
                .addFlow(utilityFlows.recursiveVerifySyncNode())
                .addFlow(ipsecCliFlows.generateNetworkMapFlow()).alwaysRun()
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(ADDED_NODES).bindTo(NODES_TO_ADD),
                        dataSource(AVAILABLE_USERS).withFilter(predicate))
                .doParallel(vUser).build();
        startScenario(scenario);
    }

    @Test(enabled = true, priority = 3, groups = { "Functional", "NSS" })
    @TestSuite
    public void ipsecActivateNegativeTest() {
        final Predicate<DataRecord> predicate = PredicateUtil.nsuOper();
        Preconditions.checkArgument(!Iterables.isEmpty(Iterables.filter(context.dataSource(AVAILABLE_USERS), PredicateUtil.nsuOper())),
                String.format(DATASOURCE_ERROR, AVAILABLE_USERS));
        dataDrivenDataSource(INPUT_DATASOURCE, "NSCS_IPSEC_ON_WrongUserRole",
                context.dataSource(ADDED_NODES));
        final TestScenario scenario = dataDrivenScenario("Set Ipsec Activation Test Scenario Wrong User")
                .addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(ipsecCliFlows.changeIpsecBase("IPSEC ACTIVATION WRONG USER", SetupAndTeardownScenarioIpsecCli.IPSEC_ACTIVATE_WRONG_USER, IpsecCliTestSteps.FREE_IP))
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(ADDED_NODES),
                        dataSource(AVAILABLE_USERS).withFilter(predicate))
                .doParallel(vUser).build();
        startScenario(scenario);
    }

    @Test(enabled = true, priority = 4, groups = { "Functional", "NSS" })
    @TestSuite
    public void ipsecDeActivateNegativeTest() {
        final Predicate<DataRecord> predicate = PredicateUtil.nsuOper();
        Preconditions.checkArgument(!Iterables.isEmpty(Iterables.filter(context.dataSource(AVAILABLE_USERS), PredicateUtil.nsuOper())),
                String.format(DATASOURCE_ERROR, AVAILABLE_USERS));
        dataDrivenDataSource(INPUT_DATASOURCE, "NSCS_IPSEC_OFF_WrongUserRole",
                context.dataSource(ADDED_NODES));
        final TestScenario scenario = dataDrivenScenario("Set Ipsec Deactivation Test Scenario Wrong User")
                .addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(ipsecCliFlows.changeIpsecBase("IPSEC DEACTIVATION WRONG USER", SetupAndTeardownScenarioIpsecCli.IPSEC_DEACTIVATE_WRONG_USER, IpsecCliTestSteps.FREE_IP))
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(ADDED_NODES),
                        dataSource(AVAILABLE_USERS).withFilter(predicate))
                .doParallel(vUser).build();
        startScenario(scenario);
    }

}

