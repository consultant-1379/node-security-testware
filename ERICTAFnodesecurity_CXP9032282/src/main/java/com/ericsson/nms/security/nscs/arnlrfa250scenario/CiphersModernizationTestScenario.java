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

import static com.ericsson.cifwk.taf.scenario.TestScenarios.dataDrivenScenario;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.dataSource;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.scenario;
import static com.ericsson.nms.security.nscs.predicate.PredicateUtil.userRoleSuiteNamePredicate;
import static com.ericsson.nms.security.nscs.arnlrfa250scenario.SetupAndTeardownScenarioCiphersModernization.SET_CIPHER_EC;
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
import com.ericsson.oss.testware.nodesecurity.flows.CiphersConfigurationFlows;
import com.ericsson.oss.testware.nodesecurity.flows.PkiCommandFlow;
import com.google.common.base.Predicate;

@SuppressWarnings({"PMD.LawOfDemeter"})
public class CiphersModernizationTestScenario extends ScenarioUtility {

    public static final String CIPHER_ALGORITHM = "ECDHE-RSA-AES256-GCM-SHA384";

    private static final Logger LOGGER = LoggerFactory.getLogger(CiphersModernizationTestScenario.class);

    @Inject
    CiphersConfigurationFlows ciphersConfigurationFlows;
    @Inject
    private PkiCommandFlow pkiCommandFlow;

    @BeforeClass(groups = { "Functional", "NSS", "RFA250", "ARNL" })
    public void beforeClass() {
        super.beforeClass();
        LOGGER.info("\n   BEFORE CLASS SETCIPHERS TEST - START \n");
        dumpDataSource();
        LOGGER.info("\n   BEFORE CLASS SETCIPHERS TEST - END \n");
        final Predicate<DataRecord> predicatePositive =  userRoleSuiteNamePredicate("roles",
                SetupAndTeardownScenarioCiphersModernization.positiveCustomRolesList());
        final Predicate<DataRecord> predicateNegative = userRoleSuiteNamePredicate("roles",
                SetupAndTeardownScenarioCiphersModernization.negativeCustomRolesList());
        super.beforeClass(predicatePositive, predicateNegative);

        final TestScenario beforeClassScenario = scenario("Before Class SetCiphers Scenario")
                .addFlow(loginLogoutRestFlows.loginDefaultUser())
                .addFlow(pkiCommandFlow.enableSha1())
                .addFlow(utilityFlows.verifySyncNodes(vUser))
                .addFlow(loginLogoutRestFlows.logout()).alwaysRun()
                .build();
        startScenario(beforeClassScenario);
    }

    @Test(enabled = true, priority = 1, groups = { "Functional", "NSS", "RFA250", "ARNL" })
    @TestSuite
    public void ciphersConfigTestScenario() {
        final Predicate<DataRecord> predicate = PredicateUtil.nsuAdm();
        dataDrivenDataSource(INPUT_DATASOURCE, "MR52338_Q2_TLS_Setciphers_onthe_nodes_positivecases",
                context.dataSource(ADDED_NODES));
        final TestScenario scenario = dataDrivenScenario("Ciphers Set Test Scenario")
                .addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(utilityFlows.verifySyncNodes())
                .addFlow(ciphersConfigurationFlows.ciphersConfigFlow("CIPHERS_CONFIG", NODES_TO_ADD, vUser))
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(ADDED_NODES),
                        dataSource(AVAILABLE_USERS).withFilter(predicate))
                .doParallel(vUser).build();
        startScenario(scenario);
    }

    @Test(enabled = true, priority = 2, groups = { "Functional", "NSS", "RFA250", "ARNL" })
    @TestSuite
    public void ciphersConfigSelectedCipherTestScenario() {
        final Predicate<DataRecord> predicate = PredicateUtil.nsuAdm();
        doParallelNodesBase(INPUT_DATASOURCE, "TORF-445094_TLS_Setciphers_onthe_nodes_positivecases",
                context.dataSource(SET_CIPHER_EC), context.dataSource(ADDED_NODES), userListPositive);
        final TestScenario scenario = dataDrivenScenario("Ciphers Set Test Scenario")
                .addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(utilityFlows.verifySyncNodes())
                .addFlow(ciphersConfigurationFlows.setSelectedCipherFlow("CIPHERS_CONFIG_SET", CIPHER_ALGORITHM))
                .addFlow(ciphersConfigurationFlows.getSelectedCipherFlow("CIPHERS_CONFIG_GET", CIPHER_ALGORITHM))
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(ADDED_NODES),
                        dataSource(AVAILABLE_USERS).withFilter(predicate))
                .doParallel(vUser).build();
        startScenario(scenario);
    }
}
