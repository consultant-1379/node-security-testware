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
import static com.ericsson.nms.security.nscs.arnlrfa250scenario.SetupAndTeardownScenarioTlsCiphersConfig.SET_CIPHER_RSA;
import static com.ericsson.nms.security.nscs.arnlrfa250scenario.SetupAndTeardownScenarioTlsCiphersConfig.SET_CIPHER_EC;
import static com.ericsson.oss.testware.nodesecurity.constant.AgnosticConstants.PUBLIC_KEY_ALGORITHM_EC;
import static com.ericsson.oss.testware.nodesecurity.constant.AgnosticConstants.PUBLIC_KEY_ALGORITHM_RSA;
import static com.ericsson.nms.security.nscs.predicate.PredicateUtil.userRoleSuiteNamePredicate;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.ADDED_NODES;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.AVAILABLE_USERS;

import javax.inject.Inject;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.ericsson.cifwk.taf.annotations.TestSuite;
import com.ericsson.cifwk.taf.datasource.DataRecord;
import com.ericsson.cifwk.taf.scenario.TestScenario;
import com.ericsson.cifwk.taf.scenario.TestScenarioRunner;
import com.ericsson.oss.testware.nodesecurity.flows.CertificateIssueFlows;
import com.ericsson.oss.testware.nodesecurity.flows.CiphersConfigurationFlows;
import com.ericsson.oss.testware.nodesecurity.flows.PkiCommandFlow;
import com.google.common.base.Predicate;

@SuppressWarnings({"PMD.LawOfDemeter"})
public class TlsCiphersConfigTestScenario extends ScenarioUtility {

    public static final String ALL = "ALL";
    public static final String EC_CIPHER = "ECDHE-ECDSA-AES256-GCM-SHA384";
    public static final String RSA_CIPHER = "ECDHE-RSA-AES256-GCM-SHA384";

	private static final Logger LOGGER = LoggerFactory.getLogger(TlsCiphersConfigTestScenario.class);

    @Inject
    private CiphersConfigurationFlows ciphersConfigurationFlows;
    @Inject
    private PkiCommandFlow pkiCommandFlow;
    @Inject
    private CertificateIssueFlows certificateIssueFlows;

    @BeforeClass(groups = { "Functional", "NSS" })
    public void beforeClass() {
        super.beforeClass();
        final Predicate<DataRecord> predicatePositive =  userRoleSuiteNamePredicate("roles",
                SetupAndTeardownScenarioTlsCiphersConfig.positiveCustomRolesList());
        final Predicate<DataRecord> predicateNegative = userRoleSuiteNamePredicate("roles",
                SetupAndTeardownScenarioTlsCiphersConfig.negativeCustomRolesList());
        super.beforeClass(predicatePositive, predicateNegative);
        LOGGER.info("\n   BEFORE CLASS set TLS ciphers - START \n");
        dumpDataSource();
        LOGGER.info("\n   BEFORE CLASS set TLS ciphers - END \n");
        final TestScenario beforeClassScenario = scenario("Before Class set TLS ciphers")
                .addFlow(loginLogoutRestFlows.loginDefaultUser())
                .addFlow(utilityFlows.verifySyncNodes(vUser))
                .addFlow(loginLogoutRestFlows.logout()).alwaysRun()
                .build();
        final TestScenarioRunner runner = SetupAndTearDownUtil.getScenarioRunner();
        runner.start(beforeClassScenario);
    }

    @Test(enabled = true, priority = 1, groups = { "Functional", "NSS" })
    @TestSuite
    public void ecCipherEnableTest() {
        doParallelNodesBase(INPUT_DATASOURCE, "NSCS_TLS_CIPHERSCONFIG_ENABLE_EC_CIPHER",
                context.dataSource(SET_CIPHER_EC), context.dataSource(ADDED_NODES), userListPositive);
        ScenarioUtility.debugScope(LOGGER, INPUT_DATASOURCE);
        final TestScenario scenario = ciphersEnableTest("Set EC cipher Positive Test Scenario", EC_CIPHER, PUBLIC_KEY_ALGORITHM_EC);
        final TestScenarioRunner runner = SetupAndTearDownUtil.getScenarioRunner();
        runner.start(scenario);
    }

    @Test(enabled = true, priority = 2, groups = { "Functional", "NSS" })
    @TestSuite
    public void rsaCipherEnableTest() {
        doParallelNodesBase(INPUT_DATASOURCE, "NSCS_TLS_CIPHERSCONFIG_ENABLE_RSA_CIPHER",
                context.dataSource(SET_CIPHER_RSA), context.dataSource(ADDED_NODES), userListPositive);
        ScenarioUtility.debugScope(LOGGER, INPUT_DATASOURCE);
        final TestScenario scenario = ciphersEnableTest("Set RSA cipher Positive Test Scenario", RSA_CIPHER, PUBLIC_KEY_ALGORITHM_RSA);
        final TestScenarioRunner runner = SetupAndTearDownUtil.getScenarioRunner();
        runner.start(scenario);
    }

    private TestScenario ciphersEnableTest(final String scenarioName, final String cipherName, final String publicKeyAlgoName) {
        return dataDrivenScenario(scenarioName)
                .addFlow(loginLogoutRestFlows.loginDefaultUser())
                .addFlow(utilityFlows.verifySyncNodes())
                .addFlow(ciphersConfigurationFlows.setSelectedCipherFlow("Set All Ciphers", ALL))
                .addFlow(ciphersConfigurationFlows.getSelectedCipherFlow("Get All Ciphers", ALL))
                .addFlow(certificateIssueFlows.certificateIssueVerify(false))
                .addFlow(utilityFlows.verifySyncNodes())
                .addFlow(ciphersConfigurationFlows.setSelectedCipherFlow("Set Specific Cipher", cipherName))
                .addFlow(ciphersConfigurationFlows.getSelectedCipherFlow("Get Specific Cipher", cipherName))
                .addFlow(certificateIssueFlows.certificateIssueVerify(false))
                .addFlow(pkiCommandFlow.getAndVerifyEECertificateFlow(publicKeyAlgoName))
                .addFlow(utilityFlows.verifySyncNodes())
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(AVAILABLE_USERS).bindTo(ADDED_NODES))
                .doParallel(vUser).build();
    }
}
