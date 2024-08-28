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

import static com.ericsson.cifwk.taf.scenario.TestScenarios.scenario;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.dataDrivenScenario;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.dataSource;
import static com.ericsson.nms.security.nscs.arnlrfa250scenario.SetupAndTeardownScenarioTrustedNtp.NTP_POSITIVE_XML_FILE_BASED_TEST;
import static com.ericsson.nms.security.nscs.predicate.PredicateUtil.userRoleSuiteNamePredicate;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.ADDED_NODES;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.AVAILABLE_USERS;
import static com.ericsson.oss.testware.nodesecurity.utils.TrustedNtpOperation.*;

import javax.inject.Inject;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.testng.annotations.AfterClass;

import com.ericsson.cifwk.taf.annotations.TestSuite;
import com.ericsson.cifwk.taf.datasource.DataRecord;
import com.ericsson.cifwk.taf.scenario.TestScenario;
import com.ericsson.cifwk.taf.scenario.TestScenarioRunner;
import com.google.common.base.Predicate;
import com.ericsson.oss.testware.nodesecurity.flows.TrustedNtpFlows;

@SuppressWarnings({ "PMD.LawOfDemeter" })
public class TrustedNtpTestScenario extends ScenarioUtility {

    private static final Logger LOGGER = LoggerFactory.getLogger(TrustedNtpTestScenario.class);
    private static final String TRUSTED_NTP_REMOVE_SINGLENODE = "TrustedNtpRemoveSingleNode";
    private static final String TRUSTED_NTP_ITSERVICES_SINGLENODE = "TrustedNtpItServicesNodeFdnCaseSingleNode";

    @Inject
    private TrustedNtpFlows trustedNtpFlows;

    @BeforeClass(groups = { "Functional", "NSS", "KGB" })
    public void beforeClass() {
        final Predicate<DataRecord> predicatePositive = userRoleSuiteNamePredicate("roles",
                SetupAndTeardownScenarioTrustedNtp.positiveCustomRolesList());
        final Predicate<DataRecord> predicateNegative = userRoleSuiteNamePredicate("roles",
                SetupAndTeardownScenarioTrustedNtp.negativeCustomRolesList());
        super.beforeClass(predicatePositive, predicateNegative);
        LOGGER.info("\n   BEFORE CLASS Trusted NTP - START \n");
        final TestScenario beforeClassScenario = scenario("Before Class Generate Keys").addFlow(loginLogoutRestFlows.loginDefaultUser())
                .addFlow(trustedNtpFlows.ntpOperationsInItservices("NtpKeyGeneration", NTP_KEYS_GENERATION_OPER))
                .addFlow(trustedNtpFlows.ntpOperationsInItservices("NtpKeyGenerationAdding", NTP_KEYS_GENERATION_ADDING_OPER))
                .addFlow(trustedNtpFlows.ntpOperationsInItservices("NtpListDefaultRestrictions", NTP_LIST_DEFAULT_RESTRICTIONS_OPER))
                .addFlow(trustedNtpFlows.ntpOperationsInItservices("NtpModifyRestrictions", NTP_MODIFY_RESTRICTIONS_OPER))
                .addFlow(trustedNtpFlows.ntpOperationsInItservices("NtpListDefaultRestrictions", NTP_LIST_DEFAULT_RESTRICTIONS_OPER))
                .addFlow(trustedNtpFlows.ntpOperationsInItservices("NtpServiceEnable", NTP_SERVICE_ENABLE_OPER))
                .addFlow(loginLogoutRestFlows.logout()).alwaysRun().build();
        final TestScenarioRunner runner = SetupAndTearDownUtil.getScenarioRunner();
        runner.start(beforeClassScenario);
        dumpDataSource();
        LOGGER.info("\n   BEFORE CLASS Trusted NTP - END \n");
    }

    @Test(enabled = true, priority = 1, groups = { "Functional", "NSS", "KGB" })
    @TestSuite
    public void ntpConfigurePositiveNodeListCase() {
        doParallelNodesBase(INPUT_DATASOURCE, "MR59788_Q2_Trusted_NTP_Server_Configure_Positive_Case", context.dataSource(ADDED_NODES),
                userListPositive);
        ScenarioUtility.debugScope(LOGGER, INPUT_DATASOURCE);
        final TestScenario scenario = dataDrivenScenario("NTP Configure Positive Scenario").addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(utilityFlows.verifySyncNodes())
                .addFlow(trustedNtpFlows.configureNtpServerOnNode("TrustedNtpConfigureUsecase", NTP_CONFIGURE_SECADM))
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(AVAILABLE_USERS).bindTo(ADDED_NODES)).doParallel(vUser).build();
        final TestScenarioRunner runner = SetupAndTearDownUtil.getScenarioRunner();
        runner.start(scenario);
    }

    @Test(enabled = true, priority = 2, groups = { "Functional", "NSS", "KGB" })
    @TestSuite
    public void ntpListPositiveNodeListCase() {
        doParallelNodesBase(INPUT_DATASOURCE, "MR59788_Q2_Trusted_NTP_Server_List_Positive_Case", context.dataSource(ADDED_NODES), userListPositive);
        ScenarioUtility.debugScope(LOGGER, INPUT_DATASOURCE);
        final TestScenario scenario = dataDrivenScenario("NTP LIST Positive Scenario").addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(utilityFlows.verifySyncNodes())
                .addFlow(trustedNtpFlows.listNtpServerDetailsOnNode("TrustedNtpListUsecase", NTP_LIST_SECADM))
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(AVAILABLE_USERS).bindTo(ADDED_NODES)).doParallel(vUser).build();
        final TestScenarioRunner runner = SetupAndTearDownUtil.getScenarioRunner();
        runner.start(scenario);
    }

    @Test(enabled = true, priority = 3, groups = { "Functional", "NSS", "KGB" })
    @TestSuite
    public void ntpRemovePositiveXmlFileCase() {
        fetchSingleNodeFromCsv(TRUSTED_NTP_REMOVE_SINGLENODE, context.dataSource(ADDED_NODES), 0);
        doParallelNodesBase(INPUT_DATASOURCE, "MR59788_Q2_Trusted_NTP_Server_Remove_Positive_Case",
                context.dataSource(NTP_POSITIVE_XML_FILE_BASED_TEST), context.dataSource(TRUSTED_NTP_REMOVE_SINGLENODE), userListPositive);
        ScenarioUtility.debugScope(LOGGER, INPUT_DATASOURCE);
        final TestScenario scenario = dataDrivenScenario("NtpRemoveXmlCase").addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(utilityFlows.verifySyncNodes())
                .addFlow(trustedNtpFlows.removeNtpConfigurationOnNode("TrustedNtpRemoveUsecase", NTP_REMOVE_SECADM, NTP_POSITIVE_XML_FILE_BASED_TEST))
                .addFlow(trustedNtpFlows.configureNtpServerOnNode("TrustedNtpConfigureUsecase", NTP_CONFIGURE_SECADM))
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(AVAILABLE_USERS).bindTo(ADDED_NODES)).doParallel(vUser).build();
        final TestScenarioRunner runner = SetupAndTearDownUtil.getScenarioRunner();
        runner.start(scenario);
    }

    @Test(enabled = true, priority = 4, groups = { "Functional", "NSS", "KGB" })
    @TestSuite
    public void ntpRenewKeys() {
        fetchSingleNodeFromCsv(TRUSTED_NTP_ITSERVICES_SINGLENODE, context.dataSource(ADDED_NODES), 0);
        doParallelNodesBase(INPUT_DATASOURCE, "MR59788_Q2_Renew_Keys_Positive_Cases_In_Physical", context.dataSource(TRUSTED_NTP_ITSERVICES_SINGLENODE), userListPositive);
        ScenarioUtility.debugScope(LOGGER, INPUT_DATASOURCE);
        final TestScenario scenario = dataDrivenScenario("NTP Renew Keys").addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(trustedNtpFlows.ntpOperationsInItservices("NtpRenewAllKeys", NTP_RENEW_ALL_KEYS_OPER))
                .addFlow(trustedNtpFlows.ntpOperationsInItservices("NtpRenewKeysWithNodeFdn", NTP_RENEW_NODEFDN_KEYS_OPER))
                .addFlow(trustedNtpFlows.ntpOperationsInItservices("NtpRenewKeysWithKeyID", NTP_RENEW_KEYID_KEYS_OPER))
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(AVAILABLE_USERS).bindTo(ADDED_NODES)).build();
        final TestScenarioRunner runner = SetupAndTearDownUtil.getScenarioRunner();
        runner.start(scenario);
    }

    @Test(enabled = true, priority = 5, groups = { "Functional", "NSS", "KGB" })
    @TestSuite
    public void ntpListAll() {
        fetchSingleNodeFromCsv(TRUSTED_NTP_ITSERVICES_SINGLENODE, context.dataSource(ADDED_NODES), 1);
        doParallelNodesBase(INPUT_DATASOURCE, "MR59788_Q2_List_NTP_Mappings_With_Nodes_Postive_Cases_In_Physical", context.dataSource(TRUSTED_NTP_ITSERVICES_SINGLENODE),
                userListPositive);
        ScenarioUtility.debugScope(LOGGER, INPUT_DATASOURCE);
        final TestScenario scenario = dataDrivenScenario("NTP List All Keys").addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(trustedNtpFlows.ntpOperationsInItservices("NtpListAll", NTP_LIST_ALL_KEYS_OPER))
                .addFlow(trustedNtpFlows.ntpOperationsInItservices("NtpListMapped", NTP_LIST_MAPPED_KEYS_OPER))
                .addFlow(trustedNtpFlows.ntpOperationsInItservices("NtpListKeyID", NTP_LIST_KEYIDS_OPER))
                .addFlow(trustedNtpFlows.ntpOperationsInItservices("NtpListNodeFDN", NTP_LIST_NODEFDNS_OPER)).addFlow(loginLogoutRestFlows.logoutBuilder())
                .alwaysRun().withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(AVAILABLE_USERS).bindTo(ADDED_NODES)).build();
        final TestScenarioRunner runner = SetupAndTearDownUtil.getScenarioRunner();
        runner.start(scenario);
    }

    @Test(enabled = true, priority = 6, groups = { "Functional", "NSS", "KGB" })
    @TestSuite
    public void ntpRemove() {
        fetchSingleNodeFromCsv(TRUSTED_NTP_ITSERVICES_SINGLENODE, context.dataSource(ADDED_NODES), 1);
        doParallelNodesBase(INPUT_DATASOURCE, "MR59788_Q2_Remove_KEY_Mappings_With_Nodes_Positive_Cases_In_Physical",
        context.dataSource(TRUSTED_NTP_ITSERVICES_SINGLENODE), userListPositive);
        ScenarioUtility.debugScope(LOGGER, INPUT_DATASOURCE);
        final TestScenario scenario = dataDrivenScenario("NTP Remove KeyMapping").addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(trustedNtpFlows.ntpOperationsInItservices("NtpRemoveNodeFDN", NTP_REMOVE_NODEFDN_KEYS_OPER))
                .addFlow(trustedNtpFlows.ntpOperationsInItservices("NtpRemoveKEYID", NTP_REMOVE_KEYID_KEYS_OPER))
                .addFlow(trustedNtpFlows.ntpOperationsInItservices("NtpRemove", NTP_REMOVE_ALL_KEYS_OPER))
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(AVAILABLE_USERS).bindTo(ADDED_NODES)).build();
        final TestScenarioRunner runner = SetupAndTearDownUtil.getScenarioRunner();
        runner.start(scenario);
    }

    @AfterClass(groups = { "Functional", "NSS", "KGB" })
    public void afterClass() {
        LOGGER.info("\n   AFTER CLASS Trusted NTP - START \n");
        dumpDataSource();
        LOGGER.info("\n   AFTER CLASS Trusted NTP - START \n");
        final TestScenario afterClassScenario = scenario("After Class Trusted Ntp Scenario").addFlow(loginLogoutRestFlows.loginDefaultUser())
                .addFlow(trustedNtpFlows.ntpOperationsInItservices("NtpRollback", NTP_ROLLBACK_OPER))
                .addFlow(trustedNtpFlows.ntpOperationsInItservices("NtpServiceDisable", NTP_SERVICE_DISABLE_OPER))
                .addFlow(loginLogoutRestFlows.logout()).alwaysRun().build();
        final TestScenarioRunner runner = SetupAndTearDownUtil.getScenarioRunner();
        runner.start(afterClassScenario);
    }
}
