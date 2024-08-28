/*******************************************************************************
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
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.ADDED_NODES;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.AVAILABLE_USERS;

import javax.inject.Inject;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testng.ITestContext;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Optional;
import org.testng.annotations.Parameters;
import org.testng.annotations.Test;

import com.ericsson.cifwk.taf.TestContext;
import com.ericsson.cifwk.taf.annotations.TestSuite;
import com.ericsson.cifwk.taf.scenario.TestScenario;
import com.ericsson.cifwk.taf.scenario.TestScenarioRunner;
import com.ericsson.nms.security.nscs.predicate.PredicateUtil;
import com.ericsson.oss.testware.nodesecurity.flows.SyntaxFlowsGeneric;
import com.ericsson.oss.testware.nodesecurity.flows.TrustDistributeFlow;
import com.ericsson.oss.testware.nodesecurity.flows.TrustRemoveFlow;
import com.ericsson.oss.testware.nodesecurity.steps.SyntaxTestSteps;
import com.ericsson.oss.testware.nodesecurity.steps.TrustDistributeTestSteps;
import com.ericsson.oss.testware.nodesecurity.utils.TrustUtils;

@SuppressWarnings({"PMD.LawOfDemeter"})
public class TrustTestScenario extends ScenarioUtility {

    private static final Logger LOGGER = LoggerFactory.getLogger(TrustTestScenario.class);
    private static final String SINGLE_NODE_DATA_SOURCE = "singleNodeDataSource";

    @Inject
    private TestContext context;

    @Inject
    private TrustDistributeFlow trustDistributeFlow;
    @Inject
    private TrustRemoveFlow trustRemoveFlow;

    @Inject
    private SetupAndTeardownScenarioTrust setupAndTeardownScenarioTrust;

    @Inject
    private SyntaxFlowsGeneric syntaxFlowsGeneric;

    @BeforeClass(groups = { "Functional", "NSS", "RFA250", "ARNL", "ENM_EXTERNAL_TESTWARE" })
    @Parameters({ "agat" })
    public void beforeClass(final ITestContext suiteContext, @Optional final String agat) {
        SetupAndTeardownScenario.setAgat(agat);
        if (SetupAndTeardownScenario.isAgat()) {
            setupAndTeardownScenarioTrust.onBeforeSuite(suiteContext, SetupAndTeardownScenario.getAgat());
        }
        super.beforeClass();
    }

    @AfterClass(groups = { "Functional", "NSS", "RFA250", "ARNL", "ENM_EXTERNAL_TESTWARE" })
    public void afterClass() {
        if (SetupAndTeardownScenario.isAgat()) {
            setupAndTeardownScenarioTrust.onAfterSuite();
        }
    }

    @Test(enabled = true, priority = 1, groups = { "Functional", "NSS", "RFA250", "ARNL", "ENM_EXTERNAL_TESTWARE" })
    @TestSuite
    public void trustDistributeOAM_PositiveTest() {
        doParallelNodesBase(INPUT_DATASOURCE, "NSCS_TRUSTDISTR_CertType(OAM)_CorrectUserRole",
                context.dataSource(SetupAndTeardownScenarioTrust.TRUST_OAM_EXPMSG), context.dataSource(ADDED_NODES),
                availableUserFiltered(PredicateUtil.nsuAdm()));
        final TestScenario scenario = dataDrivenScenario("TRUST Distribute CertType(OAM) - Positive Scenario")
                .addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(utilityFlows.recursiveCheckSyncNodeStatusCmFm())
                .addFlow(trustDistributeFlow.trustDistrCertTypeBuilder())
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(ADDED_NODES).bindTo(AVAILABLE_USERS)
                        .bindTo(TrustDistributeTestSteps.DataSource.TRUST_DATASOURCE))
                .doParallel(vUser)
                .build();
        runScenario(scenario);
    }

    @Test(enabled = true, priority = 2, groups = { "Functional", "NSS", "RFA250", "ARNL", "ENM_EXTERNAL_TESTWARE" })
    @TestSuite
    public void trustDistributeIPSEC_PositiveTest() {
        doParallelNodesBase(INPUT_DATASOURCE, "NSCS_TRUSTDISTR_CertType(IPSEC)_CorrectUserRole",
                context.dataSource(SetupAndTeardownScenarioTrust.TRUST_IPSEC_EXPMSG), context.dataSource(ADDED_NODES),
                availableUserFiltered(PredicateUtil.nsuAdm()));
        final TestScenario scenario = dataDrivenScenario("TRUST Distribute CertType(IPSEC) - Positive Scenario")
                .addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(utilityFlows.recursiveCheckSyncNodeStatusCmFm())
                .addFlow(trustDistributeFlow.trustDistrCertTypeBuilder())
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(ADDED_NODES).bindTo(AVAILABLE_USERS)
                        .bindTo(TrustDistributeTestSteps.DataSource.TRUST_DATASOURCE))
                .doParallel(vUser)
                .build();
        runScenario(scenario);
    }

    /*  Trust Distribute/Remove Combined Scenarios
     *
     *  The following combined scenarios perform, for OAM and for IPSEC respectively:
     *
     *  1. trust distribute positive test (CaName = ENM_E-mail_CA, with correct user role)
     *
     *  2. trust remove negative tests - only if not (RFA250 or ARNL or ENM_EXTERNAL_TESTWARE)
     *     (This avoids to re-distribute the CA to perform the negative test,
     *      since the "secadm trust remove.." command is composed only if the CA to remove is installed on the node.)
     *
     *     2.1 trust remove wrong user test (CaName = ENM_E-mail_CA, with wrong user role)
     *
     *     2.2 trust remove with several invalid arguments
     *
     *  3. trust remove positive test (CaName = ENM_E-mail_CA, with correct user role)
     */

    @Test(enabled = true, priority = 3, groups = { "Functional", "NSS", "RFA250", "ARNL", "ENM_EXTERNAL_TESTWARE" })
    @TestSuite
    public void trustDistribute_RemoveOAM_CaName_Combined() {
        LOGGER.info("\n\n*** Entering in combined scenario TRUST Distribute/Remove certType(OAM) by CaName ***\n");
        trustDistributeOAM_CaName_PositiveTest();
        if (!SetupAndTeardownScenario.isRfa250()) {
            trustRemoveOAM_CaName_WrongUserRole();
            trustRemoveInvalidCT_NegativeTest();
            trustRemoveInvalidCA_NegativeTest();
            trustRemoveBad_SN_Format_NegativeTest();
            trustRemoveInvalid_SN_NegativeTest();
            trustRemoveNonExistentNode_NegativeTest();
        }
        trustRemoveOAM_CaName_PositiveTest();
        LOGGER.info("\n\n*** Finishing combined scenario TRUST Distribute/Remove certType(OAM) by CaName ***\n");
    }

    @Test(enabled = true, priority = 4, groups = { "Functional", "NSS", "RFA250", "ARNL", "ENM_EXTERNAL_TESTWARE" })
    @TestSuite
    public void trustDistribute_RemoveOAM_CaName_Combined_CbpoiNode() {
        LOGGER.info("\n\n*** Entering in combined scenario TRUST Distribute/Remove certType(OAM) by CaName ***\n");
        trustDistributeOAM_CaName_PositiveTest();
        trustRemoveOAM_CaName_PositiveTest();
        LOGGER.info("\n\n*** Finishing combined scenario TRUST Distribute/Remove certType(OAM) by CaName ***\n");
    }

    @Test(enabled = true, priority = 5, groups = { "Functional", "NSS", "RFA250", "ARNL", "ENM_EXTERNAL_TESTWARE" })
    @TestSuite
    public void trustDistribute_RemoveIPSEC_CaName_Combined() {
        LOGGER.info("\n\n*** Entering in combined scenario TRUST Distribute/Remove certType(IPSEC) by CaName ***\n");
        trustDistributeIPSEC_Caname_PositiveTest();
        if (!SetupAndTeardownScenario.isRfa250()) {
            trustRemoveIPSEC_CaName_WrongUserRole();
        }
        trustRemoveIPSEC_CaName_PositiveTest();
        LOGGER.info("\n\n*** Finishing combined scenario TRUST Distribute/Remove certType(IPSEC) by CaName ***\n");
    }

    @Test(enabled = true, priority = 6, groups = { "Functional", "NSS", "RFA250", "ARNL", "ENM_EXTERNAL_TESTWARE" })
    @TestSuite
    public void trustDistribute_RemoveOAM_IssuerDn_Combined() {
        LOGGER.info("\n\n*** Entering in combined scenario TRUST Distribute/Remove certType(OAM) by IssuerDn ***\n");
        trustDistributeOAM_CaName_PositiveTest();
        trustRemoveOAM_IssuerDN_PositiveTest();
        LOGGER.info("\n\n*** Finishing combined scenario TRUST Distribute/Remove certType(OAM) by IssuerDn ***\n");
    }

    @Test(enabled = true, priority = 7, groups = { "Functional", "NSS", "RFA250", "ARNL", "ENM_EXTERNAL_TESTWARE" })
    @TestSuite
    public void trustDistribute_RemoveIPSEC_IssuerDn_Combined() {
        LOGGER.info("\n\n*** Entering in combined scenario TRUST Distribute/Remove certType(IPSEC) by IssuerDn ***\n");
        trustDistributeIPSEC_Caname_PositiveTest();
        trustRemoveIPSEC_IssuerDn_PositiveTest();
        LOGGER.info("\n\n*** Finishing combined scenario TRUST Distribute/Remove certType(IPSEC) by IssuerDn ***\n");
    }

    /*  End Combined Scenarios */

    @Test(enabled = true, priority = 8, groups = { "Functional", "NSS", "RFA250", "ARNL", "ENM_EXTERNAL_TESTWARE" })
    @TestSuite
    public void trustRemoveOAM_IssuerDN_PositiveTest() {
        doParallelNodesBase(INPUT_DATASOURCE, "NSCS_TRUSTREMOVE_CertType(OAM)_Issuer-Dn_CorrectUserRole",
                context.dataSource(SetupAndTeardownScenarioTrust.TRUST_OAM_EXPMSG), context.dataSource(ADDED_NODES),
                availableUserFiltered(PredicateUtil.nsuAdm()));
        final TestScenario scenario = dataDrivenScenario("TRUST Remove CertType(OAM) IssuerDn - Positive Scenario")
                .addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(utilityFlows.recursiveCheckSyncNodeStatusCmFm())
                .addFlow(trustRemoveFlow.removeTrustIssuerDnListBuilder(false))
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(ADDED_NODES).bindTo(AVAILABLE_USERS)
                        .bindTo(TrustDistributeTestSteps.DataSource.TRUST_DATASOURCE))
                .doParallel(vUser)
                .build();
        runScenario(scenario);
    }

    @Test(enabled = true, priority = 9, groups = { "Functional", "NSS", "RFA250", "ARNL", "ENM_EXTERNAL_TESTWARE" })
    @TestSuite
    public void trustRemoveIPSEC_IssuerDn_PositiveTest() {
        doParallelNodesBase(INPUT_DATASOURCE, "NSCS_TRUSTREMOVE_CertType(IPSEC)_Issuer-Dn_CorrectUserRole",
                context.dataSource(SetupAndTeardownScenarioTrust.TRUST_IPSEC_EXPMSG), context.dataSource(ADDED_NODES),
                availableUserFiltered(PredicateUtil.nsuAdm()));
        final TestScenario scenario = dataDrivenScenario("TRUST Remove CertType(IPSEC) IssuerDn - Positive Scenario")
                .addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(utilityFlows.recursiveCheckSyncNodeStatusCmFm())
                .addFlow(trustRemoveFlow.removeTrustIssuerDnListBuilder(false))
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(ADDED_NODES).bindTo(AVAILABLE_USERS)
                        .bindTo(TrustDistributeTestSteps.DataSource.TRUST_DATASOURCE))
                .doParallel(vUser)
                .build();
        runScenario(scenario);
    }

    @Test(enabled = true, priority = 10, groups = { "Functional", "NSS", "RFA250", "ARNL", "ENM_EXTERNAL_TESTWARE" })
    @TestSuite
    public void trustDistributeOAM_CaName_PositiveTest() {
        doParallelNodesBase(INPUT_DATASOURCE, "NSCS_TRUSTDISTR_CertType(OAM)_CaName_CorrectUserRole",
                context.dataSource(SetupAndTeardownScenarioTrust.TRUST_OAM_EXPMSG), context.dataSource(ADDED_NODES),
                availableUserFiltered(PredicateUtil.nsuAdm()));
        final TestScenario scenario = dataDrivenScenario("TRUST Distribute CertType(OAM) CaName - Positive Scenario")
                .addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(utilityFlows.recursiveCheckSyncNodeStatusCmFm())
                .addFlow(trustDistributeFlow.trustDistrCaNameBuilder(false))
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(ADDED_NODES).bindTo(AVAILABLE_USERS)
                        .bindTo(TrustDistributeTestSteps.DataSource.TRUST_DATASOURCE))
                .doParallel(vUser)
                .build();
        runScenario(scenario);
    }

    @Test(enabled = true, priority = 11, groups = { "Functional", "NSS", "RFA250", "ARNL", "ENM_EXTERNAL_TESTWARE" })
    @TestSuite
    public void trustDistributeIPSEC_Caname_PositiveTest() {
        doParallelNodesBase(INPUT_DATASOURCE, "NSCS_TRUSTDISTR_CertType(IPSEC)_CaName_CorrectUserRole",
                context.dataSource(SetupAndTeardownScenarioTrust.TRUST_IPSEC_EXPMSG), context.dataSource(ADDED_NODES),
                availableUserFiltered(PredicateUtil.nsuAdm()));
        final TestScenario scenario = dataDrivenScenario("TRUST Distribute CertType(IPSEC) CaName - Positive Scenario")
                .addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(utilityFlows.recursiveCheckSyncNodeStatusCmFm())
                .addFlow(trustDistributeFlow.trustDistrCaNameBuilder(false))
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(ADDED_NODES).bindTo(AVAILABLE_USERS)
                        .bindTo(TrustDistributeTestSteps.DataSource.TRUST_DATASOURCE))
                .doParallel(vUser)
                .build();
        runScenario(scenario);
    }

    @Test(enabled = true, priority = 12, groups = { "Functional", "NSS", "RFA250", "ARNL", "ENM_EXTERNAL_TESTWARE" })
    @TestSuite
    public void trustRemoveOAM_CaName_PositiveTest() {
        doParallelNodesBase(INPUT_DATASOURCE, "NSCS_TRUSTREMOVE_CertType(OAM)_CaName_CorrectUserRole",
                context.dataSource(SetupAndTeardownScenarioTrust.TRUST_OAM_EXPMSG), context.dataSource(ADDED_NODES),
                availableUserFiltered(PredicateUtil.nsuAdm()));
        final TestScenario scenario = dataDrivenScenario("TRUST Remove CertType(OAM) CaName - Positive Scenario")
                .addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(utilityFlows.recursiveCheckSyncNodeStatusCmFm())
                .addFlow(trustRemoveFlow.removeTrustCaNameListBuilder(false))
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(ADDED_NODES).bindTo(AVAILABLE_USERS)
                        .bindTo(TrustDistributeTestSteps.DataSource.TRUST_DATASOURCE))
                .doParallel(vUser)
                .build();
        runScenario(scenario);
    }

    @Test(enabled = true, priority = 13, groups = { "Functional", "NSS", "RFA250", "ARNL", "ENM_EXTERNAL_TESTWARE" })
    @TestSuite
    public void trustRemoveIPSEC_CaName_PositiveTest() {
        doParallelNodesBase(INPUT_DATASOURCE, "NSCS_TRUSTREMOVE_CertType(IPSEC)_CaName_CorrectUserRole",
                context.dataSource(SetupAndTeardownScenarioTrust.TRUST_IPSEC_EXPMSG), context.dataSource(ADDED_NODES),
                availableUserFiltered(PredicateUtil.nsuAdm()));
        final TestScenario scenario = dataDrivenScenario("TRUST Remove CertType(IPSEC) CaName - Positive Scenario")
                .addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(utilityFlows.recursiveCheckSyncNodeStatusCmFm())
                .addFlow(trustRemoveFlow.removeTrustCaNameListBuilder(false))
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(ADDED_NODES).bindTo(AVAILABLE_USERS)
                        .bindTo(TrustDistributeTestSteps.DataSource.TRUST_DATASOURCE))
                .doParallel(vUser)
                .build();
        runScenario(scenario);
    }

    /*      */
    /* RBAC */
    /*      */
    /* Negative Scenario with wrong user roles     */

    @Test(enabled = true, priority = 14, groups = { "Functional", "NSS" })
    @TestSuite
    public void trustDistributeOAM_WrongUserRole() {
        doParallelNodesBase(INPUT_DATASOURCE, "NSCS_TRUSTDISTR_CertType(OAM)_WrongUserRole",
                context.dataSource(SetupAndTeardownScenarioTrust.TRUST_OAM_EXPMSG), context.dataSource(ADDED_NODES),
                availableUserFiltered(PredicateUtil.nsuTrustOperatorRole()));
        final TestScenario scenario = dataDrivenScenario("TRUST Distribute CertType(OAM) - Wrong User Role")
                .addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(utilityFlows.verifySyncNodes())
                .addFlow(trustDistributeFlow.trustDistrCertType_negative())
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(ADDED_NODES).bindTo(AVAILABLE_USERS)
                        .bindTo(TrustDistributeTestSteps.DataSource.TRUST_DATASOURCE))
                .doParallel(vUser).build();
        runScenario(scenario);
    }

    private void runScenario(final TestScenario scenario) {
        final TestScenarioRunner runner = SetupAndTearDownUtil.getScenarioRunner();
        runner.start(scenario);
    }

    @Test(enabled = true, priority = 15, groups = { "Functional", "NSS" })
    @TestSuite
    public void trustDistributeIPSEC_WrongUserRole() {
        doParallelNodesBase(INPUT_DATASOURCE, "NSCS_TRUSTDISTR_CertType(IPSEC)_WrongUserRole",
                context.dataSource(SetupAndTeardownScenarioTrust.TRUST_IPSEC_EXPMSG), context.dataSource(ADDED_NODES),
                availableUserFiltered(PredicateUtil.nsuTrustOperatorRole()));
        final TestScenario scenario = dataDrivenScenario("TRUST Distribute CertType(IPSEC) - Wrong User Role")
                .addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(utilityFlows.verifySyncNodes())
                .addFlow(trustDistributeFlow.trustDistrCertType_negative())
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(ADDED_NODES).bindTo(AVAILABLE_USERS)
                        .bindTo(TrustDistributeTestSteps.DataSource.TRUST_DATASOURCE))
                .doParallel(vUser).build();
        runScenario(scenario);
    }

    @Test(enabled = true, priority = 16, groups = { "Functional", "NSS" })
    @TestSuite
    public void trustDistributeOAM_CaName_WrongUserRole() {
        doParallelNodesBase(INPUT_DATASOURCE, "NSCS_TRUSTDISTR_CertType(OAM)_CaName_WrongUserRole",
                context.dataSource(SetupAndTeardownScenarioTrust.TRUST_OAM_EXPMSG), context.dataSource(ADDED_NODES),
                availableUserFiltered(PredicateUtil.nsuTrustOperatorRole()));
        final TestScenario scenario = dataDrivenScenario("TRUST Distribute CertType(OAM) CaName - Wrong User Role")
                .addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(utilityFlows.verifySyncNodes())
                .addFlow(trustDistributeFlow.trustDistrCertTypeCaName_negative())
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(ADDED_NODES).bindTo(AVAILABLE_USERS)
                        .bindTo(TrustDistributeTestSteps.DataSource.TRUST_DATASOURCE))
                .doParallel(vUser).build();
        runScenario(scenario);
    }

    @Test(enabled = true, priority = 17, groups = { "Functional", "NSS" })
    @TestSuite
    public void trustDistributeIPSEC_Caname_WrongUserRole() {
        doParallelNodesBase(INPUT_DATASOURCE, "NSCS_TRUSTDISTR_CertType(IPSEC)_CaName_WrongUserRole",
                context.dataSource(SetupAndTeardownScenarioTrust.TRUST_IPSEC_EXPMSG), context.dataSource(ADDED_NODES),
                availableUserFiltered(PredicateUtil.nsuTrustOperatorRole()));
        final TestScenario scenario = dataDrivenScenario("TRUST Distribute CertType(IPSEC) CaName - Wrong User Role")
                .addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(utilityFlows.verifySyncNodes())
                .addFlow(trustDistributeFlow.trustDistrCertTypeCaName_negative())
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(ADDED_NODES).bindTo(AVAILABLE_USERS)
                        .bindTo(TrustDistributeTestSteps.DataSource.TRUST_DATASOURCE))
                .doParallel(vUser).build();
        runScenario(scenario);
    }

    @Test(enabled = true, priority = 18, groups = { "Functional", "NSS" })
    @TestSuite
    public void trustRemoveOAM_CaName_WrongUserRole() {
        doParallelNodesBase(INPUT_DATASOURCE, "NSCS_TRUSTREMOVE_CertType(OAM)_CaName_WrongUserRole",
                context.dataSource(SetupAndTeardownScenarioTrust.TRUST_OAM_EXPMSG), context.dataSource(ADDED_NODES),
                availableUserFiltered(PredicateUtil.nsuTrustOperatorRole()));
        final TestScenario scenario = dataDrivenScenario("TRUST Remove CertType(OAM) CaName - Wrong User Role")
                .addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(utilityFlows.verifySyncNodes())
                .addFlow(trustRemoveFlow.removeTrustCaNameList_negative(TrustUtils.TrustRemoveMode.WRONG_USER_ROLE))
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(ADDED_NODES).bindTo(AVAILABLE_USERS)
                        .bindTo(TrustDistributeTestSteps.DataSource.TRUST_DATASOURCE))
                .doParallel(vUser).build();
        runScenario(scenario);
    }

    @Test(enabled = true, priority = 19, groups = { "Functional", "NSS" })
    @TestSuite
    public void trustRemoveIPSEC_CaName_WrongUserRole() {
        doParallelNodesBase(INPUT_DATASOURCE, "NSCS_TRUSTREMOVE_CertType(IPSEC)_CaName_WrongUserRole",
                context.dataSource(SetupAndTeardownScenarioTrust.TRUST_IPSEC_EXPMSG), context.dataSource(ADDED_NODES),
                availableUserFiltered(PredicateUtil.nsuTrustOperatorRole()));
        final TestScenario scenario = dataDrivenScenario("TRUST Remove CertType(IPSEC) - Wrong User Role")
                .addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(utilityFlows.verifySyncNodes())
                .addFlow(trustRemoveFlow.removeTrustCaNameList_negative(TrustUtils.TrustRemoveMode.WRONG_USER_ROLE))
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(ADDED_NODES).bindTo(AVAILABLE_USERS)
                        .bindTo(TrustDistributeTestSteps.DataSource.TRUST_DATASOURCE))
                .doParallel(vUser).build();
        runScenario(scenario);
    }


    /*      */
    /* Trust Distribute/Remove Negative Scenarios  */
    /* invalid arguments     */
    /* Syntax ERRORS         */

    @Test(enabled = true, priority = 20, groups = { "Functional", "NSS" })
    @TestSuite
    public void trustDistributeInvalidCT_NegativeTest() {
        singlenode(SINGLE_NODE_DATA_SOURCE, context.dataSource(ADDED_NODES));
        doParallelNodesBase(INPUT_DATASOURCE, "NSCS_TRUSTDISTR_NEGATIVE_TEST_INVALID_CT",
                context.dataSource(SetupAndTeardownScenarioTrust.TRUST_DISTRIBUTE_INVALID_CT), context.dataSource(SINGLE_NODE_DATA_SOURCE),
                availableUserFiltered(PredicateUtil.nsuAdm()));
        final TestScenario scenario = dataDrivenScenario("TRUST Distribute with invalid CT - Negative Scenario")
                .addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(utilityFlows.verifySyncNodes())
                .addFlow(trustDistributeFlow.trustDistrInvalidCertType_negative())
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(ADDED_NODES).bindTo(AVAILABLE_USERS)
                        .bindTo(TrustDistributeTestSteps.DataSource.TRUST_DATASOURCE))
                .doParallel(vUser).build();
        runScenario(scenario);
    }

    @Test(enabled = true, priority = 21, groups = { "Functional", "NSS" })
    @TestSuite
    public void trustDistributeInvalidCA_NegativeTest() {
        singlenode(SINGLE_NODE_DATA_SOURCE, context.dataSource(ADDED_NODES));
        doParallelNodesBase(INPUT_DATASOURCE, "NSCS_TRUSTDISTR_NEGATIVE_TEST_INVALID_CA",
                context.dataSource(SetupAndTeardownScenarioTrust.TRUST_DISTRIBUTE_INVALID_CA), context.dataSource(SINGLE_NODE_DATA_SOURCE),
                availableUserFiltered(PredicateUtil.nsuAdm()));
        final TestScenario scenario = dataDrivenScenario("TRUST Distribute with invalid CA - Negative Scenario")
                .addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(utilityFlows.verifySyncNodes())
                .addFlow(trustDistributeFlow.trustDistrInvalidCA_negative())
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(ADDED_NODES).bindTo(AVAILABLE_USERS)
                        .bindTo(TrustDistributeTestSteps.DataSource.TRUST_DATASOURCE))
                .doParallel(vUser).build();
        runScenario(scenario);
    }

    @Test(enabled = true, priority = 22, groups = { "Functional", "NSS" })
    @TestSuite
    public void trustDistributeNonExistentNode() {
        doParallelNodesBase(INPUT_DATASOURCE, "NSCS_TRUSTDISTR_NEGATIVE_NOT_EXISTENT_NODE",
                context.dataSource(SetupAndTeardownScenarioTrust.TRUST_OAM),
                context.dataSource(SetupAndTeardownScenarioTrust.TRUST_NODES_TO_ADD_NOT_EXISTENT_NODE),
                availableUserFiltered(PredicateUtil.nscsAdm()));
        final TestScenario scenario = dataDrivenScenario("TRUST Distribute on non Existent node - Negative Scenario")
                .addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(trustDistributeFlow.trustDistrNonExistentNode())
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(ADDED_NODES).bindTo(AVAILABLE_USERS)
                        .bindTo(TrustDistributeTestSteps.DataSource.TRUST_DATASOURCE))
                .doParallel(vUser).build();
        runScenario(scenario);
    }

    @Test(enabled = true, priority = 23, groups = { "Functional", "NSS" })
    @TestSuite
    public void trustRemoveInvalidCT_NegativeTest() {
        singlenode(SINGLE_NODE_DATA_SOURCE, context.dataSource(ADDED_NODES));
        doParallelNodesBase(INPUT_DATASOURCE, "NSCS_TRUSTREMOVE_NEGATIVE_TEST_INVALID_CT",
                context.dataSource(SetupAndTeardownScenarioTrust.TRUST_REMOVE_INVALID_CT), context.dataSource(SINGLE_NODE_DATA_SOURCE),
                availableUserFiltered(PredicateUtil.nscsAdm()));
        final TestScenario scenario = dataDrivenScenario("TRUST Remove with Invalid CT - Negative Scenario")
                .addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(utilityFlows.verifySyncNodes())
                .addFlow(trustRemoveFlow.removeTrustCaNameList_negative(TrustUtils.TrustRemoveMode.INVALID_ARGUMENT_CT))
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(ADDED_NODES).bindTo(AVAILABLE_USERS)
                        .bindTo(TrustDistributeTestSteps.DataSource.TRUST_DATASOURCE))
                .doParallel(vUser).build();
        runScenario(scenario);
    }

    @Test(enabled = true, priority = 24, groups = { "Functional", "NSS" })
    @TestSuite
    public void trustRemoveInvalidCA_NegativeTest() {
        singlenode(SINGLE_NODE_DATA_SOURCE, context.dataSource(ADDED_NODES));
        doParallelNodesBase(INPUT_DATASOURCE, "NSCS_TRUSTREMOVE_NEGATIVE_TEST_INVALID_CA",
                context.dataSource(SetupAndTeardownScenarioTrust.TRUST_REMOVE_INVALID_CA), context.dataSource(SINGLE_NODE_DATA_SOURCE),
                availableUserFiltered(PredicateUtil.nscsAdm()));
        final TestScenario scenario = dataDrivenScenario("TRUST Remove with Invalid CA - Negative Scenario")
                .addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(utilityFlows.verifySyncNodes())
                .addFlow(trustRemoveFlow.removeTrustCaNameList_negative(TrustUtils.TrustRemoveMode.INVALID_ARGUMENT_CA))
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(ADDED_NODES).bindTo(AVAILABLE_USERS)
                        .bindTo(TrustDistributeTestSteps.DataSource.TRUST_DATASOURCE))
                .doParallel(vUser).build();
        runScenario(scenario);
    }


    /*      */
    /* LAAD */
    /*      */
    /* Positive Scenarios with correct user roles     */

    @Test(enabled = true, priority = 25, groups = { "Functional", "NSS" })
    @TestSuite
    public void trustDistribute_RemoveLAAD_CaName_Combined() throws InterruptedException {
        LOGGER.info("\n\n*** Entering in combined scenario TRUST Distribute/Remove trustCategory(LAAD) by CaName ***\n");
        trustDistributeLAAD_CaName_PositiveTest();
        trustRemoveLAAD_CaName_PositiveTest();
        LOGGER.info("\n\n*** Finishing combined scenario TRUST Distribute/Remove trustCategory(LAAD) by CaName ***\n");
    }

    @Test(enabled = true, priority = 26, groups = { "Functional", "NSS" })
    @TestSuite
    public void trustDistribute_RemoveLAAD_IssuerDn_Combined() throws InterruptedException {
        LOGGER.info("\n\n*** Entering in combined scenario TRUST Distribute/Remove trustCategory(LAAD) by IssuerDn ***\n");
        trustDistributeLAAD_CaName_PositiveTest();
        trustRemoveLAAD_IssuerDN_PositiveTest();
        LOGGER.info("\n\n*** Finishing combined scenario TRUST Distribute/Remove trustCategory(LAAD) by IssuerDn ***\n");
    }

    @Test(enabled = true, priority = 27, groups = { "Functional", "NSS" })
    @TestSuite
    public void trustDistributeLAAD_PositiveTest() {
        doParallelNodesBase(INPUT_DATASOURCE, "MR57916_Trust_Distribution_LAAD_on_Netsim_node_Positive_Scenarios",
                context.dataSource(SetupAndTeardownScenarioTrust.TRUST_LAAD), context.dataSource(ADDED_NODES),
                availableUserFiltered(PredicateUtil.nsuAdm()));
        final TestScenario scenario = dataDrivenScenario("TRUST Distribute trustCategory(LAAD) - Positive Scenario")
                .addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(utilityFlows.verifySyncNodes())
                .addFlow(trustDistributeFlow.trustDistrTrustCategoryBuilder())
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(ADDED_NODES).bindTo(AVAILABLE_USERS)
                        .bindTo(TrustDistributeTestSteps.DataSource.TRUST_DATASOURCE))
                .doParallel(vUser)
                .build();
        runScenario(scenario);
    }

    @Test(enabled = true, priority = 28, groups = { "Functional", "NSS" })
    @TestSuite
    private void trustRemoveLAAD_CaName_PositiveTest() {
        doParallelNodesBase(INPUT_DATASOURCE, "MR57916_Trust_Removal_LAAD_on_Netsim_node",
                context.dataSource(SetupAndTeardownScenarioTrust.TRUST_LAAD), context.dataSource(ADDED_NODES),
                availableUserFiltered(PredicateUtil.nsuAdm()));
        final TestScenario scenario = dataDrivenScenario("TRUST Remove trustCategory(LAAD) CaName - Positive Scenario")
                .addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(utilityFlows.verifySyncNodes())
                .addFlow(trustRemoveFlow.removeTrustCategoryCaNameListBuilder())
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(ADDED_NODES).bindTo(AVAILABLE_USERS)
                        .bindTo(TrustDistributeTestSteps.DataSource.TRUST_DATASOURCE))
                .doParallel(vUser)
                .build();
        runScenario(scenario);
    }

    @Test(enabled = true, priority = 29, groups = { "Functional", "NSS" })
    @TestSuite
    public void trustDistributeLAAD_CaName_PositiveTest() {
        doParallelNodesBase(INPUT_DATASOURCE, "MR57916_Trust_Distribution_LAAD_on_Netsim_node_Positive_Scenarios",
                context.dataSource(SetupAndTeardownScenarioTrust.TRUST_LAAD), context.dataSource(ADDED_NODES),
                availableUserFiltered(PredicateUtil.nsuAdm()));
        final TestScenario scenario = dataDrivenScenario("TRUST Distribute trustCategory(LAAD) CaName - Positive Scenario")
                .addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(utilityFlows.verifySyncNodes())
                .addFlow(trustDistributeFlow.trustDistrTrustCategoryCaNameBuilder())
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(ADDED_NODES).bindTo(AVAILABLE_USERS)
                        .bindTo(TrustDistributeTestSteps.DataSource.TRUST_DATASOURCE))
                .doParallel(vUser)
                .build();
        runScenario(scenario);
    }

    @Test(enabled = true, priority = 30, groups = { "Functional", "NSS" })
    @TestSuite
    public void trustRemoveLAAD_IssuerDN_PositiveTest() {
        doParallelNodesBase(INPUT_DATASOURCE, "TRUST Remove trustCategory(LAAD) CaName - Positive Scenario",
                context.dataSource(SetupAndTeardownScenarioTrust.TRUST_LAAD), context.dataSource(ADDED_NODES),
                availableUserFiltered(PredicateUtil.nsuAdm()));
        final TestScenario scenario = dataDrivenScenario("TRUST Remove trustCategory(LAAD) IssuerDn - Positive Scenario")
                .addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(utilityFlows.verifySyncNodes())
                .addFlow(trustRemoveFlow.removeTrustCategoryIssuerDnListBuilder())
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(ADDED_NODES).bindTo(AVAILABLE_USERS)
                        .bindTo(TrustDistributeTestSteps.DataSource.TRUST_DATASOURCE))
                .doParallel(vUser)
                .build();
        runScenario(scenario);
    }

    /*                          */
    /* Other Negative scenarios */
    /*                          */

    @Test(enabled = true, priority = 31, groups = { "Functional", "NSS" })
    @TestSuite
    public void trustRemoveBad_SN_Format_NegativeTest() {
        singlenode(SINGLE_NODE_DATA_SOURCE, context.dataSource(ADDED_NODES));
        doParallelNodesBase(INPUT_DATASOURCE, "NSCS_TRUSTREMOVE_NEGATIVE_TEST_BAD_SIGNAL_NUMBER_FORMAT",
                context.dataSource(SetupAndTeardownScenarioTrust.TRUST_REMOVE_INVALID_SN), context.dataSource(SINGLE_NODE_DATA_SOURCE),
                availableUserFiltered(PredicateUtil.nscsAdm()));
        final TestScenario scenario = dataDrivenScenario("TRUST Remove with Bad SN Format - Negative Scenario")
                .addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(utilityFlows.verifySyncNodes())
                .addFlow(trustRemoveFlow.removeTrustCaNameList_negative(TrustUtils.TrustRemoveMode.INVALID_ARGUMENT_SN_BAD_FORMAT))
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(ADDED_NODES).bindTo(AVAILABLE_USERS)
                        .bindTo(TrustDistributeTestSteps.DataSource.TRUST_DATASOURCE))
                .doParallel(vUser).build();
        runScenario(scenario);
    }

    @Test(enabled = true, priority = 32, groups = { "Functional", "NSS" })
    @TestSuite
    public void trustRemoveInvalid_SN_NegativeTest() {
        singlenode(SINGLE_NODE_DATA_SOURCE, context.dataSource(ADDED_NODES));
        doParallelNodesBase(INPUT_DATASOURCE, "NSCS_TRUSTREMOVE_NEGATIVE_TEST_INVALID_SIGNAL_NUMBER",
                context.dataSource(SetupAndTeardownScenarioTrust.TRUST_REMOVE_INVALID_SN), context.dataSource(SINGLE_NODE_DATA_SOURCE),
                availableUserFiltered(PredicateUtil.nscsAdm()));
        final TestScenario scenario = dataDrivenScenario("TRUST Remove with Invalid SN - Negative Scenario")
                .addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(utilityFlows.verifySyncNodes())
                .addFlow(trustRemoveFlow.removeTrustCaNameList_negative(TrustUtils.TrustRemoveMode.INVALID_ARGUMENT_SN))
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(ADDED_NODES).bindTo(AVAILABLE_USERS)
                        .bindTo(TrustDistributeTestSteps.DataSource.TRUST_DATASOURCE))
                .doParallel(1).build();
        runScenario(scenario);
    }

    @Test(enabled = true, priority = 33, groups = { "Functional", "NSS" })
    @TestSuite
    public void trustRemoveNonExistentNode_NegativeTest() {
        singlenode(SINGLE_NODE_DATA_SOURCE, context.dataSource(ADDED_NODES));
        doParallelNodesBase(INPUT_DATASOURCE, "NSCS_TRUSTREMOVE_NEGATIVE_NOT_EXISTENT_NODE",
                context.dataSource(SetupAndTeardownScenarioTrust.TRUST_REMOVE_NON_EXISTENT_NODE), context.dataSource(SINGLE_NODE_DATA_SOURCE),
                availableUserFiltered(PredicateUtil.nscsAdm()));
        final TestScenario scenario = dataDrivenScenario("TRUST Remove on non Existent node - Negative Scenario")
                .addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(utilityFlows.verifySyncNodes())
                .addFlow(trustRemoveFlow.removeTrustCaNameList_negative(TrustUtils.TrustRemoveMode.NON_EXISTENT_NETWORK_ELEMENT))
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(ADDED_NODES).bindTo(AVAILABLE_USERS)
                        .bindTo(TrustDistributeTestSteps.DataSource.TRUST_DATASOURCE))
                .doParallel(1).build();
        runScenario(scenario);
    }

    @Test(enabled = true, priority = 34, groups = { "Functional", "NSS" })
    @TestSuite
    public void trustNegativeSyntax() {
        singlenode(SINGLE_NODE_DATA_SOURCE, context.dataSource(ADDED_NODES));
        doParallelNodesBase(INPUT_DATASOURCE, "NSCS_TRUSTDISTR_REMOVE_NEGATIVE_TEST_SYNTAX_ERRORS",
                context.dataSource(SetupAndTeardownScenarioTrust.TRUST_SYNTAX_NEGATIVE), context.dataSource(SINGLE_NODE_DATA_SOURCE),
                availableUserFiltered(PredicateUtil.nscsAdm()));
        final TestScenario scenario = dataDrivenScenario("TRUST Distribute Remove with Syntax errors - Negative Scenario")
                .addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(syntaxFlowsGeneric.syntaxCommandBasic())
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(ADDED_NODES).bindTo(AVAILABLE_USERS)
                        .bindTo(SyntaxTestSteps.DataSource.SYNTAX_INFO_DATASOURCE))
                .doParallel(1).build();
        runScenario(scenario);
    }
}

