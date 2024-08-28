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

import static com.ericsson.cifwk.taf.datasource.TafDataSources.shared;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.dataDrivenScenario;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.dataSource;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.flow;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.scenario;
import static com.ericsson.nms.security.nscs.arnlrfa250scenario.SetupAndTeardownScenarioCrlCheck.ISSUE_IPSEC;
import static com.ericsson.nms.security.nscs.arnlrfa250scenario.SetupAndTeardownScenarioCrlCheck.ISSUE_OAM;
import static com.ericsson.nms.security.nscs.predicate.PredicateUtil.userRoleSuiteNamePredicate;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.ADDED_NODES;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.AVAILABLE_USERS;

import java.lang.reflect.Method;
import javax.inject.Inject;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testng.ITestContext;
import org.testng.annotations.AfterClass;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Optional;
import org.testng.annotations.Parameters;
import org.testng.annotations.Test;

import com.ericsson.cifwk.taf.annotations.TestSuite;
import com.ericsson.cifwk.taf.configuration.TafConfiguration;
import com.ericsson.cifwk.taf.configuration.TafConfigurationProvider;
import com.ericsson.cifwk.taf.datasource.DataRecord;
import com.ericsson.cifwk.taf.scenario.TestScenario;
import com.ericsson.cifwk.taf.scenario.api.TestStepFlowBuilder;
import com.ericsson.nms.security.nscs.predicate.PredicateUtil;
import com.ericsson.oss.testware.nodesecurity.flows.CertificateIssueFlows;
import com.ericsson.oss.testware.nodesecurity.flows.PkiCommandFlow;
import com.google.common.base.Predicate;
import com.google.common.collect.Iterables;

@SuppressWarnings({ "PMD.LawOfDemeter", "PMD.ExcessiveImports" })
public class CrlCheckTestScenario extends LogScenarioUtility {

    private static final Logger LOGGER = LoggerFactory.getLogger(CrlCheckTestScenario.class);

    private static final String TITLE_CRLCHECK_OAM_ENABLE_NODELIST = "Crl Check OAM Enable with node list";
    private static final String TITLE_CRLCHECK_OAM_DISABLE_NODELIST = "Crl Check OAM Disable with node list";
    private static final String TITLE_CRLCHECK_IPSEC_ENABLE_NODELIST = "Crl Check IPSEC Enable with node list";
    private static final String TITLE_CRLCHECK_IPSEC_DISABLE_NODELIST = "Crl Check IPSEC Disable with node list";
    private static final String TITLE_CRLCHECK_ALL_ENABLE_NODELIST = "Crl Check ALL Enable with node list";
    private static final String TITLE_CRLCHECK_ALL_DISABLE_NODELIST = "Crl Check ALL Disable with node list";
    private static final String TITLE_CRLCHECK_DOWNLOAD_NODELIST = "Crl Check Download with node list";

    private static final String LOG_SCENARIO_TAG = "CRLCHECK";

    private static final String BEFORECLASS_OAM = "BEFORECLASS_OAM";
    private static final String BEFORECLASS_IPSEC = "BEFORECLASS_IPSEC";
    private final TafConfiguration configuration = TafConfigurationProvider.provide();

    private int vUserLocalOam;
    private int vUserLocalIpsec;

    @Inject
    private PkiCommandFlow pkiCommandFlow;
    @Inject
    private CertificateIssueFlows certificateIssueFlows;
    @Inject
    private SetupAndTeardownScenarioCrlCheck setupAndTeardownScenarioCrlCheck;

    private String scenario = "";

    @BeforeClass(groups = { "Functional", "NSS", "RFA250", "ARNL", "ENM_EXTERNAL_TESTWARE", "KGB" })
    @Parameters({ "agat" })
    public void beforeClass(final ITestContext suiteContext, @Optional final String agat) {
        SetupAndTeardownScenario.setAgat(agat);
        final boolean isAgat = SetupAndTeardownScenario.isAgat();
        if (isAgat) {
            setupAndTeardownScenarioCrlCheck.onBeforeSuite(suiteContext, SetupAndTeardownScenario.getAgat());
        }
        vUserLocalOam = SetupAndTeardownScenarioCrlCheck.getNumUserOam();
        vUserLocalIpsec = SetupAndTeardownScenarioCrlCheck.getNumUserIpsec();
        context.addDataSource(BEFORECLASS_OAM, shared(SetupAndTeardownCertTypeCrlCheckScenario.getOamDataSource()));
        context.addDataSource(BEFORECLASS_IPSEC, shared(SetupAndTeardownCertTypeCrlCheckScenario.getIpsecDataSource()));
        final Predicate<DataRecord> predicatePositive = userRoleSuiteNamePredicate("roles",
                SetupAndTeardownScenarioCrlCheck.positiveCustomRolesList());
        final Predicate<DataRecord> predicateNegative = userRoleSuiteNamePredicate("roles",
                SetupAndTeardownScenarioCrlCheck.negativeCustomRolesList());
        super.beforeClass(predicatePositive, predicateNegative);
        LOGGER.info("\n   BEFORE CLASS CRLCHECK TEST - START \n");
        dumpDataSource();
        scenario = suiteContext.getName();
        enableLogManagement(LOG_ENABLE_SCRIPT_FILENAME, LOG_SCENARIO_TAG);
        if(SetupAndTeardownScenario.isRealNode()) {
            setUpRnlSyncNodesTimeOut();
        }
        LOGGER.info("\n   BEFORE CLASS CRLCHECK TEST - END \n");
        final TestScenario beforeClassScenario = scenario("Before Class CrlCheck Scenario")
                .addFlow(loginLogoutRestFlows.loginDefaultUser())
                .addFlow(pkiCommandFlow.enableSha1())
                .addFlow(loginLogoutRestFlows.logout()).alwaysRun()
                .addFlow(utilityFlows.login(PredicateUtil.nsuAdm(), vUser))
                .addFlow(utilityFlows.verifySyncNodes(vUser))
                .addFlow(!isAgat && !Iterables.isEmpty(SetupAndTeardownScenarioCrlCheck.getOamDataSource()) ?
                        certificateIssueFlows.certificateIssueVerify(SetupAndTeardownScenarioCrlCheck.ISSUE_OAM, false)
                                .withDataSources(dataSource(BEFORECLASS_OAM).bindTo(ADDED_NODES)).withVusers(vUserLocalOam) : flow("Empty"))
                .addFlow(!isAgat && !Iterables.isEmpty(SetupAndTeardownScenarioCrlCheck.getIpsecDataSource()) ?
                        certificateIssueFlows.certificateIssueVerify(SetupAndTeardownScenarioCrlCheck.ISSUE_IPSEC, false)
                                .withDataSources(dataSource(BEFORECLASS_IPSEC).bindTo(ADDED_NODES)).withVusers(vUserLocalIpsec) : flow("Empty"))
                .addFlow(utilityFlows.logout(PredicateUtil.nsuAdm(), vUser)).alwaysRun()
                .build();
        startScenario(beforeClassScenario);
    }

    @AfterClass(groups = { "Functional", "NSS", "RFA250", "ARNL", "ENM_EXTERNAL_TESTWARE" })
    public void afterClass() {
        disableLogManagement(LOG_DISABLE_SCRIPT_FILENAME, LOG_SCENARIO_TAG);
        if (SetupAndTeardownScenario.isAgat()) {
            setupAndTeardownScenarioCrlCheck.onAfterSuite();
        }
    }

    @BeforeMethod(groups = { "Functional", "NSS", "RFA250", "ARNL", "ENM_EXTERNAL_TESTWARE", "KGB" })
    public void beforeMethod(final Method method) {
        if (method.getName().startsWith("crlCheckUnsupportedNodeVersion")) {
            super.setupKgbOnly();
        }
        if (method.getName().equalsIgnoreCase("crlCheckDownloadPositiveTest")) {
            configuration.setProperty("taf.scenario.sync.point.timeout", "5");
        }
    }

    @AfterMethod(groups = { "Functional", "NSS", "RFA250", "ARNL", "ENM_EXTERNAL_TESTWARE", "KGB" })
    public void afterMethod(final Method method) {
        if (method.getName().startsWith("crlCheckUnsupportedNodeVersion")) {
            super.teardownKgbOnly();
        }
        if (method.getName().equalsIgnoreCase("crlCheckDownloadPositiveTest")) {
            configuration.setProperty("taf.scenario.sync.point.timeout", "30");
        }
    }

    @Test(enabled = true, priority = 1, groups = { "Functional", "NSS", "RFA250", "ARNL", "ENM_EXTERNAL_TESTWARE", "KGB" })
    @TestSuite
    public void crlCheckOAMEnablePositiveTest() {
        doParallelNodesBase(INPUT_DATASOURCE_OAM, "NSCS_CRLCHECK_OAM_ON_CorrectUserRole", TITLE_CRLCHECK_OAM_ENABLE_NODELIST,
                context.dataSource(ISSUE_OAM),
                SetupAndTeardownCertTypeCrlCheckScenario.getOamDataSource(), userListPositive);
        scenarioBaseCrlCheck("CRLCheck OAM Enable - Positive Scenario", INPUT_DATASOURCE_OAM, true,
                crLCheckFlows.enableCrlCheckFlow(false), vUserLocalOam);
    }

    @Test(enabled = true, priority = 2, groups = { "Functional", "NSS", "RFA250", "ARNL", "ENM_EXTERNAL_TESTWARE", "KGB" })
    @TestSuite
    public void crlCheckOAMDisablePositiveTest() {
        doParallelNodesBase(INPUT_DATASOURCE_OAM, "NSCS_CRLCHECK_OAM_OFF_CorrectUserRole", TITLE_CRLCHECK_OAM_DISABLE_NODELIST,
                context.dataSource(ISSUE_OAM),
                SetupAndTeardownCertTypeCrlCheckScenario.getOamDataSource(), userListPositive);
        scenarioBaseCrlCheck("CRLCheck OAM Disable - Positive Scenario", INPUT_DATASOURCE_OAM, true,
                crLCheckFlows.disableCrlCheckFlow(false), vUserLocalOam);
    }

    @Test(enabled = true, priority = 3, groups = { "Functional", "NSS", "RFA250", "ARNL", "ENM_EXTERNAL_TESTWARE", "KGB" })
    @TestSuite
    public void crlCheckIPSECEnablePositiveTest() {
        doParallelNodesBase(INPUT_DATASOURCE_IPSEC, "NSCS_CRLCHECK_IPSEC_ON_CorrectUserRole", TITLE_CRLCHECK_IPSEC_ENABLE_NODELIST,
                context.dataSource(ISSUE_IPSEC),
                SetupAndTeardownCertTypeCrlCheckScenario.getIpsecDataSource(), userListPositive);
        scenarioBaseCrlCheck("CRLCheck IPSEC Enable - Positive Scenario", INPUT_DATASOURCE_IPSEC, true,
                crLCheckFlows.enableCrlCheckFlow(false), vUserLocalIpsec);
    }

    @Test(enabled = true, priority = 4, groups = { "Functional", "NSS", "RFA250", "ARNL", "ENM_EXTERNAL_TESTWARE", "KGB" })
    @TestSuite
    public void crlCheckIPSECDisablePositiveTest() {
        doParallelNodesBase(INPUT_DATASOURCE_IPSEC, "NSCS_CRLCHECK_IPSEC_OFF_CorrectUserRole", TITLE_CRLCHECK_IPSEC_DISABLE_NODELIST,
                context.dataSource(ISSUE_IPSEC),
                SetupAndTeardownCertTypeCrlCheckScenario.getIpsecDataSource(), userListPositive);
        scenarioBaseCrlCheck("CRLCheck IPSEC Disable - Positive Scenario", INPUT_DATASOURCE_IPSEC, true,
                crLCheckFlows.disableCrlCheckFlow(false), vUserLocalIpsec);
    }

    private void scenarioBaseAll(final String scenarioName, final boolean isCorrectUser, final TestStepFlowBuilder flowName, final int vUsers) {
        final TestScenario scenario = dataDrivenScenario(scenarioName)
                .addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(isCorrectUser ? utilityFlows.verifySyncNodes() : flow("").build())
                .addFlow(flowName)
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(AVAILABLE_USERS).bindTo(ADDED_NODES))
                .doParallel(vUsers).build();
        startScenario(scenario);
    }

    @Test(enabled = true, priority = 5, groups = { "Functional", "NSS", "RFA250", "ARNL", "ENM_EXTERNAL_TESTWARE", "KGB" })
    @TestSuite
    public void crlCheckALLEnablePositiveTest() {
        LOGGER.info("Skipping crlCheckALLEnablePositiveTest for RNC and VDU nodeType.");
        final Iterable<DataRecord> addedNodeList = Iterables.filter(context.dataSource(ADDED_NODES), PredicateUtil.isCRLNonApplicableNodes);
        if (!Iterables.isEmpty(addedNodeList)) {
            doParallelNodesBase(INPUT_DATASOURCE, "NSCS_CRLCHECK_ALL_ON_CorrectUserRole", TITLE_CRLCHECK_ALL_ENABLE_NODELIST,
                    context.dataSource(SetupAndTeardownScenarioCrlCheck.ISSUE_ALL),
                    addedNodeList, userListPositive);
            scenarioBaseAll("CRLCheck ALL Enable - Positive Scenario", true,
                    crLCheckFlows.enableCrlCheckAllFlow(false), vUser);
        } else {
            LOGGER.info("InputDataSource did not produce any records for crlCheckALLEnablePositiveTest. Skipping the Testcase.");
            return;
        }
    }

    @Test(enabled = true, priority = 6, groups = { "Functional", "NSS", "RFA250", "ARNL", "ENM_EXTERNAL_TESTWARE", "KGB" })
    @TestSuite
    public void crlCheckALLDisablePositiveTest() {
        LOGGER.info("Skipping crlCheckALLDisablePositiveTest for RNC and VDU nodeType.");
        final Iterable<DataRecord> addedNodeList = Iterables.filter(context.dataSource(ADDED_NODES), PredicateUtil.isCRLNonApplicableNodes);
        if (!Iterables.isEmpty(addedNodeList)) {
            doParallelNodesBase(INPUT_DATASOURCE, "NSCS_CRLCHECK_ALL_OFF_CorrectUserRole", TITLE_CRLCHECK_ALL_DISABLE_NODELIST,
                    context.dataSource(SetupAndTeardownScenarioCrlCheck.ISSUE_ALL),
                    addedNodeList, userListPositive);
            scenarioBaseAll("CRLCheck ALL Disable - Positive Scenario", true,
                    crLCheckFlows.disableCrlCheckAllFlow(false), vUser);
        } else {
            LOGGER.info("InputDataSource did not produce any records for crlCheckALLDisablePositiveTest. Skipping the Testcase.");
            return;
        }
    }

    @Test(enabled = true, priority = 7, groups = { "Functional", "NSS", "RFA250", "ARNL", "ENM_EXTERNAL_TESTWARE", "KGB" })
    @TestSuite
    public void crlCheckDownloadPositiveTest() {
        LOGGER.info("Skipping crlCheckDownloadPositiveTest for RNC and VDU nodeType.");
        final Iterable<DataRecord> addedNodeList = Iterables.filter(context.dataSource(ADDED_NODES), PredicateUtil.isCRLNonApplicableNodes);
        if (!Iterables.isEmpty(addedNodeList)) {
            dataDrivenDataSource(INPUT_DATASOURCE, "NSCS_CRL_DOWNLOAD_CorrectUserRole", TITLE_CRLCHECK_DOWNLOAD_NODELIST,
                    addedNodeList);
            final TestScenario scenario = dataDrivenScenario("CRLCheck Download - Positive Scenario")
                    .addFlow(utilityFlows.login(PredicateUtil.nscsAdm()))
                    .addFlow(crLCheckFlows.downloadCrlCheckFlow(false))
                    .addFlow(utilityFlows.logout(PredicateUtil.nscsAdm()))
                    .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(ADDED_NODES))
                    .doParallel(Iterables.size(context.dataSource(INPUT_DATASOURCE))).build();
            startScenario(scenario);
        } else {
            LOGGER.info("InputDataSource did not produce any records for crlCheckDownloadPositiveTest. Skipping the Testcase.");
            return;
        }
    }

    //RBAC

    @Test(enabled = true, priority = 8, groups = { "Functional", "NSS", "KGB" })
    @TestSuite
    public void crlCheckOAMEnableNegativeTest() {
        doParallelNodesBase(INPUT_DATASOURCE_OAM, "NSCS_CRLCHECK_OAM_ON_WrongUserRole",
                context.dataSource(SetupAndTeardownScenarioCrlCheck.ISSUE_OAM_EXPMSG),
                SetupAndTeardownCertTypeCrlCheckScenario.getOamDataSource(), userListNegative);
        scenarioBaseCrlCheck("CRLCheck OAM Enable - Negative Scenario", INPUT_DATASOURCE_OAM, false,
                crLCheckFlows.enableCrlCheckFlow(true), vUserLocalOam);
    }

    @Test(enabled = true, priority = 9, groups = { "Functional", "NSS", "KGB" })
    @TestSuite
    public void crlCheckOAMDisableNegativeTest() {
        doParallelNodesBase(INPUT_DATASOURCE_OAM, "NSCS_CRLCHECK_OAM_OFF_WrongUserRole",
                context.dataSource(SetupAndTeardownScenarioCrlCheck.ISSUE_OAM_EXPMSG),
                SetupAndTeardownCertTypeCrlCheckScenario.getOamDataSource(), userListNegative);
        scenarioBaseCrlCheck("CRLCheck OAM Disable - Negative Scenario", INPUT_DATASOURCE_OAM, false,
                crLCheckFlows.disableCrlCheckFlow(true), vUserLocalOam);
    }

    @Test(enabled = true, priority = 10, groups = { "Functional", "NSS", "KGB" })
    @TestSuite
    public void crlCheckIPSECEnableNegativeTest() {
        doParallelNodesBase(INPUT_DATASOURCE_IPSEC, "NSCS_CRLCHECK_IPSEC_ON_WrongUserRole",
                context.dataSource(SetupAndTeardownScenarioCrlCheck.ISSUE_IPSEC_EXPMSG),
                SetupAndTeardownCertTypeCrlCheckScenario.getIpsecDataSource(), userListNegative);
        scenarioBaseCrlCheck("CRLCheck IPSEC Enable - Negative Scenario", INPUT_DATASOURCE_IPSEC, false,
                crLCheckFlows.enableCrlCheckFlow(true), vUserLocalIpsec);
    }

    @Test(enabled = true, priority = 11, groups = { "Functional", "NSS", "KGB" })
    @TestSuite
    public void crlCheckIPSECDisableNegativeTest() {
        doParallelNodesBase(INPUT_DATASOURCE_IPSEC, "NSCS_CRLCHECK_IPSEC_OFF_WrongUserRole",
                context.dataSource(SetupAndTeardownScenarioCrlCheck.ISSUE_IPSEC_EXPMSG),
                SetupAndTeardownCertTypeCrlCheckScenario.getIpsecDataSource(), userListNegative);
        scenarioBaseCrlCheck("CRLCheck IPSEC Disable - Negative Scenario", INPUT_DATASOURCE_IPSEC, false,
                crLCheckFlows.disableCrlCheckFlow(true), vUserLocalIpsec);
    }

    @Test(enabled = true, priority = 12, groups = { "Functional", "NSS", "KGB" })
    @TestSuite
    public void crlCheckALLEnableNegativeTest() {
        doParallelNodesBase(INPUT_DATASOURCE, "NSCS_CRLCHECK_ALL_ON_WrongUserRole",
                context.dataSource(SetupAndTeardownScenarioCrlCheck.ISSUE_ALL_EXPMSG),
                context.dataSource(ADDED_NODES), userListNegative);
        scenarioBaseAll("CRLCheck ALL Enable - Negative Scenario", false,
                crLCheckFlows.enableCrlCheckAllFlow(true), vUser);
    }

    @Test(enabled = true, priority = 13, groups = { "Functional", "NSS", "KGB" })
    @TestSuite
    public void crlCheckALLDisableNegativeTest() {
        doParallelNodesBase(INPUT_DATASOURCE, "NSCS_CRLCHECK_ALL_OFF_WrongUserRole",
                context.dataSource(SetupAndTeardownScenarioCrlCheck.ISSUE_ALL_EXPMSG),
                context.dataSource(ADDED_NODES), userListNegative);
        scenarioBaseAll("CRLCheck ALL Disable - Negative Scenario", false,
                crLCheckFlows.disableCrlCheckAllFlow(true), vUser);
    }

    //Unsuppported node version negative test
    //shall be introduced after a decision from MT on groups

    //    @Test(enabled = true, groups = { "KGB" })
    //    @TestSuite
    //    public void crlCheckUnsupportedNodeVersionNegativeTest() {
    //        doParallelNodesBase(INPUT_DATASOURCE, "NSCS_CRLCHECK_ALL_ON_UnsupportedNodeVersion",
    //                context.dataSource(SetupAndTeardownScenarioCrlCheck.UNSUPPORTED_NODE_VERSION__EXPMSG),
    //                context.dataSource(ADDED_NODES), userListPositive, vUser);
    //        scenarioBaseAll("CRLCheck Unsupported Node Version- Negative Scenario", false,
    //                crLCheckFlows.enableCrlCheckAllFlow(true), vUser);
    //    }

}
