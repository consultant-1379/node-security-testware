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
import static com.ericsson.nms.security.nscs.arnlrfa250scenario.SetupAndTeardownScenarioIssueReIssue.ISSUE_EXPMSG;
import static com.ericsson.nms.security.nscs.constants.UserRoleValues.ROLE_IPSEC;
import static com.ericsson.nms.security.nscs.constants.UserRoleValues.ROLE_NODESECURITY_ADMIN;
import static com.ericsson.nms.security.nscs.constants.UserRoleValues.ROLE_NODESECURITY_OPERATOR;
import static com.ericsson.nms.security.nscs.constants.UserRoleValues.ROLE_OAM;
import static com.ericsson.nms.security.nscs.predicate.PredicateUtil.userRolePredicate;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.ADDED_NODES;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.AVAILABLE_USERS;

import java.util.Arrays;
import java.util.List;
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
import com.ericsson.cifwk.taf.datasource.DataRecord;
import com.ericsson.cifwk.taf.scenario.TestScenario;
import com.ericsson.cifwk.taf.scenario.api.TestStepFlowBuilder;
import com.ericsson.nms.security.nscs.constants.UserRoleValues;
import com.ericsson.nms.security.nscs.predicate.PredicateUtil;
import com.ericsson.oss.testware.nodesecurity.flows.CertificateIssueFlows;
import com.ericsson.oss.testware.nodesecurity.flows.CertificateReissueFlows;
import com.ericsson.oss.testware.nodesecurity.flows.SyntaxFlowsGeneric;
import com.ericsson.oss.testware.nodesecurity.steps.CertificateReissueTestSteps;
import com.ericsson.oss.testware.nodesecurity.steps.SyntaxTestSteps;
import com.google.common.base.Predicate;
import com.google.common.collect.Iterables;

@SuppressWarnings({ "PMD.LawOfDemeter", "PMD.ExcessiveImports", "PMD.TooManyFields" })
public class IssueReIssueTestScenario extends LogScenarioUtility {

    private static final Logger LOGGER = LoggerFactory.getLogger(IssueReIssueTestScenario.class);
    private static final String SINGLE_NODE_DATA_SOURCE = "singleNodeDataSource";
    private static final String TITLE_ISSUE_OAM = "Certificate Issue OAM";
    private static final String TITLE_ISSUE_IPSEC = "Certificate Issue IPSEC";
    private static final String TITLE_REISSUE_OAM_CERTTYPE = "Certificate Re-Issue OAM with Cert Type";
    private static final String TITLE_REISSUE_IPSEC_CERTTYPE = "Certificate Re-Issue IPSEC with Cert Type";
    private static final String TITLE_REISSUE_OAM_CANAME = "Certificate Re-Issue OAM with CA name";
    private static final String TITLE_REISSUE_IPSEC_CANAME = "Certificate Re-Issue IPSEC with CA name";
    private static String get_MOs_for_debug_purpose;
    private static final String LOG_SCENARIO_TAG = "ISSUEREISSUE";

    @Inject
    private TestContext context;
    @Inject
    private CertificateIssueFlows certificateIssueFlows;
    @Inject
    private CertificateReissueFlows certificateReissueFlows;
    @Inject
    private SetupAndTeardownScenarioIssueReIssue setupAndTeardownScenarioIssueReIssue;

    @Inject
    private SyntaxFlowsGeneric syntaxFlowsGeneric;

    Iterable<? extends DataRecord> oam = null;
    Iterable<? extends DataRecord> ipsec = null;
    int vUserLocalOam;
    int vUserLocalIpsec;

    public static List<String> issue_positiveUserRoles = Arrays.asList(ROLE_NODESECURITY_ADMIN);
    public static List<String> reissue_oam_positiveUserRoles = Arrays.asList(ROLE_NODESECURITY_ADMIN, ROLE_OAM);
    public static List<String> reissue_ipsec_positiveUserRoles = Arrays.asList(ROLE_NODESECURITY_ADMIN, ROLE_IPSEC);

    final Predicate<DataRecord> predicateIssueOamPositive = userRolePredicate("roles", issue_positiveUserRoles);
    final Predicate<DataRecord> predicateIssueIpsecPositive = userRolePredicate("roles", issue_positiveUserRoles);
    final Predicate<DataRecord> predicateReIssueOamPositive = userRolePredicate("roles", reissue_oam_positiveUserRoles);
    final Predicate<DataRecord> predicateReIssueIpsecPositive = userRolePredicate("roles", reissue_ipsec_positiveUserRoles);

    final Predicate<DataRecord> predicateIssueOamNegative = userRolePredicate("roles", new UserRoleValues().removeAll(reissue_oam_positiveUserRoles));
    final Predicate<DataRecord> predicateIssueIpsecNegative = userRolePredicate("roles", new UserRoleValues().removeAll
            (reissue_ipsec_positiveUserRoles));
    final Predicate<DataRecord> predicateReIssueOamNegative = userRolePredicate("roles", Arrays.asList(ROLE_NODESECURITY_OPERATOR));
    final Predicate<DataRecord> predicateReIssueIpsecNegative = userRolePredicate("roles", Arrays.asList(ROLE_NODESECURITY_OPERATOR));

    private String scenario = "";

    @BeforeClass(groups = { "Functional", "NSS", "RFA250", "ARNL", "ENM_EXTERNAL_TESTWARE" })
    @Parameters({ "agat" , "get_MOs_for_debug_purpose"})
    @TestSuite
    public void beforeClass(final ITestContext suiteContext, @Optional final String agat, @Optional final String get_MOs_for_debug_purpose) {
        this.get_MOs_for_debug_purpose = get_MOs_for_debug_purpose;
        MOsDataCollectionForDebug(get_MOs_for_debug_purpose);
        SetupAndTeardownScenario.setAgat(agat);
        if (SetupAndTeardownScenario.isAgat()) {
            setupAndTeardownScenarioIssueReIssue.onBeforeSuite(suiteContext, SetupAndTeardownScenario.getAgat());
        }
        oam = SetupAndTeardownScenarioIssueReIssue.getOamDataSource();
        ipsec = SetupAndTeardownScenarioIssueReIssue.getIpsecDataSource();
        vUserLocalOam = SetupAndTeardownScenarioIssueReIssue.getNumUserOam();
        vUserLocalIpsec = SetupAndTeardownScenarioIssueReIssue.getNumUserIpsec();
        scenario = suiteContext.getName();
        enableLogManagement(LOG_ENABLE_SCRIPT_FILENAME, LOG_SCENARIO_TAG);
        if(SetupAndTeardownScenario.isRealNode()) {
            setUpRnlSyncNodesTimeOut();
        }
    }



    @AfterClass(groups = { "Functional", "NSS", "RFA250", "ARNL", "ENM_EXTERNAL_TESTWARE" })
    @TestSuite
    public void afterClass() {
        disableLogManagement(LOG_DISABLE_SCRIPT_FILENAME, LOG_SCENARIO_TAG);
        if (SetupAndTeardownScenario.isAgat()) {
            setupAndTeardownScenarioIssueReIssue.onAfterSuite();
        }
    }

    @Test(enabled = true, priority = 1, groups = { "Functional", "NSS", "RFA250", "ARNL", "ENM_EXTERNAL_TESTWARE" })
    @TestSuite
    public void issueOAMPositiveTest() {
        doParallelDifferentCommandsPerNodesBase(INPUT_DATASOURCE_OAM, "NSCS_ISSUE_OAM_CorrectUserRole", TITLE_ISSUE_OAM, oam,
                Iterables.filter(context.dataSource(AVAILABLE_USERS), predicateIssueOamPositive), vUser);
        ScenarioUtility.debugScope(LOGGER, INPUT_DATASOURCE_OAM);
        scenarioBase("ISSUE OAM - Positive Scenario", INPUT_DATASOURCE_OAM,
                certificateIssueFlows.certificateIssueVerify(SetupAndTeardownScenario.isRealNode()), vUserLocalOam);
    }

    @Test(enabled = true, priority = 2, groups = { "Functional", "NSS", "RFA250", "ARNL", "ENM_EXTERNAL_TESTWARE" })
    @TestSuite
    public void issueIPSECPositiveTest() {
        doParallelDifferentCommandsPerNodesBase(INPUT_DATASOURCE_IPSEC, "NSCS_ISSUE_IPSEC_CorrectUserRole", TITLE_ISSUE_IPSEC, ipsec,
                Iterables.filter(context.dataSource(AVAILABLE_USERS), predicateIssueIpsecPositive), vUser);
        ScenarioUtility.debugScope(LOGGER, INPUT_DATASOURCE_IPSEC);
        scenarioBase("ISSUE IPSEC - Positive Scenario", INPUT_DATASOURCE_IPSEC,
                certificateIssueFlows.certificateIssueVerify(SetupAndTeardownScenario.isRealNode()), vUserLocalIpsec);
    }

    //CERTTYPE
    @Test(enabled = true, priority = 3, groups = { "Functional", "NSS", "RFA250", "ARNL", "ENM_EXTERNAL_TESTWARE" })
    @TestSuite
    public void reIssueOAMCertTypePositiveTest() {
        doParallelNodesBase(INPUT_DATASOURCE_OAM, "NSCS_REISSUE_OAM_CertType_CorrectUserRole", TITLE_REISSUE_OAM_CERTTYPE,
                context.dataSource(SetupAndTeardownScenarioIssueReIssue.REISSUE_OAM), oam,
                Iterables.filter(context.dataSource(AVAILABLE_USERS), predicateReIssueOamPositive));
        ScenarioUtility.debugScope(LOGGER, INPUT_DATASOURCE_OAM);
        scenarioBase("REISSUE OAM CertType - Positive Scenario", INPUT_DATASOURCE_OAM,
                certificateReissueFlows.certificateReissueCertTypeVerify(SetupAndTeardownScenario.isRealNode()), vUserLocalOam);
    }

    @Test(enabled = true, priority = 4, groups = { "Functional", "NSS", "RFA250", "ARNL", "ENM_EXTERNAL_TESTWARE" })
    @TestSuite
    public void reIssueIPSECCertTypePositiveTest() {
        doParallelNodesBase(INPUT_DATASOURCE_IPSEC, "NSCS_REISSUE_IPSEC_CertType_CorrectUserRole", TITLE_REISSUE_IPSEC_CERTTYPE,
                context.dataSource(SetupAndTeardownScenarioIssueReIssue.REISSUE_IPSEC), ipsec,
                Iterables.filter(context.dataSource(AVAILABLE_USERS), predicateReIssueIpsecPositive));
        ScenarioUtility.debugScope(LOGGER, INPUT_DATASOURCE_IPSEC);
        scenarioBase("REISSUE IPSEC CertType - Positive Scenario", INPUT_DATASOURCE_IPSEC,
                certificateReissueFlows.certificateReissueCertTypeVerify(SetupAndTeardownScenario.isRealNode()), vUserLocalIpsec);
    }

    //CANAME
    @Test(enabled = true, priority = 5, groups = { "Functional", "NSS", "ARNL", "ENM_EXTERNAL_TESTWARE" })
    @TestSuite
    public void reIssueOAMCaNamePositiveTest() {
        doParallelNodesBase(INPUT_DATASOURCE_OAM, "NSCS_REISSUE_OAM_CaName_CorrectUserRole", TITLE_REISSUE_OAM_CANAME,
                context.dataSource(SetupAndTeardownScenarioIssueReIssue.REISSUE_OAM), oam,
                Iterables.filter(context.dataSource(AVAILABLE_USERS), predicateReIssueOamPositive));
        ScenarioUtility.debugScope(LOGGER, INPUT_DATASOURCE_OAM);
        scenarioBase("REISSUE OAM CaName - Positive Scenario", INPUT_DATASOURCE_OAM,
                certificateReissueFlows.certificateReissueCaNameVerify(SetupAndTeardownScenario.isRealNode()), vUserLocalOam);
    }

    @Test(enabled = true, priority = 6, groups = { "Functional", "NSS", "ARNL", "ENM_EXTERNAL_TESTWARE" })
    @TestSuite
    public void reIssueIPSECCaNamePositiveTest() {
        doParallelNodesBase(INPUT_DATASOURCE_IPSEC, "NSCS_REISSUE_IPSEC_CaName_CorrectUserRole", TITLE_REISSUE_IPSEC_CANAME,
                context.dataSource(SetupAndTeardownScenarioIssueReIssue.REISSUE_IPSEC), ipsec,
                Iterables.filter(context.dataSource(AVAILABLE_USERS), predicateReIssueIpsecPositive));
        ScenarioUtility.debugScope(LOGGER, INPUT_DATASOURCE_IPSEC);
        scenarioBase("REISSUE IPSEC CaName - Positive Scenario", INPUT_DATASOURCE_IPSEC,
                certificateReissueFlows.certificateReissueCaNameVerify(SetupAndTeardownScenario.isRealNode()), vUserLocalIpsec);
    }

    //RBAC
    //RBAC
    //RBAC

    private void scenarioBaseRbac(final String scenarioName, final TestStepFlowBuilder flowName, final int vUsers) {
        final TestScenario scenario = dataDrivenScenario(scenarioName)
                .addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(flowName)
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(AVAILABLE_USERS).bindTo(ADDED_NODES))
                .doParallel(vUsers).build();
        startScenario(scenario);
    }

    //Wrong user role
    @Test(enabled = true, priority = 7, groups = { "Functional", "NSS" })
    @TestSuite
    public void issueOAMNegativeTest() {
        doParallelDifferentCommandsPerNodesBase(INPUT_DATASOURCE, "NSCS_ISSUE_OAM_WrongUserRole",
                addDataRecordForEachDataSourceFields(context.dataSource(ISSUE_EXPMSG).iterator().next(), oam),
                Iterables.filter(context.dataSource(AVAILABLE_USERS), predicateIssueOamNegative), vUser);
        ScenarioUtility.debugScope(LOGGER, INPUT_DATASOURCE);
        scenarioBaseRbac("ISSUE OAM - Negative Scenario",
                certificateIssueFlows.certificateIssueBuilder(), vUserLocalOam);
    }

    @Test(enabled = true, priority = 8, groups = { "Functional", "NSS" })
    @TestSuite
    public void issueIPSECNegativeTest() {
        doParallelDifferentCommandsPerNodesBase(INPUT_DATASOURCE, "NSCS_ISSUE_IPSEC_WrongUserRole",
                addDataRecordForEachDataSourceFields(context.dataSource(ISSUE_EXPMSG).iterator().next(), ipsec),
                Iterables.filter(context.dataSource(AVAILABLE_USERS), predicateIssueIpsecNegative), vUser);
        ScenarioUtility.debugScope(LOGGER, INPUT_DATASOURCE);
        scenarioBaseRbac("ISSUE IPSEC - Negative Scenario",
                certificateIssueFlows.certificateIssueBuilder(), vUserLocalIpsec);
    }

    @Test(enabled = true, priority = 9, groups = { "Functional", "NSS" })
    @TestSuite
    public void reIssueOAMCertTypeNegativeTest() {
        doParallelNodesBase(INPUT_DATASOURCE, "NSCS_REISSUE_OAM_CertType_WrongUserRole",
                context.dataSource(SetupAndTeardownScenarioIssueReIssue.REISSUE_OAM_EXPMSG), oam,
                Iterables.filter(context.dataSource(AVAILABLE_USERS), predicateReIssueOamNegative));
        ScenarioUtility.debugScope(LOGGER, INPUT_DATASOURCE);
        scenarioBaseRbac("REISSUE OAM CertType - Negative Scenario",
                certificateReissueFlows
                        .certificateReissueBasicFlow("Certificate Reissue Flow with Cert Type", CertificateReissueTestSteps.CERT_REISSUE_CERT_TYPE),
                vUserLocalOam);
    }

    @Test(enabled = true, priority = 10, groups = { "Functional", "NSS" })
    @TestSuite
    public void reIssueIPSECCertTypeNegativeTest() {
        doParallelNodesBase(INPUT_DATASOURCE, "NSCS_REISSUE_IPSEC_CertType_WrongUserRole",
                context.dataSource(SetupAndTeardownScenarioIssueReIssue.REISSUE_IPSEC_EXPMSG), ipsec,
                Iterables.filter(context.dataSource(AVAILABLE_USERS), predicateReIssueIpsecNegative));
        ScenarioUtility.debugScope(LOGGER, INPUT_DATASOURCE);
        scenarioBaseRbac("REISSUE IPSEC CertType - Negative Scenario",
                certificateReissueFlows
                        .certificateReissueBasicFlow("Certificate Reissue Flow with Cert Type", CertificateReissueTestSteps.CERT_REISSUE_CERT_TYPE),
                vUserLocalIpsec);
    }

    @Test(enabled = true, priority = 11, groups = { "Functional", "NSS" })
    @TestSuite
    public void reIssueOAMCaNameNegativeTest() {
        doParallelNodesBase(INPUT_DATASOURCE, "NSCS_REISSUE_OAM_CaName_WrongUserRole",
                context.dataSource(SetupAndTeardownScenarioIssueReIssue.REISSUE_OAM_EXPMSG), oam,
                Iterables.filter(context.dataSource(AVAILABLE_USERS), predicateReIssueOamNegative));
        ScenarioUtility.debugScope(LOGGER, INPUT_DATASOURCE);
        scenarioBaseRbac("REISSUE OAM CaName - Negative Scenario",
                certificateReissueFlows
                        .certificateReissueBasicFlow("Certificate Reissue Flow with CA name", CertificateReissueTestSteps.CERT_REISSUE_CA_NAME),
                vUserLocalOam);
    }

    @Test(enabled = true, priority = 12, groups = { "Functional", "NSS" })
    @TestSuite
    public void reIssueIPSECCaNameNegativeTest() {
        doParallelNodesBase(INPUT_DATASOURCE, "NSCS_REISSUE_IPSEC_CaName_WrongUserRole",
                context.dataSource(SetupAndTeardownScenarioIssueReIssue.REISSUE_IPSEC_EXPMSG), ipsec,
                Iterables.filter(context.dataSource(AVAILABLE_USERS), predicateReIssueIpsecNegative));
        ScenarioUtility.debugScope(LOGGER, INPUT_DATASOURCE);
        scenarioBaseRbac("REISSUE IPSEC CaName - Negative Scenario",
                certificateReissueFlows
                        .certificateReissueBasicFlow("Certificate Reissue Flow with CA name", CertificateReissueTestSteps.CERT_REISSUE_CA_NAME),
                vUserLocalIpsec);
    }

    @Test(enabled = true, priority = 13, groups = { "Functional", "NSS" })
    @TestSuite
    public void issueReIssueNegativeSyntax() {
        singlenode(SINGLE_NODE_DATA_SOURCE, context.dataSource(ADDED_NODES));
        doParallelNodesBase(INPUT_DATASOURCE, "NSCS_ISSUE_REISSUE_NEGATIVE_TEST_SYNTAX_ERRORS",
                context.dataSource(SetupAndTeardownScenarioIssueReIssue.ISSUE_REISSUE_SYNTAX_NEGATIVE), context.dataSource(SINGLE_NODE_DATA_SOURCE),
                availableUserFiltered(PredicateUtil.nscsAdm()));
        final TestScenario scenario = dataDrivenScenario("Issue ReIssue with Syntax errors - Negative Scenario")
                .addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(syntaxFlowsGeneric.syntaxCommandBasic())
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(ADDED_NODES).bindTo(AVAILABLE_USERS)
                        .bindTo(SyntaxTestSteps.DataSource.SYNTAX_INFO_DATASOURCE))
                .doParallel(1).build();
        startScenario(scenario);
    }
}

