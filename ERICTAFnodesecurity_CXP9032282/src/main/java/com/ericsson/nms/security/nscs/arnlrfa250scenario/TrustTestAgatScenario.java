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

import static com.ericsson.nms.security.nscs.arnlrfa250scenario.SetupAndTeardownScenarioTrust.TRUST_IPSEC;
import static com.ericsson.nms.security.nscs.arnlrfa250scenario.SetupAndTeardownScenarioTrust.TRUST_OAM;

import javax.inject.Inject;

import org.testng.ITestContext;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Optional;
import org.testng.annotations.Parameters;
import org.testng.annotations.Test;

import com.ericsson.cifwk.taf.TestContext;
import com.ericsson.cifwk.taf.annotations.TestSuite;
import com.ericsson.nms.security.nscs.predicate.PredicateUtil;
import com.ericsson.oss.testware.nodesecurity.flows.TrustDistributeFlow;
import com.ericsson.oss.testware.nodesecurity.flows.TrustRemoveFlow;

@SuppressWarnings({ "PMD.LawOfDemeter" })
public class TrustTestAgatScenario extends LogScenarioUtility {

    private static final String TITLE_TRUST_DISTRIBUITE_OAM = "Trust Distribute OAM";
    private static final String TITLE_TRUST_DISTRIBUITE_IPSEC = "Trust Distribute IPSEC";
    private static final String TITLE_TRUST_DISTRIBUITE_OAMLAAD_CANAME = "Trust Distribute OAM/LAAD with CA name";
    private static final String TITLE_TRUST_DISTRIBUITE_IPSEC_CANAME = "Trust Distribute IPSEC with CA name";
    private static final String TITLE_TRUST_REMOVE_OAMLAAD_CANAME = "Trust Remove OAM/LAAD with CA name";
    private static final String TITLE_TRUST_REMOVE_IPSEC_CANAME = "Trust Remove IPSEC with CA name";
    private static final String TITLE_TRUST_REMOVE_OAMLAAD_ISSUERDN = "Trust Remove OAM/LAAD with Issuer DN";
    private static final String TITLE_TRUST_REMOVE_IPSEC_ISSUERDN = "Trust Remove IPSEC with Issuer DN";

    private static final String LOG_SCENARIO_TAG = "TRUST";

    private String scenario = "";

    int vUserLocalOam;
    int vUserLocalIpsec;

    @Inject
    private TestContext context;

    @Inject
    private TrustDistributeFlow trustDistributeFlow;

    @Inject
    private TrustRemoveFlow trustRemoveFlow;
    @Inject
    private SetupAndTeardownScenarioTrust setupAndTeardownScenarioTrust;

    @BeforeClass(groups = { "Functional", "NSS", "RFA250", "ARNL", "ENM_EXTERNAL_TESTWARE" })
    @Parameters({ "agat" })
    @TestSuite
    public void beforeClass(final ITestContext suiteContext, @Optional final String agat) {
        SetupAndTeardownScenario.setAgat(agat);
        if (SetupAndTeardownScenario.isAgat()) {
            setupAndTeardownScenarioTrust.onBeforeSuite(suiteContext, SetupAndTeardownScenario.getAgat());
        }
        super.beforeClass();
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
            setupAndTeardownScenarioTrust.onAfterSuite();
        }
    }

    @Test(enabled = true, priority = 1, groups = { "Functional", "NSS", "RFA250", "ARNL", "ENM_EXTERNAL_TESTWARE" })
    @TestSuite
    public void trustDistributeOAM_PositiveTest() {
        doParallelNodesBase(INPUT_DATASOURCE_OAM, "NSCS_TRUSTDISTR_CertType(OAM)_CorrectUserRole", TITLE_TRUST_DISTRIBUITE_OAM,
                context.dataSource(TRUST_OAM), SetupAndTeardownCertTypeScenario.getOamDataSource(),
                availableUserFiltered(PredicateUtil.nsuAdm()));
        scenarioBaseTrust("TRUST Distribute CertType(OAM) - Positive Scenario", INPUT_DATASOURCE_OAM,
                trustDistributeFlow.trustDistrCertTypeBuilder(), vUserLocalOam);
    }

    @Test(enabled = true, priority = 2, groups = { "Functional", "NSS", "RFA250", "ARNL", "ENM_EXTERNAL_TESTWARE" })
    @TestSuite
    public void trustDistributeIPSEC_PositiveTest() {
        doParallelNodesBase(INPUT_DATASOURCE_IPSEC, "NSCS_TRUSTDISTR_CertType(IPSEC)_CorrectUserRole", TITLE_TRUST_DISTRIBUITE_IPSEC,
                context.dataSource(TRUST_IPSEC), SetupAndTeardownCertTypeScenario.getIpsecDataSource(),
                availableUserFiltered(PredicateUtil.nsuAdm()));
        scenarioBaseTrust("TRUST Distribute CertType(IPSEC) - Positive Scenario", INPUT_DATASOURCE_IPSEC,
                trustDistributeFlow.trustDistrCertTypeBuilder(), vUserLocalIpsec);
    }

    @Test(enabled = true, priority = 3, groups = { "Functional", "NSS", "RFA250", "ARNL", "ENM_EXTERNAL_TESTWARE" })
    @TestSuite
    public void trustDistributeOAM_CaName_PositiveTest() {
        doParallelNodesBase(INPUT_DATASOURCE_OAM, "NSCS_TRUSTDISTR_OAM_or_LAAD_CaName_CorrectUserRole", TITLE_TRUST_DISTRIBUITE_OAMLAAD_CANAME,
                context.dataSource(SetupAndTeardownScenarioTrust.TRUST_OAM_EXPMSG_FORCED_TO_LAAD), SetupAndTeardownCertTypeScenario.getOamDataSource(),
                availableUserFiltered(PredicateUtil.nsuAdm()));
        scenarioBaseTrust("TRUST Distribute OAM/LAAD CaName - Positive Scenario", INPUT_DATASOURCE_OAM,
                trustDistributeFlow.trustDistrCaNameBuilder(false), vUserLocalOam);
    }

    @Test(enabled = true, priority = 4, groups = { "Functional", "NSS", "RFA250", "ARNL", "ENM_EXTERNAL_TESTWARE" })
    @TestSuite
    public void trustDistribute_RemoveOAM_CaName() {
        doParallelNodesBase(INPUT_DATASOURCE_OAM, "NSCS_TRUSTREMOVE_OAM_or_LAAD_CaName_CorrectUserRole", TITLE_TRUST_REMOVE_OAMLAAD_CANAME,
                context.dataSource(SetupAndTeardownScenarioTrust.TRUST_OAM_EXPMSG_FORCED_TO_LAAD), SetupAndTeardownCertTypeScenario.getOamDataSource(),
                availableUserFiltered(PredicateUtil.nsuAdm()));
        scenarioBaseTrust("TRUST Remove OAM/LAAD CaName - Positive Scenario", INPUT_DATASOURCE_OAM,
                trustRemoveFlow.removeTrustCaNameListBuilder(false), vUserLocalOam);
    }

    @Test(enabled = true, priority = 5, groups = { "Functional", "NSS", "RFA250", "ARNL", "ENM_EXTERNAL_TESTWARE" })
    @TestSuite
    public void trustDistributeIPSEC_CaName_PositiveTest() {
        doParallelNodesBase(INPUT_DATASOURCE_IPSEC, "NSCS_TRUSTDISTR_CertType(IPSEC)_CaName_CorrectUserRole", TITLE_TRUST_DISTRIBUITE_IPSEC_CANAME,
                context.dataSource(SetupAndTeardownScenarioTrust.TRUST_IPSEC_EXPMSG), SetupAndTeardownCertTypeScenario.getIpsecDataSource(),
                availableUserFiltered(PredicateUtil.nsuAdm()));
        scenarioBaseTrust("TRUST Distribute CertType(IPSEC) CaName - Positive Scenario", INPUT_DATASOURCE_IPSEC,
                trustDistributeFlow.trustDistrCaNameBuilder(false), vUserLocalIpsec);
    }

    @Test(enabled = true, priority = 6, groups = { "Functional", "NSS", "RFA250", "ARNL", "ENM_EXTERNAL_TESTWARE" })
    @TestSuite
    public void trustDistribute_RemoveIPSEC_CaName() {
        doParallelNodesBase(INPUT_DATASOURCE_IPSEC, "NSCS_TRUSTREMOVE_CertType(IPSEC)_CaName_CorrectUserRole", TITLE_TRUST_REMOVE_IPSEC_CANAME,
                context.dataSource(SetupAndTeardownScenarioTrust.TRUST_IPSEC_EXPMSG), SetupAndTeardownCertTypeScenario.getIpsecDataSource(),
                availableUserFiltered(PredicateUtil.nsuAdm()));
        scenarioBaseTrust("TRUST Remove CertType(IPSEC) CaName - Positive Scenario", INPUT_DATASOURCE_IPSEC,
                trustRemoveFlow.removeTrustCaNameListBuilder(false), vUserLocalIpsec);
    }

    @Test(enabled = true, priority = 7, groups = { "Functional", "NSS", "RFA250", "ARNL", "ENM_EXTERNAL_TESTWARE" })
    @TestSuite
    public void trustDistribute_RemoveOAM_IssuerDn() {
        doParallelNodesBase(INPUT_DATASOURCE_OAM, "NSCS_TRUSTREMOVE_OAM_or_LAAD_Issuer-Dn_CorrectUserRole", TITLE_TRUST_REMOVE_OAMLAAD_ISSUERDN,
                context.dataSource(SetupAndTeardownScenarioTrust.TRUST_OAM_EXPMSG_FORCED_TO_LAAD), SetupAndTeardownCertTypeScenario.getOamDataSource(),
                availableUserFiltered(PredicateUtil.nsuAdm()));
        trustDistributeRemoveScenario("TRUST Remove OAM/LAAD IssuerDn - Positive Scenario", INPUT_DATASOURCE_OAM,
                trustDistributeFlow.trustDistrCaNameBuilder(false),
                trustRemoveFlow.removeTrustIssuerDnListBuilder(false), vUserLocalOam);
    }

    @Test(enabled = true, priority = 8, groups = { "Functional", "NSS", "RFA250", "ARNL", "ENM_EXTERNAL_TESTWARE" })
    @TestSuite
    public void trustDistribute_RemoveIPSEC_IssuerDn() {
        doParallelNodesBase(INPUT_DATASOURCE_IPSEC, "NSCS_TRUSTREMOVE_CertType(IPSEC)_Issuer-Dn_CorrectUserRole", TITLE_TRUST_REMOVE_IPSEC_ISSUERDN,
                context.dataSource(SetupAndTeardownScenarioTrust.TRUST_IPSEC_EXPMSG), SetupAndTeardownCertTypeScenario.getIpsecDataSource(),
                availableUserFiltered(PredicateUtil.nsuAdm()));
        trustDistributeRemoveScenario("TRUST Remove CertType(IPSEC) IssuerDn - Positive Scenario", INPUT_DATASOURCE_IPSEC,
                trustDistributeFlow.trustDistrCaNameBuilder(false),
                trustRemoveFlow.removeTrustIssuerDnListBuilder(false), vUserLocalIpsec);
    }
}

