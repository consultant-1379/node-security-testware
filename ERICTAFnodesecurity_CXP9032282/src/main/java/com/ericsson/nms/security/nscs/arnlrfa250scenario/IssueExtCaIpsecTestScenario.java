/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2012
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
import static com.ericsson.nms.security.nscs.arnlrfa250scenario.SetupAndTeardownScenarioIssueExtCaIpsec.ENTITY_CREATION;
import static com.ericsson.nms.security.nscs.arnlrfa250scenario.SetupAndTeardownScenarioIssueExtCaIpsec.ISSUE_EXTCA_MULTIPLENODE;
import static com.ericsson.nms.security.nscs.arnlrfa250scenario.SetupAndTeardownScenarioIssueExtCaIpsec.ISSUE_EXTCA_SINGLENODE;
import static com.ericsson.nms.security.nscs.predicate.PredicateUtil.userRoleSuiteNamePredicate;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.ADDED_NODES;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.AVAILABLE_USERS;

import java.lang.reflect.Method;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Optional;
import org.testng.annotations.Parameters;
import org.testng.annotations.Test;

import com.ericsson.cifwk.taf.annotations.TestSuite;
import com.ericsson.cifwk.taf.datasource.DataRecord;
import com.ericsson.cifwk.taf.scenario.TestScenario;
import com.ericsson.cifwk.taf.scenario.TestScenarioRunner;
import com.ericsson.nms.security.nscs.predicate.PredicateUtil;
import com.ericsson.oss.testware.nodesecurity.flows.CertificateIssueFlows;
import com.ericsson.oss.testware.nodesecurity.flows.PkiCommandFlow;
import com.ericsson.oss.testware.nodesecurity.steps.PkiCommandsTestSteps;
import com.google.common.base.Predicate;
import com.google.common.collect.Iterables;
import com.google.inject.Inject;

@SuppressWarnings({"PMD.LawOfDemeter"})
public class IssueExtCaIpsecTestScenario extends ScenarioUtility {

    private static final Logger LOGGER = LoggerFactory.getLogger(IssueExtCaIpsecTestScenario.class);
    private static final String ISSUE_EXTCA_IPSEC_SINGLENODE = "IssueExtCaIpsecSingleNode";
    private static String get_MOs_for_debug_purpose;


    @Inject
    private CertificateIssueFlows certificateIssueFlows;

    @Inject
    private PkiCommandsTestSteps pkiCommandsTestSteps;

    @Inject
    private PkiCommandFlow PkiCommandFlow;

    @BeforeClass(groups = { "Functional", "NSS", "RFA250" })

    @Parameters({ "get_MOs_for_debug_purpose"})
    public void beforeClass(@Optional final String get_MOs_for_debug_purpose) {
        this.get_MOs_for_debug_purpose = get_MOs_for_debug_purpose;
        MOsDataCollectionForDebug(get_MOs_for_debug_purpose);
        final Predicate<DataRecord> predicatePositive =  userRoleSuiteNamePredicate("roles",
                SetupAndTeardownScenarioIssueExtCaIpsec.positiveCustomRolesList());
        final Predicate<DataRecord> predicateNegative = userRoleSuiteNamePredicate("roles",
                SetupAndTeardownScenarioIssueExtCaIpsec.negativeCustomRolesList());
        super.beforeClass(predicatePositive, predicateNegative);
        LOGGER.info("\n   BEFORE CLASS Issue ExtCaIpsec - START \n");
        dumpDataSource();
        LOGGER.info("\n   BEFORE CLASS Issue ExtCaIpsec - END \n");
        final TestScenario beforeClassScenario = scenario("Before Class Issue ExtCaIpsec Scenario")
                .addFlow(loginLogoutRestFlows.loginDefaultUser())
                .addFlow(PkiCommandFlow.deleteEndEntityFlowBuilder().withDataSources(dataSource(ADDED_NODES)))
                .addFlow(PkiCommandFlow.inputsForIssueXml(ISSUE_EXTCA_SINGLENODE))
                .addFlow(PkiCommandFlow.createEndEntityFlow(ENTITY_CREATION).withDataSources(dataSource(ADDED_NODES)))
                .addFlow(loginLogoutRestFlows.logout()).alwaysRun()
                .build();
        final TestScenarioRunner runner = SetupAndTearDownUtil.getScenarioRunner();
        runner.start(beforeClassScenario);
    }

    @BeforeMethod(groups = { "Functional", "NSS", "RFA250" })
    public void beforeMethod(final Method method) {
        //NODES_TO_ADD_MULTINODES dataSource generator
        if (method.getName().startsWith("issueMultiple")) {
            super.setupMultiNodes();
        }
    }

    @Test(enabled = true, priority = 1, groups = { "Functional", "NSS", "KGB" , "RFA250" })
    @TestSuite
    public void issueSingleNode() {
        singlenode(ISSUE_EXTCA_IPSEC_SINGLENODE, context.dataSource(ADDED_NODES));
        doParallelNodesBase(INPUT_DATASOURCE, "NSCS_EXTERNALCAFORIPSEC_ISSUE_SINGLENODE",
                context.dataSource(ISSUE_EXTCA_SINGLENODE), context.dataSource(ISSUE_EXTCA_IPSEC_SINGLENODE), userListPositive);
        ScenarioUtility.debugScope(LOGGER, INPUT_DATASOURCE);
        final TestScenario scenario = dataDrivenScenario("SingleNodeIssueExternalCAForIpsec")
                .addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(utilityFlows.verifySyncNodes())
                .addFlow(certificateIssueFlows.certificateIssueSingleNodeExtCa("ExternalCaForIpsecIssueSingleNode",
                        ISSUE_EXTCA_SINGLENODE, pkiCommandsTestSteps.URLS))
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(AVAILABLE_USERS).bindTo(ADDED_NODES))
                .doParallel(vUser).build();
        final TestScenarioRunner runner = SetupAndTearDownUtil.getScenarioRunner();
        runner.start(scenario);
    }

    @Test(enabled = true, priority = 2, groups = { "Functional", "NSS", "KGB" })
    @TestSuite
    public void issueMultipleNodes() {
        final Iterable<DataRecord> userMultiNode = availableUserFiltered(PredicateUtil.nscsAdm());
        final int skipped = (Iterables.size(userMultiNode) >= 1) ? Iterables.size(userMultiNode) - 1 : 1;
        doParallelNodesBase(INPUT_DATASOURCE, "NSCS_EXTERNALCAFORIPSEC_ISSUE_MULTIPLENODES",
                context.dataSource(ISSUE_EXTCA_MULTIPLENODE), context.dataSource(NODES_TO_ADD_MULTINODES),
                Iterables.skip(userMultiNode, skipped));
        final TestScenario scenario = dataDrivenScenario("MultipleNodeIssueExternalCAForIpsec")
                .addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(certificateIssueFlows.certificateIssueMultipleNodesExtCa("ExternalCaForIpsecIssueMultipleNodes",
                        ISSUE_EXTCA_MULTIPLENODE, pkiCommandsTestSteps.URLS))
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(AVAILABLE_USERS).bindTo(ADDED_NODES))
                .doParallel(vUser).build();
        final TestScenarioRunner runner = SetupAndTearDownUtil.getScenarioRunner();
        runner.start(scenario);
    }

    @AfterClass(groups = { "Functional", "NSS", "RFA250" })
    public void afterClass() {
        LOGGER.info("\n   AFTER CLASS Issue ExtCaIpsec - START \n");
        dumpDataSource();
        LOGGER.info("\n   AFTER CLASS Issue ExtCaIpsec - END \n");
        final TestScenario afterClassScenario = scenario("After Class Issue ExtCaIpsec Scenario")
                .addFlow(loginLogoutRestFlows.loginDefaultUser())
                .addFlow(PkiCommandFlow.deleteEndEntityFlowBuilder()
                        .withDataSources(dataSource(ADDED_NODES)))
                .addFlow(loginLogoutRestFlows.logout()).alwaysRun()
                .build();
        final TestScenarioRunner runner = SetupAndTearDownUtil.getScenarioRunner();
        runner.start(afterClassScenario);
    }
}
