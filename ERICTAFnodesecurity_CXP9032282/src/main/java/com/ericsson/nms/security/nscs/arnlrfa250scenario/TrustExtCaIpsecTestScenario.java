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
import static com.ericsson.nms.security.nscs.arnlrfa250scenario.SetupAndTeardownScenarioTrustExtCaIpsec.EXTERNALCA_TRUST_USECASE;
import static com.ericsson.nms.security.nscs.predicate.PredicateUtil.userRoleSuiteNamePredicate;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.ADDED_NODES;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.AVAILABLE_USERS;

import java.lang.reflect.Method;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.ericsson.cifwk.taf.annotations.TestSuite;
import com.ericsson.cifwk.taf.datasource.DataRecord;
import com.ericsson.cifwk.taf.scenario.TestScenario;
import com.ericsson.cifwk.taf.scenario.TestScenarioRunner;
import com.ericsson.nms.security.nscs.predicate.PredicateUtil;
import com.ericsson.oss.testware.nodesecurity.flows.PkiCommandFlow;
import com.ericsson.oss.testware.nodesecurity.flows.TrustDistributeFlow;
import com.ericsson.oss.testware.nodesecurity.steps.PkiCommandsTestSteps;
import com.google.common.base.Predicate;
import com.google.common.collect.Iterables;
import com.google.inject.Inject;

@SuppressWarnings({"PMD.LawOfDemeter"})
public class TrustExtCaIpsecTestScenario extends ScenarioUtility {

    private static final Logger LOGGER = LoggerFactory.getLogger(TrustExtCaIpsecTestScenario.class);
    private static final String TRUST_EXTCA_IPSEC_SINGLENODE = "TrustExtCaIpsecSingleNode";

    @Inject
    private TrustDistributeFlow trustDistributeFlow;
    @Inject
    private PkiCommandsTestSteps pkiCommandsTestSteps;
    @Inject
    private PkiCommandFlow PkiCommandFlow;

    @BeforeClass(groups = { "Functional", "NSS", "RFA250" })
    public void beforeClass() {
        final Predicate<DataRecord> predicatePositive =  userRoleSuiteNamePredicate("roles",
                SetupAndTeardownScenarioTrustExtCaIpsec.positiveCustomRolesList());
        final Predicate<DataRecord> predicateNegative = userRoleSuiteNamePredicate("roles",
                SetupAndTeardownScenarioTrustExtCaIpsec.negativeCustomRolesList());
        super.beforeClass(predicatePositive, predicateNegative);
        LOGGER.info("\n   BEFORE CLASS Trust ExtCaIpsec - START \n");
        dumpDataSource();
        LOGGER.info("\n   BEFORE CLASS Trust ExtCaIpsec - END \n");
        final TestScenario beforeClassScenario = scenario("Before Class Trust ExtCaIpsec Scenario")
                .addFlow(loginLogoutRestFlows.loginDefaultUser())
                .addFlow(PkiCommandFlow.inputsForTrustXml(EXTERNALCA_TRUST_USECASE))
                .build();
        final TestScenarioRunner runner = SetupAndTearDownUtil.getScenarioRunner();
        runner.start(beforeClassScenario);
    }

    @BeforeMethod(groups = { "Functional", "NSS", "RFA250" })
    public void beforeMethod(final Method method) {
        //NODES_TO_ADD_MULTINODES dataSource generator
        if (method.getName().startsWith("trustMultipleNodes")) {
            super.setupMultiNodes();
        }
    }

    @Test(enabled = true, priority = 1, groups = { "Functional", "NSS", "KGB" , "RFA250" })
    @TestSuite
    public void trustSingleNode() {
        singlenode(TRUST_EXTCA_IPSEC_SINGLENODE, context.dataSource(ADDED_NODES));
        doParallelNodesBase(INPUT_DATASOURCE, "NSCS_EXTERNALCAFORIPSEC_TRUST_SINGLENODE",
                context.dataSource(EXTERNALCA_TRUST_USECASE), context.dataSource(TRUST_EXTCA_IPSEC_SINGLENODE), userListPositive);
        ScenarioUtility.debugScope(LOGGER, INPUT_DATASOURCE);
        final TestScenario scenario = dataDrivenScenario("SingleNodeTrustExternalCAForIpsec")
                .addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(utilityFlows.verifySyncNodes())
                .addFlow(trustDistributeFlow.trustDistributeExtCa("TRUSTSINGLENODE", EXTERNALCA_TRUST_USECASE, pkiCommandsTestSteps.URLS))
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(AVAILABLE_USERS).bindTo(ADDED_NODES))
                .doParallel(vUser).build();
        final TestScenarioRunner runner = SetupAndTearDownUtil.getScenarioRunner();
        runner.start(scenario);
    }

    @Test(enabled = true, priority = 2, groups = { "Functional", "NSS", "KGB" })
    @TestSuite
    public void trustMultipleNodes() {
        final Iterable<DataRecord> userMultiNode = availableUserFiltered(PredicateUtil.nscsAdm());
        final int skipped = (Iterables.size(userMultiNode) >= 1) ? Iterables.size(userMultiNode) - 1 : 1;
        doParallelNodesBase(INPUT_DATASOURCE, "NSCS_EXTERNALCAFORIPSEC_TRUST_MULTIPLENODES",
                context.dataSource(EXTERNALCA_TRUST_USECASE), context.dataSource(NODES_TO_ADD_MULTINODES),
                Iterables.skip(userMultiNode, skipped));
        final TestScenario scenario = dataDrivenScenario("MultipleNodeTrustExternalCAForIpsec")
                .addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(trustDistributeFlow.trustDistributeExtCa("TRUSTMULTIPLENODE", EXTERNALCA_TRUST_USECASE, pkiCommandsTestSteps.URLS))
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(AVAILABLE_USERS).bindTo(ADDED_NODES))
                .doParallel(vUser).build();
        final TestScenarioRunner runner = SetupAndTearDownUtil.getScenarioRunner();
        runner.start(scenario);
    }

}

