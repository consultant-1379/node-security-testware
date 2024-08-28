package com.ericsson.nms.security.nscs.scenario;

import static com.ericsson.cifwk.taf.scenario.TestScenarios.annotatedMethod;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.dataDrivenScenario;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.flow;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.fromTestStepResult;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.scenario;
import static com.ericsson.nms.security.nscs.constants.CsvDataSourceConstants.TRUST_DISTRIBUTE_POSITIVE_TESTS;
import static com.ericsson.nms.security.nscs.constants.CsvDataSourceConstants.TRUST_DISTRIBUTE_POSITIVE_TESTS_CSV;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.ADDED_NODES;

import javax.inject.Inject;

import org.testng.annotations.Test;

import com.ericsson.cifwk.taf.TafTestBase;
import com.ericsson.cifwk.taf.annotations.TestId;
import com.ericsson.cifwk.taf.annotations.TestSuite;
import com.ericsson.cifwk.taf.scenario.TestScenario;
import com.ericsson.cifwk.taf.scenario.TestStepFlow;
import com.ericsson.nms.security.nscs.datasource.PredicatesExt;
import com.ericsson.nms.security.nscs.flow.BaseFlow;
import com.ericsson.nms.security.nscs.flow.TrustDistributeFlow;
import com.ericsson.nms.security.nscs.teststep.GenericTestSteps;
import com.ericsson.oss.testware.enmbase.data.NodeType;
import com.ericsson.oss.testware.nodesecurity.steps.CredentialTestSteps;
import com.ericsson.oss.testware.nodesecurity.steps.JobIdMonitorTestSteps;
import com.ericsson.oss.testware.nodesecurity.steps.TrustDistributeTestSteps;
import com.ericsson.oss.testware.security.authentication.flows.LoginLogoutRestFlows;
import com.google.common.base.Predicate;

/**
 * Scenarios for trust distribute command.
 */
@SuppressWarnings({"PMD.LawOfDemeter"})
public class TrustDistributeScenario extends TafTestBase {

    private static final String TITLE_POSITIVE = "Trust Distribute Positive Scenario";
    private static final String TITLE_NEGATIVE = "Trust Distribute Negative Scenario";
    private static final String ADDED_NODES_WITH_TRUST_DISTR = "addedNodesWithTrustDistr";

    @Inject
    private LoginLogoutRestFlows loginlogoutFlow;

    @Inject
    private TrustDistributeFlow trustDistributeFlow;

    @Inject
    private BaseScenario baseScenario;

    @Inject
    private BaseFlow baseFlow;

    @Inject
    private GenericTestSteps genericTestSteps;

    @Inject
    private CredentialTestSteps credentialTestSteps;

    @Inject
    private TrustDistributeTestSteps trustDistributeTestSteps;

    @Inject
    private JobIdMonitorTestSteps jobIdMonitorTestSteps;

    /**
     * Trust distribute with cert type data driven scenario.
     */
    @Test(enabled = true, priority = 1, groups = { "Acceptance", "NSS" })
    @TestSuite
    public void trustDistributePositiveCertType() {
        final TestScenario scenario = trustDistributeScenario("Trust Distribute cert type data driven",
                TrustDistributeTestSteps.TRUST_DISTRIBUTE_CERT_TYPE, PredicatesExt.trustDistrCT);
        baseScenario.executeScenario(scenario);
    }

    /**
     * Trust distribute with cert type and ca name data driven scenario.
     */
    @Test(enabled = true, priority = 2, groups = { "Acceptance", "NSS" })
    @TestSuite
    public void trustDistributePositiveCaName() {
        final TestScenario scenario = trustDistributeScenario("Trust Distribute cert type and ca name data driven",
                TrustDistributeTestSteps.TRUST_DISTRIBUTE_CA_NAME, PredicatesExt.trustDistrCA);
        baseScenario.executeScenario(scenario);
    }

    private TestScenario trustDistributeScenario(final String flowName, final String testStepName, final Predicate predicate) {
        return dataDrivenScenario(TITLE_POSITIVE).addFlow(loginlogoutFlow.loginDefaultUser()).addFlow(trustDistributeFlow(flowName, testStepName))
                .withScenarioDataSources(
                        baseFlow.fillDataSource(TRUST_DISTRIBUTE_POSITIVE_TESTS_CSV, TRUST_DISTRIBUTE_POSITIVE_TESTS, ADDED_NODES_WITH_TRUST_DISTR,
                                NodeType.ERBS.toString()).withFilter(predicate).bindTo(ADDED_NODES)).addFlow(loginlogoutFlow.logout()).build();
    }

    private TestStepFlow trustDistributeFlow(final String flowName, final String testStepName) {
        return flow(flowName).addTestStep(annotatedMethod(credentialTestSteps, CredentialTestSteps.DELETE_SECURITY_INFO))
                .addTestStep(annotatedMethod(credentialTestSteps, CredentialTestSteps.CRED_CREATE))
                .addTestStep(annotatedMethod(genericTestSteps, GenericTestSteps.ENABLE_ALARM_SUPERVISION))
                .addTestStep(annotatedMethod(genericTestSteps, GenericTestSteps.CHECK_SYNC))
                .addTestStep(annotatedMethod(trustDistributeTestSteps, testStepName)).addTestStep(
                        annotatedMethod(jobIdMonitorTestSteps, JobIdMonitorTestSteps.JOB_ID_MONITOR)
                                .withParameter(ADDED_NODES, fromTestStepResult(testStepName))
                                .withParameter(JobIdMonitorTestSteps.Parameter.FUNCTIONALITY, JobIdMonitorTestSteps.Functionality.TRUST))
                .addTestStep(annotatedMethod(trustDistributeTestSteps, TrustDistributeTestSteps.TRUST_GET))
                .addTestStep(annotatedMethod(trustDistributeTestSteps, TrustDistributeTestSteps.TRUST_GET_VERIFY)
                        .withParameter(TrustDistributeTestSteps.Parameter.GET_RESPONSE, fromTestStepResult(TrustDistributeTestSteps.TRUST_GET)))
                .build();
    }

    /**
     * Trust distribute negative with cert type and ca name.
     */
    @Test(enabled = true, priority = 3, groups = { "Acceptance" })
    @TestId(id = "TORF-94195_NodeSecurity_TrustDistribute_NegativeScenarios", title = TITLE_NEGATIVE)
    public void trustDistributeNegative() {
        final TestScenario scenario = scenario(TITLE_NEGATIVE).addFlow(loginlogoutFlow.loginDefaultUser())
                .addFlow(trustDistributeFlow.trustDistributeCertTypeNegative()).addFlow(trustDistributeFlow.trustDistributeCaNameNegative())
                .addFlow(loginlogoutFlow.logout()).build();
        baseScenario.executeScenario(scenario);
    }
}
