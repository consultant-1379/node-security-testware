package com.ericsson.nms.security.nscs.scenario;

import static com.ericsson.cifwk.taf.scenario.TestScenarios.annotatedMethod;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.dataDrivenScenario;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.flow;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.fromTestStepResult;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.scenario;
import static com.ericsson.nms.security.nscs.constants.CsvDataSourceConstants.TRUST_REMOVE_POSITIVE_TESTS;
import static com.ericsson.nms.security.nscs.constants.CsvDataSourceConstants.TRUST_REMOVE_POSITIVE_TESTS_CSV;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.ADDED_NODES;

import javax.inject.Inject;

import com.ericsson.cifwk.taf.TafTestBase;
import org.testng.annotations.Test;

import com.ericsson.cifwk.taf.annotations.TestId;
import com.ericsson.cifwk.taf.annotations.TestSuite;
import com.ericsson.cifwk.taf.scenario.TestScenario;
import com.ericsson.cifwk.taf.scenario.TestStepFlow;
import com.ericsson.oss.testware.enmbase.data.NodeType;
import com.ericsson.nms.security.nscs.datasource.PredicatesExt;
import com.ericsson.nms.security.nscs.flow.BaseFlow;
import com.ericsson.nms.security.nscs.flow.TrustRemoveFlow;
import com.ericsson.nms.security.nscs.teststep.GenericTestSteps;
import com.ericsson.oss.testware.nodesecurity.steps.JobIdMonitorTestSteps;
import com.ericsson.oss.testware.nodesecurity.steps.TrustDistributeTestSteps;
import com.ericsson.oss.testware.nodesecurity.steps.TrustRemoveTestSteps;
import com.ericsson.oss.testware.security.authentication.flows.LoginLogoutRestFlows;
import com.google.common.base.Predicate;

/**
 * Scenarios for trust remove command.
 */
@SuppressWarnings({"PMD.LawOfDemeter"})
public class TrustRemoveScenario extends TafTestBase {

    private static final String TITLE_POSITIVE = "Trust Remove Positive Scenario";
    private static final String TITLE_NEGATIVE = "Trust Remove Negative Scenario";
    private static final String ADDED_NODES_WITH_TRUST_REMOVE = "addedNodesWithTrustRemove";
    private static final String TRUST_REMOVE_VERIFY_CA_LABEL = "CA Name";
    private static final String TRUST_REMOVE_VERIFY_ISDN_LABEL = "Issuer-Dn";

    @Inject
    private LoginLogoutRestFlows loginlogoutFlow;

    @Inject
    private TrustRemoveFlow trustRemoveFlow;

    @Inject
    private BaseScenario baseScenario;

    @Inject
    private BaseFlow baseFlow;

    @Inject
    private GenericTestSteps genericTestSteps;

    @Inject
    private TrustDistributeTestSteps trustDistributeTestSteps;

    @Inject
    private TrustRemoveTestSteps trustRemoveTestSteps;

    @Inject
    private JobIdMonitorTestSteps jobIdMonitorTestSteps;

    /**
     * Trust remove with issuer-dn data driven scenario.
     */
    @Test(enabled = true, priority = 1, groups = { "Acceptance", "NSS" })
    @TestSuite
    public void trustRemovePositiveIsdn() {
        final TestScenario scenario = trustRemoveScenario("Trust Remove cert type with issuer-dn data driven",
                TrustRemoveTestSteps.TRUST_REMOVE_ISDN_LIST, PredicatesExt.trustDistrCT, TRUST_REMOVE_VERIFY_ISDN_LABEL);
        baseScenario.executeScenario(scenario);
    }

    /**
     * Trust remove with ca name data driven scenario.
     */
    @Test(enabled = true, priority = 2, groups = { "Acceptance", "NSS" })
    @TestSuite
    public void trustRemovePositiveCaName() {
        final TestScenario scenario = trustRemoveScenario("Trust Remove cert type with ca name data driven",
                TrustRemoveTestSteps.TRUST_REMOVE_CA_NAME_LIST, PredicatesExt.trustDistrCA, TRUST_REMOVE_VERIFY_CA_LABEL);
        baseScenario.executeScenario(scenario);
    }

    private TestScenario trustRemoveScenario(final String flowName, final String testStepTrustRemoveName, final Predicate predicate, final String trustVerifyRemoveTypeName) {
        return dataDrivenScenario(TITLE_POSITIVE)
                .addFlow(loginlogoutFlow.loginDefaultUser())
                .addFlow(trustRemoveFlow(flowName, testStepTrustRemoveName, trustVerifyRemoveTypeName))
                .withScenarioDataSources(baseFlow.fillDataSource(TRUST_REMOVE_POSITIVE_TESTS_CSV, TRUST_REMOVE_POSITIVE_TESTS, ADDED_NODES_WITH_TRUST_REMOVE,
                        NodeType.ERBS.toString()).withFilter(predicate).bindTo(ADDED_NODES))
                .addFlow(loginlogoutFlow.logout())
                .build();
    }

    private TestStepFlow trustRemoveFlow(final String flowName, final String testStepName, final String trustVerifyType) {
        return flow(flowName)
                .addTestStep(annotatedMethod(genericTestSteps, GenericTestSteps.CHECK_SYNC))
                .addTestStep(annotatedMethod(trustDistributeTestSteps, TrustDistributeTestSteps.TRUST_LIST_GET))
                .addTestStep(annotatedMethod(trustRemoveTestSteps, testStepName)
                        .withParameter(TrustRemoveTestSteps.DataSource.TRUST_REMOVE_DATASOURCE,
                                fromTestStepResult(TrustDistributeTestSteps.TRUST_LIST_GET)))
                .addTestStep(annotatedMethod(jobIdMonitorTestSteps, JobIdMonitorTestSteps.JOB_ID_MONITOR_LIST)
                        .withParameter(JobIdMonitorTestSteps.Parameter.JOB_ID_LIST,
                                fromTestStepResult(testStepName)))
                .addTestStep(annotatedMethod(genericTestSteps, GenericTestSteps.CHECK_SYNC))
                .addTestStep(annotatedMethod(trustDistributeTestSteps, TrustDistributeTestSteps.TRUST_GET))
                .addTestStep(annotatedMethod(trustRemoveTestSteps, TrustRemoveTestSteps.TRUST_REMOVE_VERIFY_BY_PARAMETERS)
                                .withParameter(TrustDistributeTestSteps.Parameter.GET_RESPONSE, fromTestStepResult(TrustDistributeTestSteps.TRUST_GET))
                                .withParameter(TrustRemoveTestSteps.DataSource.TRUST_REMOVE_DATASOURCE, fromTestStepResult(TrustDistributeTestSteps.TRUST_LIST_GET))
                                .withParameter("verifyType", trustVerifyType))
                .build();
    }

    /**
     * Trust remove negative with issuer dn and ca name.
     */
    @Test(enabled = true, priority = 3, groups = { "Acceptance" })
    @TestId(id = "TORF-77165_NodeSecurity_TrustRemove_NegativeScenarios", title = TITLE_NEGATIVE)
    public void trustRemoveNegative() {
        final TestScenario scenario = scenario(TITLE_NEGATIVE).addFlow(loginlogoutFlow.loginDefaultUser())
                .addFlow(trustRemoveFlow.trustRemoveByIsdnNegative()).addFlow(trustRemoveFlow.trustRemoveByCANegative())
                .addFlow(loginlogoutFlow.logout()).build();
        baseScenario.executeScenario(scenario);
    }
}
