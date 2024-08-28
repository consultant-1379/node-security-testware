package com.ericsson.nms.security.nscs.flow;

import static com.ericsson.cifwk.taf.scenario.TestScenarios.annotatedMethod;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.flow;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.fromTestStepResult;
import static com.ericsson.nms.security.nscs.teststep.SpecificIssueTestSteps.CERT_GET_RESULT;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.ADDED_NODES;

import javax.inject.Inject;

import com.ericsson.cifwk.taf.scenario.api.TestStepFlowBuilder;
import com.ericsson.nms.security.nscs.teststep.PkiCommandsTestSteps;
import com.ericsson.nms.security.nscs.teststep.SpecificIssueTestSteps;
import com.ericsson.oss.testware.nodesecurity.steps.JobIdMonitorTestSteps;

/**
 * Certificate issue flow class.
 */
@SuppressWarnings({"PMD.LawOfDemeter"})
public class GatFlows extends BaseFlow {

    @Inject
    private SpecificIssueTestSteps specificCertificateIssueTestSteps;
    @Inject
    private JobIdMonitorTestSteps jobIdMonitorTestSteps;
    @Inject
    private PkiCommandsTestSteps pkiCommandsTestSteps;

    /**
     * Start certificate issue test step with multiple nodes.
     *
     * @param inputCsv
     *         input test csv file
     * @param certTypeValue
     *         input cert type param
     *
     * @return TestStepFlowBuilder
     */
    public TestStepFlowBuilder certificateIssueMixability(final String inputCsv, final String certTypeValue) {
        return flow("######### GAT Specific Cert Issue Mixability")
                // 1st issue
                .addTestStep(annotatedMethod(specificCertificateIssueTestSteps, SpecificIssueTestSteps.SPECIFIC_CERTIFICATE_ISSUE_MIX)
                        .withParameter(SpecificIssueTestSteps.INPUT_CSV, inputCsv)
                        .withParameter(SpecificIssueTestSteps.CERT_TYPE_VALUE, certTypeValue)).addTestStep(
                        annotatedMethod(jobIdMonitorTestSteps, JobIdMonitorTestSteps.JOB_ID_MONITOR_GAT_MIX)
                                .withParameter(ADDED_NODES, fromTestStepResult(SpecificIssueTestSteps.SPECIFIC_CERTIFICATE_ISSUE_MIX))).addTestStep(
                        annotatedMethod(specificCertificateIssueTestSteps, SpecificIssueTestSteps.SPECIFIC_CERTIFICATE_GET_MIX)
                                .withParameter(SpecificIssueTestSteps.INPUT_CSV, inputCsv)
                                .withParameter(SpecificIssueTestSteps.CERT_TYPE_VALUE, certTypeValue))
                // 2nd issue
                .addTestStep(annotatedMethod(specificCertificateIssueTestSteps, SpecificIssueTestSteps.SPECIFIC_CERTIFICATE_ISSUE_MIX)
                        .withParameter(SpecificIssueTestSteps.INPUT_CSV, inputCsv)
                        .withParameter(SpecificIssueTestSteps.CERT_TYPE_VALUE, certTypeValue)).addTestStep(
                        annotatedMethod(jobIdMonitorTestSteps, JobIdMonitorTestSteps.JOB_ID_MONITOR_GAT_MIX)
                                .withParameter(ADDED_NODES, fromTestStepResult(SpecificIssueTestSteps.SPECIFIC_CERTIFICATE_ISSUE_MIX))).addTestStep(
                        annotatedMethod(pkiCommandsTestSteps, PkiCommandsTestSteps.PKI_REVOKED_CERTIFICATE)
                                .withParameter(SpecificIssueTestSteps.INPUT_CSV, inputCsv)
                                .withParameter(SpecificIssueTestSteps.CERT_TYPE_VALUE, certTypeValue)
                                .withParameter(CERT_GET_RESULT, fromTestStepResult(SpecificIssueTestSteps.SPECIFIC_CERTIFICATE_GET_MIX))).addTestStep(
                        annotatedMethod(specificCertificateIssueTestSteps, SpecificIssueTestSteps.SPECIFIC_CERTIFICATE_GET_MIX)
                                .withParameter(SpecificIssueTestSteps.INPUT_CSV, inputCsv)
                                .withParameter(SpecificIssueTestSteps.CERT_TYPE_VALUE, certTypeValue))
                // reissue
                .addTestStep(annotatedMethod(specificCertificateIssueTestSteps, SpecificIssueTestSteps.SPECIFIC_CERTIFICATE_REISSUE_MIX)
                        .withParameter(SpecificIssueTestSteps.INPUT_CSV, inputCsv)
                        .withParameter(SpecificIssueTestSteps.CERT_TYPE_VALUE, certTypeValue)).addTestStep(
                        annotatedMethod(jobIdMonitorTestSteps, JobIdMonitorTestSteps.JOB_ID_MONITOR_GAT_MIX)
                                .withParameter(ADDED_NODES, fromTestStepResult(SpecificIssueTestSteps.SPECIFIC_CERTIFICATE_REISSUE_MIX))).addTestStep(
                        annotatedMethod(pkiCommandsTestSteps, PkiCommandsTestSteps.PKI_REVOKED_CERTIFICATE)
                                .withParameter(SpecificIssueTestSteps.INPUT_CSV, inputCsv)
                                .withParameter(SpecificIssueTestSteps.CERT_TYPE_VALUE, certTypeValue)
                                .withParameter(CERT_GET_RESULT, fromTestStepResult(SpecificIssueTestSteps.SPECIFIC_CERTIFICATE_GET_MIX))).addTestStep(
                        annotatedMethod(specificCertificateIssueTestSteps, SpecificIssueTestSteps.SPECIFIC_CERTIFICATE_GET_MIX)
                                .withParameter(SpecificIssueTestSteps.INPUT_CSV, inputCsv)
                                .withParameter(SpecificIssueTestSteps.CERT_TYPE_VALUE, certTypeValue));
    }
}
