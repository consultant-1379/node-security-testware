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

package com.ericsson.nms.security.nscs.flow;

import static com.ericsson.cifwk.taf.scenario.TestScenarios.annotatedMethod;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.dataSource;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.flow;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.fromTestStepResult;
import static com.ericsson.nms.security.nscs.constants.CsvDataSourceConstants.CERTIFICATE_REISSUE_NEGATIVE_TESTS;
import static com.ericsson.nms.security.nscs.constants.CsvDataSourceConstants.CERTIFICATE_REISSUE_NEGATIVE_TESTS_CSV;
import static com.ericsson.nms.security.nscs.constants.CsvDataSourceConstants.CERTIFICATE_REISSUE_POSITIVE_TESTS;
import static com.ericsson.nms.security.nscs.constants.CsvDataSourceConstants.CERTIFICATE_REISSUE_POSITIVE_TESTS_CSV;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.ADDED_NODES;
import static com.ericsson.oss.testware.nodesecurity.steps.CertificateIssueTestSteps.Param.ENROLL_STATE_AFTER;
import static com.ericsson.oss.testware.nodesecurity.steps.CertificateIssueTestSteps.Param.ENROLL_STATE_BEFORE;

import javax.inject.Inject;

import com.ericsson.cifwk.taf.scenario.api.TestStepFlowBuilder;
import com.ericsson.nms.security.nscs.datasource.PredicatesExt;
import com.ericsson.oss.testware.enmbase.data.NodeType;
import com.ericsson.oss.testware.nodesecurity.steps.CertificateIssueTestSteps;
import com.ericsson.oss.testware.nodesecurity.steps.CertificateReissueTestSteps;
import com.ericsson.oss.testware.nodesecurity.steps.JobIdMonitorTestSteps;
import com.google.common.base.Predicate;

/**
 * Flows for certificate reissue commands.
 */
@SuppressWarnings({"PMD.LawOfDemeter"})
public class CertificateReissueFlow extends BaseFlow {

    private static final String ADDED_NODES_WITH_CERT_REISSUE = "addedNodesWithCertReIssue";

    @Inject
    private CertificateReissueTestSteps certificateReissueTestSteps;
    @Inject
    private CertificateIssueTestSteps certificateIssueTestSteps;
    @Inject
    private JobIdMonitorTestSteps jobIdMonitorTestSteps;

    /**
     * Start certificate reissue command with cert type parameter and check the MoAction is triggered on the node.
     *
     * @return TestStepFlowBuilder
     */
    public TestStepFlowBuilder certificateReissueCertTypeVerify() {
        return certificateReissueFlow("Certificate Reissue Flow with cert type", CertificateReissueTestSteps.CERT_REISSUE_CERT_TYPE,
                PredicatesExt.testByCertType);
    }

    /**
     * Start certificate reissue command with ca name parameter and check the MoAction is triggered on the node.
     *
     * @return TestStepFlowBuilder
     */
    public TestStepFlowBuilder certificateReissueCaNameVerify() {
        return certificateReissueFlow("Certificate Reissue Flow with ca name", CertificateReissueTestSteps.CERT_REISSUE_CA_NAME,
                PredicatesExt.testByCA);
    }

    private TestStepFlowBuilder certificateReissueFlow(final String flowName, final String testStepName, final Predicate predicate) {
        return flow(flowName).beforeFlow(
                addNodeTypeToDataSource(CERTIFICATE_REISSUE_POSITIVE_TESTS_CSV, CERTIFICATE_REISSUE_POSITIVE_TESTS, ADDED_NODES_WITH_CERT_REISSUE,
                        NodeType.ERBS.toString())).afterFlow(resetDataSource(ADDED_NODES_WITH_CERT_REISSUE))
                .addTestStep(annotatedMethod(certificateIssueTestSteps, CertificateIssueTestSteps.CERTIFICATE_GET_BEFORE))
                .addTestStep(annotatedMethod(certificateReissueTestSteps, testStepName)).addTestStep(
                        annotatedMethod(jobIdMonitorTestSteps, JobIdMonitorTestSteps.JOB_ID_MONITOR_CERT_ISSUE)
                                .withParameter(ADDED_NODES, fromTestStepResult(testStepName)))
                .addTestStep(annotatedMethod(certificateIssueTestSteps, CertificateIssueTestSteps.CERTIFICATE_GET_AFTER)).addTestStep(
                        annotatedMethod(certificateIssueTestSteps, CertificateIssueTestSteps.CERTIFICATE_VERIFY)
                                .withParameter(ENROLL_STATE_BEFORE, fromTestStepResult(CertificateIssueTestSteps.CERTIFICATE_GET_BEFORE))
                                .withParameter(ENROLL_STATE_AFTER, fromTestStepResult(CertificateIssueTestSteps.CERTIFICATE_GET_AFTER)))
                .withDataSources(dataSource(ADDED_NODES_WITH_CERT_REISSUE).withFilter(predicate).bindTo(ADDED_NODES));
    }

    /**
     * Start certificate reissue command with cert type parameter.
     *
     * @return TestStepFlowBuilder
     */
    public TestStepFlowBuilder certificateReissueCertType() {
        return flow("Certificate Reissue Negative Flow with cert type").beforeFlow(
                addNodeTypeToDataSource(CERTIFICATE_REISSUE_NEGATIVE_TESTS_CSV, CERTIFICATE_REISSUE_NEGATIVE_TESTS, ADDED_NODES_WITH_CERT_REISSUE,
                        NodeType.ERBS.toString())).afterFlow(resetDataSource(ADDED_NODES_WITH_CERT_REISSUE))
                .addTestStep(annotatedMethod(certificateReissueTestSteps, CertificateReissueTestSteps.CERT_REISSUE_CERT_TYPE))
                .withDataSources(dataSource(ADDED_NODES_WITH_CERT_REISSUE).withFilter(PredicatesExt.testByCertType).bindTo(ADDED_NODES));
    }

    /**
     * Start certificate reissue command with cert type and ca name parameters.
     *
     * @return TestStepFlowBuilder
     */
    public TestStepFlowBuilder certificateReissueCaName() {
        return flow("Certificate Reissue Negative Flow with cert type and ca name").beforeFlow(
                addNodeTypeToDataSource(CERTIFICATE_REISSUE_NEGATIVE_TESTS_CSV, CERTIFICATE_REISSUE_NEGATIVE_TESTS, ADDED_NODES_WITH_CERT_REISSUE,
                        NodeType.ERBS.toString())).afterFlow(resetDataSource(ADDED_NODES_WITH_CERT_REISSUE))
                .addTestStep(annotatedMethod(certificateReissueTestSteps, CertificateReissueTestSteps.CERT_REISSUE_CA_NAME))
                .withDataSources(dataSource(ADDED_NODES_WITH_CERT_REISSUE).withFilter(PredicatesExt.testByCA).bindTo(ADDED_NODES));
    }
}
