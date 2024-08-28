package com.ericsson.nms.security.nscs.flow;

import static com.ericsson.cifwk.taf.scenario.TestScenarios.annotatedMethod;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.dataSource;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.flow;
import static com.ericsson.nms.security.nscs.constants.CsvDataSourceConstants.JOB_ID_CERTIFICATE_ISSUE_TESTS;
import static com.ericsson.nms.security.nscs.constants.CsvDataSourceConstants.JOB_ID_CERTIFICATE_ISSUE_TESTS_CSV;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.ADDED_NODES;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.NODES_TO_ADD;

import javax.inject.Inject;

import com.ericsson.cifwk.taf.scenario.api.TestStepFlowBuilder;
import com.ericsson.nms.security.nscs.datasource.PredicatesExt;
import com.ericsson.nms.security.nscs.teststep.JobIdSpecificIssueTestSteps;
import com.ericsson.oss.testware.enmbase.data.NodeType;
import com.ericsson.oss.testware.nodeintegration.teststeps.NodeIntegrationTestSteps;

/**
 * A TAF flow class to perform Job Id for Certificate Issue command
 *
 * @author The16thFloor
 * @version 1.15, 22 September 2016
 */
@SuppressWarnings({"PMD.LawOfDemeter"})
public class JobIdForCertificateIssueFlow extends BaseFlow {

    public static final String ADDED_NODES_WITH_CERT_ISSUE = "addedNodesWithCertIssue";

    @Inject
    private JobIdSpecificIssueTestSteps jobIdCertIssueTestSteps;
    @Inject
    private NodeIntegrationTestSteps nodeIntegrationTestSteps;

    /**
     * Certificate Issue <b>positive</b> flow for ERBS node type. <br/>
     * <br/>
     * It performs the following test steps:
     * <ol>
     * <li>enable alarm supervision on the node</li>
     * <li>check if the node is synchronized</li>
     * <li>start "certificate issue" with CertificateIssuePositiveTests.csv</li>
     * </ol>
     *
     * @return TestStepFlowBuilder
     */
    public TestStepFlowBuilder jobIdForCertIssueERBS() {
        return flow("Job Id for OAM Certificate Issue command for ERBS node").beforeFlow(
                addNodeTypeToDataSource(JOB_ID_CERTIFICATE_ISSUE_TESTS_CSV, JOB_ID_CERTIFICATE_ISSUE_TESTS, ADDED_NODES_WITH_CERT_ISSUE,
                        NodeType.ERBS.toString())).afterFlow(resetDataSource(ADDED_NODES_WITH_CERT_ISSUE))
                .addTestStep(annotatedMethod(nodeIntegrationTestSteps, NodeIntegrationTestSteps.CONFIRM_NODE_SYNCED))
                .addTestStep(annotatedMethod(jobIdCertIssueTestSteps, JobIdSpecificIssueTestSteps.CERTIFICATE_ISSUE_WITH_JOB_ID)).withDataSources(
                        dataSource(ADDED_NODES_WITH_CERT_ISSUE).withFilter(PredicatesExt.certIssueByProfile).bindTo(NODES_TO_ADD)
                                .inTestStep(NodeIntegrationTestSteps.CONFIRM_NODE_SYNCED),
                        dataSource(ADDED_NODES_WITH_CERT_ISSUE).withFilter(PredicatesExt.certIssueByProfile).bindTo(ADDED_NODES)
                                .inTestStep(JobIdSpecificIssueTestSteps.CERTIFICATE_ISSUE_WITH_JOB_ID));
    }
}