package com.ericsson.nms.security.nscs.flow;

import static com.ericsson.cifwk.taf.scenario.TestScenarios.annotatedMethod;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.dataSource;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.flow;
import static com.ericsson.nms.security.nscs.constants.CsvDataSourceConstants.JOB_ID_TRUST_DISTRIBUTE_TESTS;
import static com.ericsson.nms.security.nscs.constants.CsvDataSourceConstants.JOB_ID_TRUST_DISTRIBUTE_TESTS_CSV;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.ADDED_NODES;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.NODES_TO_ADD;
import static com.ericsson.oss.testware.nodesecurity.flows.TrustDistributeFlow.TRUST_DELAY;

import java.util.concurrent.TimeUnit;
import javax.inject.Inject;

import com.ericsson.cifwk.taf.scenario.api.TestStepFlowBuilder;
import com.ericsson.nms.security.nscs.datasource.PredicatesExt;
import com.ericsson.nms.security.nscs.teststep.JobIdTrustDistributionTestSteps;
import com.ericsson.oss.testware.enmbase.data.NodeType;
import com.ericsson.oss.testware.nodeintegration.teststeps.NodeIntegrationTestSteps;

/**
 * A TAF flow class to perform Job Id for Trust Distribute command
 *
 * @version 1.15, 04 October 2016
 */
@SuppressWarnings({"PMD.LawOfDemeter"})
public class JobIdForTrustDistributeFlow extends BaseFlow {

    public static final String ADDED_NODES_WITH_TRUST_DISTRIBUTE = "addedNodesWithTrustDistribute";

    @Inject
    private NodeIntegrationTestSteps nodeIntegrationTestSteps;
    @Inject
    private JobIdTrustDistributionTestSteps jobIdTrustDistributionTestSteps;

    /**
     * Trust Distribute <b>positive</b> flow for ERBS node type. <br/>
     * <br/>
     * It performs the following test steps:
     * <ol>
     * <li>enable alarm supervision on the node</li>
     * <li>check if the node is synchronized</li>
     * <li>start "trust remove" with TrustDistributeForJobIdTests.csv</li>
     * </ol>
     *
     * @return TestStepFlowBuilder
     */
    public TestStepFlowBuilder jobIdForTrustDistributeErbs() {
        return flow("Job Id for Trust Distribute command for ERBS node").beforeFlow(
                addNodeTypeToDataSource(JOB_ID_TRUST_DISTRIBUTE_TESTS_CSV, JOB_ID_TRUST_DISTRIBUTE_TESTS, ADDED_NODES_WITH_TRUST_DISTRIBUTE,
                        NodeType.ERBS.toString())).afterFlow(resetDataSource(ADDED_NODES_WITH_TRUST_DISTRIBUTE))
                .addTestStep(annotatedMethod(nodeIntegrationTestSteps, NodeIntegrationTestSteps.CONFIRM_NODE_SYNCED))
                .addTestStep(annotatedMethod(jobIdTrustDistributionTestSteps, JobIdTrustDistributionTestSteps.TRUST_DISTRIBUTE))
                .pause(TRUST_DELAY, TimeUnit.SECONDS).withDataSources(
                        dataSource(ADDED_NODES_WITH_TRUST_DISTRIBUTE).withFilter(PredicatesExt.trustDistrCT).bindTo(NODES_TO_ADD)
                                .inTestStep(NodeIntegrationTestSteps.CONFIRM_NODE_SYNCED),
                        dataSource(ADDED_NODES_WITH_TRUST_DISTRIBUTE).withFilter(PredicatesExt.trustDistrCT).bindTo(ADDED_NODES)
                                .inTestStep(JobIdTrustDistributionTestSteps.TRUST_DISTRIBUTE));
    }
}