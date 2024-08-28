package com.ericsson.nms.security.nscs.flow;

import static com.ericsson.cifwk.taf.scenario.TestScenarios.annotatedMethod;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.dataSource;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.flow;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.fromTestStepResult;
import static com.ericsson.nms.security.nscs.constants.CsvDataSourceConstants.TRUST_DISTRIBUTE_POSITIVE_TESTS;
import static com.ericsson.nms.security.nscs.constants.CsvDataSourceConstants.TRUST_DISTRIBUTE_POSITIVE_TESTS_CSV;
import static com.ericsson.nms.security.nscs.constants.CsvDataSourceConstants.TRUST_REMOVE_NEGATIVE_TESTS;
import static com.ericsson.nms.security.nscs.constants.CsvDataSourceConstants.TRUST_REMOVE_NEGATIVE_TESTS_CSV;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.ADDED_NODES;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.NODES_TO_ADD;

import javax.inject.Inject;

import com.ericsson.cifwk.taf.scenario.TestStepFlow;
import com.ericsson.cifwk.taf.scenario.api.TestStepFlowBuilder;
import com.ericsson.nms.security.nscs.datasource.PredicatesExt;
import com.ericsson.nms.security.nscs.teststep.GenericTestSteps;
import com.ericsson.oss.testware.enmbase.data.NodeType;
import com.ericsson.oss.testware.nodeintegration.teststeps.NodeIntegrationTestSteps;
import com.ericsson.oss.testware.nodesecurity.steps.JobIdMonitorTestSteps;
import com.ericsson.oss.testware.nodesecurity.steps.TrustDistributeTestSteps;
import com.ericsson.oss.testware.nodesecurity.steps.TrustRemoveTestSteps;

/**
 * Flows for trust remove command.
 */
@SuppressWarnings({"PMD.LawOfDemeter"})
public class TrustRemoveFlow extends BaseFlow {

    private static final String ADDED_NODES_WITH_TRUST_DISTR = "addedNodesWithTrustDistr";

    @Inject
    private TrustDistributeTestSteps trustDistributeTestSteps;
    @Inject
    private TrustRemoveTestSteps trustRemoveTestSteps;
    @Inject
    private JobIdMonitorTestSteps jobIdMonitorTestSteps;
    @Inject
    private NodeIntegrationTestSteps nodeIntegrationTestSteps;
    @Inject
    private GenericTestSteps genericTestSteps;

    // TODO remove method
    /**
     * Get the number of trusts installed on the node. Start trust remove command with issuer dn parameter. Check the number of trusts are removed
     * from the node.
     *
     * @return TestStepFlow
     */
    public TestStepFlow trustRemoveIsdn() {
        return flow("Trust Remove with issuer dn").beforeFlow(
                addNodeTypeToDataSource(TRUST_DISTRIBUTE_POSITIVE_TESTS_CSV, TRUST_DISTRIBUTE_POSITIVE_TESTS, ADDED_NODES_WITH_TRUST_DISTR,
                        NodeType.ERBS.toString())).afterFlow(resetDataSource(ADDED_NODES_WITH_TRUST_DISTR))
                .addTestStep(annotatedMethod(nodeIntegrationTestSteps, NodeIntegrationTestSteps.CONFIRM_NODE_SYNCED))
                .addTestStep(annotatedMethod(trustDistributeTestSteps, TrustDistributeTestSteps.TRUST_GET)).addTestStep(
                        annotatedMethod(trustRemoveTestSteps, TrustRemoveTestSteps.TRUST_REMOVE_ISDN_LIST)
                                .withParameter(ADDED_NODES, fromTestStepResult(TrustDistributeTestSteps.TRUST_GET))).addTestStep(
                        annotatedMethod(jobIdMonitorTestSteps, JobIdMonitorTestSteps.JOB_ID_MONITOR_LIST)
                                .withParameter(ADDED_NODES, fromTestStepResult(TrustRemoveTestSteps.TRUST_REMOVE_ISDN_LIST)))
                .addTestStep(annotatedMethod(trustRemoveTestSteps, TrustRemoveTestSteps.TRUST_REMOVE_VERIFY)).withDataSources(
                        dataSource(ADDED_NODES_WITH_TRUST_DISTR).withFilter(PredicatesExt.trustDistrCT).bindTo(NODES_TO_ADD)
                                .inTestStep(NodeIntegrationTestSteps.CONFIRM_NODE_SYNCED),
                        dataSource(ADDED_NODES_WITH_TRUST_DISTR).withFilter(PredicatesExt.trustDistrCT).bindTo(ADDED_NODES)
                                .inTestStep(TrustDistributeTestSteps.TRUST_GET),
                        dataSource(ADDED_NODES_WITH_TRUST_DISTR).withFilter(PredicatesExt.trustDistrCT).bindTo(ADDED_NODES)
                                .inTestStep(TrustRemoveTestSteps.TRUST_REMOVE_VERIFY)).build();
    }

    // TODO remove method
    /**
     * Get the number of trusts installed on the node. Start trust remove command with ca name parameter. Check the number of trusts are removed from
     * the node.
     *
     * @return TestStepFlow
     */
    public TestStepFlow trustRemoveCaName() {
        return flow("Trust Remove with ca name").beforeFlow(
                addNodeTypeToDataSource(TRUST_DISTRIBUTE_POSITIVE_TESTS_CSV, TRUST_DISTRIBUTE_POSITIVE_TESTS, ADDED_NODES_WITH_TRUST_DISTR,
                        NodeType.ERBS.toString())).afterFlow(resetDataSource(ADDED_NODES_WITH_TRUST_DISTR))
                .addTestStep(annotatedMethod(nodeIntegrationTestSteps, NodeIntegrationTestSteps.CONFIRM_NODE_SYNCED))
                .addTestStep(annotatedMethod(trustDistributeTestSteps, TrustDistributeTestSteps.TRUST_GET)).addTestStep(
                        annotatedMethod(trustRemoveTestSteps, TrustRemoveTestSteps.TRUST_REMOVE_CA_NAME_LIST)
                                .withParameter(ADDED_NODES, fromTestStepResult(TrustDistributeTestSteps.TRUST_GET))).addTestStep(
                        annotatedMethod(jobIdMonitorTestSteps, JobIdMonitorTestSteps.JOB_ID_MONITOR_LIST)
                                .withParameter(ADDED_NODES, fromTestStepResult(TrustRemoveTestSteps.TRUST_REMOVE_CA_NAME_LIST)))
                .addTestStep(annotatedMethod(trustRemoveTestSteps, TrustRemoveTestSteps.TRUST_REMOVE_VERIFY)).withDataSources(
                        dataSource(ADDED_NODES_WITH_TRUST_DISTR).withFilter(PredicatesExt.trustDistrCA).bindTo(NODES_TO_ADD)
                                .inTestStep(NodeIntegrationTestSteps.CONFIRM_NODE_SYNCED),
                        dataSource(ADDED_NODES_WITH_TRUST_DISTR).withFilter(PredicatesExt.trustDistrCA).bindTo(ADDED_NODES)
                                .inTestStep(TrustDistributeTestSteps.TRUST_GET),
                        dataSource(ADDED_NODES_WITH_TRUST_DISTR).withFilter(PredicatesExt.trustDistrCA).bindTo(ADDED_NODES)
                                .inTestStep(TrustRemoveTestSteps.TRUST_REMOVE_VERIFY)).build();
    }

    /**
     * Start trust remove with issuer dn parameter.
     *
     * @return TestStepFlowBuilder
     */
    public TestStepFlowBuilder trustRemoveByIsdnNegative() {
        return flow("Trust Remove By Isdn Negative Flow").beforeFlow(
                addNodeTypeToDataSource(TRUST_REMOVE_NEGATIVE_TESTS_CSV, TRUST_REMOVE_NEGATIVE_TESTS, ADDED_NODES_WITH_TRUST_DISTR,
                        NodeType.ERBS.toString())).afterFlow(resetDataSource(ADDED_NODES_WITH_TRUST_DISTR))
                .addTestStep(annotatedMethod(genericTestSteps, GenericTestSteps.CHECK_SYNC))
                .addTestStep(annotatedMethod(trustRemoveTestSteps, TrustRemoveTestSteps.TRUST_REMOVE_ISDN))
                .withDataSources(dataSource(ADDED_NODES_WITH_TRUST_DISTR).withFilter(PredicatesExt.testByCertType).bindTo(ADDED_NODES));
    }

    /**
     * Start trust remove with ca name parameter.
     *
     * @return TestStepFlowBuilder
     */
    public TestStepFlowBuilder trustRemoveByCANegative() {
        return flow("Trust Remove By CA Negative Flow").beforeFlow(
                addNodeTypeToDataSource(TRUST_REMOVE_NEGATIVE_TESTS_CSV, TRUST_REMOVE_NEGATIVE_TESTS, ADDED_NODES_WITH_TRUST_DISTR,
                        NodeType.ERBS.toString())).afterFlow(resetDataSource(ADDED_NODES_WITH_TRUST_DISTR))
                .addTestStep(annotatedMethod(genericTestSteps, GenericTestSteps.CHECK_SYNC))
                .addTestStep(annotatedMethod(trustRemoveTestSteps, TrustRemoveTestSteps.TRUST_REMOVE_CA_NAME))
                .withDataSources(dataSource(ADDED_NODES_WITH_TRUST_DISTR).withFilter(PredicatesExt.testByCA).bindTo(ADDED_NODES));
    }
}
