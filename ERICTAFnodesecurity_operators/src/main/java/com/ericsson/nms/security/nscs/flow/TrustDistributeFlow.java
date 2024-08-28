package com.ericsson.nms.security.nscs.flow;

import static com.ericsson.cifwk.taf.scenario.TestScenarios.annotatedMethod;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.dataSource;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.flow;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.fromTestStepResult;
import static com.ericsson.nms.security.nscs.constants.CsvDataSourceConstants.TRUST_DISTRIBUTE_NEGATIVE_TESTS;
import static com.ericsson.nms.security.nscs.constants.CsvDataSourceConstants.TRUST_DISTRIBUTE_NEGATIVE_TESTS_CSV;
import static com.ericsson.nms.security.nscs.constants.CsvDataSourceConstants.TRUST_DISTRIBUTE_POSITIVE_TESTS;
import static com.ericsson.nms.security.nscs.constants.CsvDataSourceConstants.TRUST_DISTRIBUTE_POSITIVE_TESTS_CSV;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.ADDED_NODES;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.NODES_TO_ADD;

import javax.inject.Inject;

import com.ericsson.cifwk.taf.scenario.TestStepFlow;
import com.ericsson.cifwk.taf.scenario.api.TestStepFlowBuilder;
import com.ericsson.nms.security.nscs.datasource.PredicatesExt;
import com.ericsson.oss.testware.enmbase.data.NodeType;
import com.ericsson.oss.testware.nodeintegration.teststeps.NodeIntegrationTestSteps;
import com.ericsson.oss.testware.nodesecurity.steps.CredentialTestSteps;
import com.ericsson.oss.testware.nodesecurity.steps.JobIdMonitorTestSteps;
import com.ericsson.oss.testware.nodesecurity.steps.TrustDistributeTestSteps;

/**
 * Flows for trust distribute command.
 */
@SuppressWarnings({"PMD.LawOfDemeter"})
public class TrustDistributeFlow extends BaseFlow {

    private static final String ADDED_NODES_WITH_TRUST_DISTR = "addedNodesWithTrustDistr";

    @Inject
    private CredentialTestSteps credentialTestSteps;
    @Inject
    private TrustDistributeTestSteps trustDistributeTestSteps;
    @Inject
    private JobIdMonitorTestSteps jobIdMonitorTestSteps;
    @Inject
    private NodeIntegrationTestSteps nodeIntegrationTestSteps;

    /**
     * Credentials delete/create on the node. Start trust distribute command with cert type parameter. Check the trusts are installed on the node.
     *
     * @return TestStepFlow
     */
    public TestStepFlow trustDistributeCertType() {
        return flow("Trust Distribute with cert type").beforeFlow(
                addNodeTypeToDataSource(TRUST_DISTRIBUTE_POSITIVE_TESTS_CSV, TRUST_DISTRIBUTE_POSITIVE_TESTS, ADDED_NODES_WITH_TRUST_DISTR,
                        NodeType.ERBS.toString())).afterFlow(resetDataSource(ADDED_NODES_WITH_TRUST_DISTR))
                .addTestStep(annotatedMethod(nodeIntegrationTestSteps, NodeIntegrationTestSteps.CONFIRM_NODE_SYNCED))
                .addTestStep(annotatedMethod(credentialTestSteps, CredentialTestSteps.DELETE_SECURITY_INFO))
                .addTestStep(annotatedMethod(credentialTestSteps, CredentialTestSteps.CRED_CREATE))
                .addTestStep(annotatedMethod(trustDistributeTestSteps, TrustDistributeTestSteps.TRUST_DISTRIBUTE_CERT_TYPE)).addTestStep(
                        annotatedMethod(jobIdMonitorTestSteps, JobIdMonitorTestSteps.JOB_ID_MONITOR)
                                .withParameter(ADDED_NODES, fromTestStepResult(TrustDistributeTestSteps.TRUST_DISTRIBUTE_CERT_TYPE)))
                .addTestStep(annotatedMethod(trustDistributeTestSteps, TrustDistributeTestSteps.TRUST_GET_VERIFY)).withDataSources(
                        dataSource(ADDED_NODES_WITH_TRUST_DISTR).withFilter(PredicatesExt.trustDistrCT).bindTo(NODES_TO_ADD)
                                .inTestStep(NodeIntegrationTestSteps.CONFIRM_NODE_SYNCED),
                        dataSource(ADDED_NODES_WITH_TRUST_DISTR).withFilter(PredicatesExt.trustDistrCT).bindTo(ADDED_NODES)
                                .inTestStep(CredentialTestSteps.DELETE_SECURITY_INFO),
                        dataSource(ADDED_NODES_WITH_TRUST_DISTR).withFilter(PredicatesExt.trustDistrCT).bindTo(ADDED_NODES)
                                .inTestStep(CredentialTestSteps.CRED_CREATE),
                        dataSource(ADDED_NODES_WITH_TRUST_DISTR).withFilter(PredicatesExt.trustDistrCT).bindTo(ADDED_NODES)
                                .inTestStep(TrustDistributeTestSteps.TRUST_DISTRIBUTE_CERT_TYPE),
                        dataSource(ADDED_NODES_WITH_TRUST_DISTR).withFilter(PredicatesExt.trustDistrCT).bindTo(ADDED_NODES)
                                .inTestStep(TrustDistributeTestSteps.TRUST_GET_VERIFY)).build();
    }

    // TODO remove method
    /**
     * Credentials delete/create on the node. Start trust distribute command with ca name parameter. Check the trusts are installed on the node.
     *
     * @return TestStepFlow
     */
    public TestStepFlow trustDistributeCaName() {
        return flow("Trust Distribute with cert type and ca name").beforeFlow(
                addNodeTypeToDataSource(TRUST_DISTRIBUTE_POSITIVE_TESTS_CSV, TRUST_DISTRIBUTE_POSITIVE_TESTS, ADDED_NODES_WITH_TRUST_DISTR,
                        NodeType.ERBS.toString())).afterFlow(resetDataSource(ADDED_NODES_WITH_TRUST_DISTR))
                .addTestStep(annotatedMethod(nodeIntegrationTestSteps, NodeIntegrationTestSteps.CONFIRM_NODE_SYNCED))
                .addTestStep(annotatedMethod(credentialTestSteps, CredentialTestSteps.DELETE_SECURITY_INFO))
                .addTestStep(annotatedMethod(credentialTestSteps, CredentialTestSteps.CRED_CREATE))
                .addTestStep(annotatedMethod(trustDistributeTestSteps, TrustDistributeTestSteps.TRUST_DISTRIBUTE_CA_NAME)).addTestStep(
                        annotatedMethod(jobIdMonitorTestSteps, JobIdMonitorTestSteps.JOB_ID_MONITOR)
                                .withParameter(ADDED_NODES, fromTestStepResult(TrustDistributeTestSteps.TRUST_DISTRIBUTE_CA_NAME)))
                .addTestStep(annotatedMethod(trustDistributeTestSteps, TrustDistributeTestSteps.TRUST_GET_VERIFY)).withDataSources(
                        dataSource(ADDED_NODES_WITH_TRUST_DISTR).withFilter(PredicatesExt.trustDistrCA).bindTo(NODES_TO_ADD)
                                .inTestStep(NodeIntegrationTestSteps.CONFIRM_NODE_SYNCED),
                        dataSource(ADDED_NODES_WITH_TRUST_DISTR).withFilter(PredicatesExt.trustDistrCA).bindTo(ADDED_NODES)
                                .inTestStep(CredentialTestSteps.DELETE_SECURITY_INFO),
                        dataSource(ADDED_NODES_WITH_TRUST_DISTR).withFilter(PredicatesExt.trustDistrCA).bindTo(ADDED_NODES)
                                .inTestStep(CredentialTestSteps.CRED_CREATE),
                        dataSource(ADDED_NODES_WITH_TRUST_DISTR).withFilter(PredicatesExt.trustDistrCA).bindTo(ADDED_NODES)
                                .inTestStep(TrustDistributeTestSteps.TRUST_DISTRIBUTE_CA_NAME),
                        dataSource(ADDED_NODES_WITH_TRUST_DISTR).withFilter(PredicatesExt.trustDistrCA).bindTo(ADDED_NODES)
                                .inTestStep(TrustDistributeTestSteps.TRUST_GET_VERIFY)).build();
    }

    /**
     * Starts trust distribute with cert type parameter.
     *
     * @return TestStepFlowBuilder
     */
    public TestStepFlowBuilder trustDistributeCertTypeNegative() {
        return flow("Trust Distribute negative with cert type").beforeFlow(
                addNodeTypeToDataSource(TRUST_DISTRIBUTE_NEGATIVE_TESTS_CSV, TRUST_DISTRIBUTE_NEGATIVE_TESTS, ADDED_NODES_WITH_TRUST_DISTR,
                        NodeType.ERBS.toString())).afterFlow(resetDataSource(ADDED_NODES_WITH_TRUST_DISTR))
                .addTestStep(annotatedMethod(trustDistributeTestSteps, TrustDistributeTestSteps.TRUST_DISTRIBUTE_CERT_TYPE))
                .withDataSources(dataSource(ADDED_NODES_WITH_TRUST_DISTR).withFilter(PredicatesExt.testByCertType).bindTo(ADDED_NODES));
    }

    /**
     * Starts trust distribute with ca name parameter.
     *
     * @return TestStepFlowBuilder
     */
    public TestStepFlowBuilder trustDistributeCaNameNegative() {
        return flow("Trust Distribute negative with ca name").beforeFlow(
                addNodeTypeToDataSource(TRUST_DISTRIBUTE_NEGATIVE_TESTS_CSV, TRUST_DISTRIBUTE_NEGATIVE_TESTS, ADDED_NODES_WITH_TRUST_DISTR,
                        NodeType.ERBS.toString())).afterFlow(resetDataSource(ADDED_NODES_WITH_TRUST_DISTR))
                .addTestStep(annotatedMethod(trustDistributeTestSteps, TrustDistributeTestSteps.TRUST_DISTRIBUTE_CA_NAME))
                .withDataSources(dataSource(ADDED_NODES_WITH_TRUST_DISTR).withFilter(PredicatesExt.testByCA).bindTo(ADDED_NODES));
    }
}
