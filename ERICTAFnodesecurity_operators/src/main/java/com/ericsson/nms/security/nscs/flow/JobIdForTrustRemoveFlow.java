/*
 * ------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2016
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------
 */

package com.ericsson.nms.security.nscs.flow;

import static com.ericsson.cifwk.taf.scenario.TestScenarios.annotatedMethod;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.dataSource;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.flow;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.fromTestStepResult;
import static com.ericsson.nms.security.nscs.constants.CsvDataSourceConstants.JOB_ID_TRUST_REMOVE_TESTS;
import static com.ericsson.nms.security.nscs.constants.CsvDataSourceConstants.JOB_ID_TRUST_REMOVE_TESTS_CSV;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.ADDED_NODES;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.NODES_TO_ADD;
import static com.ericsson.oss.testware.nodesecurity.flows.TrustDistributeFlow.TRUST_DELAY;

import java.util.concurrent.TimeUnit;
import javax.inject.Inject;

import com.ericsson.cifwk.taf.scenario.api.TestStepFlowBuilder;
import com.ericsson.nms.security.nscs.datasource.PredicatesExt;
import com.ericsson.nms.security.nscs.teststep.JobIdSpecificTrustRemoveTestSteps;
import com.ericsson.oss.testware.enmbase.data.NodeType;
import com.ericsson.oss.testware.nodeintegration.teststeps.NodeIntegrationTestSteps;
import com.ericsson.oss.testware.nodesecurity.steps.TrustDistributeTestSteps;

/**
 * A TAF flow class to perform Job Id for Trust Remove command
 *
 * @author The16thFloor
 * @version 1.15, 04 October 2016
 */
@SuppressWarnings({"PMD.LawOfDemeter"})
public class JobIdForTrustRemoveFlow extends BaseFlow {

    public static final String ADDED_NODES_WITH_TRUST_REMOVE = "addedNodesWithTrustRemove";

    @Inject
    private JobIdSpecificTrustRemoveTestSteps jobIdSpecificTrustRemoveTestSteps;
    @Inject
    private NodeIntegrationTestSteps nodeIntegrationTestSteps;
    @Inject
    private TrustDistributeTestSteps trustDistributeTestSteps;

    /**
     * Trust Remove <b>positive</b> flow for ERBS node type. <br/>
     * <br/>
     * It performs the following test steps:
     * <ol>
     * <li>enable alarm supervision on the node</li>
     * <li>check if the node is synchronized</li>
     * <li>start "trust remove" with TrustRemoveForJobIdTests.csv</li>
     * </ol>
     *
     * @return TestStepFlowBuilder
     */
    public TestStepFlowBuilder jobIdForTrustRemoveERBS() {
        return flow("Job Id for OAM/IPSEC Trust Remove command for ERBS node").beforeFlow(
                addNodeTypeToDataSource(JOB_ID_TRUST_REMOVE_TESTS_CSV, JOB_ID_TRUST_REMOVE_TESTS, ADDED_NODES_WITH_TRUST_REMOVE,
                        NodeType.ERBS.toString())).afterFlow(resetDataSource(ADDED_NODES_WITH_TRUST_REMOVE))
                .addTestStep(annotatedMethod(nodeIntegrationTestSteps, NodeIntegrationTestSteps.CONFIRM_NODE_SYNCED))
                .addTestStep(annotatedMethod(trustDistributeTestSteps, TrustDistributeTestSteps.TRUST_DISTRIBUTE_CERT_TYPE))
                .pause(TRUST_DELAY, TimeUnit.SECONDS)
                .addTestStep(annotatedMethod(trustDistributeTestSteps, TrustDistributeTestSteps.TRUST_LIST_GET))
                .addTestStep(annotatedMethod(jobIdSpecificTrustRemoveTestSteps, JobIdSpecificTrustRemoveTestSteps.TRUST_REMOVE_WITH_JOB_ID)
                        .withParameter(ADDED_NODES, fromTestStepResult(TrustDistributeTestSteps.TRUST_LIST_GET)))
                .pause(TRUST_DELAY, TimeUnit.SECONDS)
                .withDataSources(dataSource(ADDED_NODES_WITH_TRUST_REMOVE).withFilter(PredicatesExt.trustDistrCT).bindTo(NODES_TO_ADD)
                                .inTestStep(NodeIntegrationTestSteps.CONFIRM_NODE_SYNCED),
                        dataSource(ADDED_NODES_WITH_TRUST_REMOVE).withFilter(PredicatesExt.trustDistrCT).bindTo(ADDED_NODES)
                                .inTestStep(TrustDistributeTestSteps.TRUST_DISTRIBUTE_CERT_TYPE),
                        dataSource(ADDED_NODES_WITH_TRUST_REMOVE)
                                .withFilter(PredicatesExt.trustDistrCT).bindTo(ADDED_NODES)
                                .inTestStep(TrustDistributeTestSteps.TRUST_LIST_GET));
    }
}