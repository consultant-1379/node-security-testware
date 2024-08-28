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

import static com.ericsson.cifwk.taf.datasource.TafDataSources.fromCsv;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.annotatedMethod;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.dataSource;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.flow;
import static com.ericsson.nms.security.nscs.constants.CsvDataSourceConstants.NETSIM_PATCHES_CSV;
import static com.ericsson.nms.security.nscs.constants.CsvDataSourceConstants.NETSIM_TESTS;
import static com.ericsson.nms.security.nscs.datasource.PredicatesExt.buildNetsimObjectsIpsec;
import static com.ericsson.nms.security.nscs.datasource.PredicatesExt.buildNetsimObjectsRadioNode;
import static com.ericsson.nms.security.nscs.teststep.NetSimTestStep.ERBS_NODE_CONFIGURATION_STEP;
import static com.ericsson.nms.security.nscs.teststep.NetSimTestStep.INSTALL_PATCHES_DOWNLOAD_SCRIPT_STEP;
import static com.ericsson.nms.security.nscs.teststep.NetSimTestStep.INSTALL_PATCHES_REMOVE_SCRIPT_STEP;
import static com.ericsson.nms.security.nscs.teststep.NetSimTestStep.INSTALL_PATCHES_STEP;
import static com.ericsson.nms.security.nscs.teststep.NetSimTestStep.RADIO_NODE_CONFIGURATION_STEP;
import static com.ericsson.nms.security.nscs.teststep.NetSimTestStep.START_NODE_STEP;
import static com.ericsson.nms.security.nscs.teststep.NetSimTestStep.STOP_NODE_STEP;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.ADDED_NODES;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.NODES_TO_ADD;

import javax.inject.Inject;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.cifwk.taf.datasource.DataRecord;
import com.ericsson.cifwk.taf.scenario.api.TestStepFlowBuilder;
import com.ericsson.nms.security.nscs.datasource.PredicatesExt;
import com.ericsson.nms.security.nscs.teststep.NetSimTestStep;
import com.ericsson.nms.security.nscs.utils.Utils;
import com.google.common.base.Predicate;

/**
 * Flows for Netsim start/stop/patch the node.
 */
@SuppressWarnings({"PMD.LawOfDemeter", "PMD.DoNotUseThreads"})
public class NetSimFlow extends BaseFlow {

    private static final Logger log = LoggerFactory.getLogger(NetSimFlow.class);

    @Inject
    private NetSimTestStep netsimTestStep;

    /**
     * Start the node.
     *
     * @return TestStepFlowBuilder
     */
    public TestStepFlowBuilder startNode() {
        return flow("NetSim Start Node").addTestStep(annotatedMethod(netsimTestStep, START_NODE_STEP))
                .withDataSources(dataSource(ADDED_NODES).withFilter(PredicatesExt.nodesToStart));
    }

    /**
     * Stop the node.
     *
     * @return TestStepFlowBuilder
     */
    public TestStepFlowBuilder stopNode(final Predicate<DataRecord> predicate) {
        return flow("NetSim Stop Node").addTestStep(annotatedMethod(netsimTestStep, STOP_NODE_STEP))
                .withDataSources(dataSource(ADDED_NODES).withFilter(predicate));
    }

    /**
     * Add patch to Netsim.
     *
     * @return TestStepFlowBuilder
     */
    public TestStepFlowBuilder addPatch() {
        return flow("NetSim add patches").beforeFlow(addNetsimDataSource())
                .addTestStep(annotatedMethod(netsimTestStep, INSTALL_PATCHES_DOWNLOAD_SCRIPT_STEP))
                .addTestStep(annotatedMethod(netsimTestStep, INSTALL_PATCHES_STEP))
                .addTestStep(annotatedMethod(netsimTestStep, INSTALL_PATCHES_REMOVE_SCRIPT_STEP)).withDataSources(dataSource(NETSIM_TESTS));
    }

    /**
     * Create objects for RadioNode node.
     *
     * @return TestStepFlowBuilder
     */
    public TestStepFlowBuilder radioNode() {
        return flow("NetSim Radio Node configuration").addTestStep(annotatedMethod(netsimTestStep, RADIO_NODE_CONFIGURATION_STEP))
                .withDataSources(dataSource(ADDED_NODES).withFilter(buildNetsimObjectsRadioNode));
    }

    /**
     * Create objects for ERBS node.
     *
     * @return TestStepFlowBuilder
     */
    public TestStepFlowBuilder erbsNode() {
        return flow("NetSim Erbs Node configuration").addTestStep(annotatedMethod(netsimTestStep, ERBS_NODE_CONFIGURATION_STEP))
                .withDataSources(dataSource(NODES_TO_ADD).withFilter(buildNetsimObjectsIpsec));
    }

    private Runnable addNetsimDataSource() {
        return new Runnable() {
            @Override
            public void run() {
                final String sourcePath = Utils.getSourcePath();
                log.debug("addNetsimDataSource... loading csv [{}]", sourcePath + NETSIM_PATCHES_CSV);
                context.addDataSource(NETSIM_TESTS, fromCsv(sourcePath + NETSIM_PATCHES_CSV));
            }
        };
    }
}
