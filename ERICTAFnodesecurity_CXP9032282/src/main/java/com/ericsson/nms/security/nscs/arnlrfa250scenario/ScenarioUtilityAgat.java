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

package com.ericsson.nms.security.nscs.arnlrfa250scenario;


import static com.ericsson.cifwk.taf.datasource.TafDataSources.shared;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.dataDrivenScenario;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.dataSource;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.flow;
import static com.ericsson.cifwk.taf.scenario.api.DataDrivenTestScenarioBuilder.TEST_CASE_ID;
import static com.ericsson.cifwk.taf.scenario.api.DataDrivenTestScenarioBuilder.TEST_CASE_TITLE;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.ADDED_NODES;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.AVAILABLE_USERS;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.NODES_TO_ADD;

import java.util.Iterator;
import java.util.concurrent.TimeUnit;
import javax.inject.Inject;

import com.ericsson.cifwk.taf.TafTestContext;
import com.ericsson.cifwk.taf.TestContext;
import com.ericsson.cifwk.taf.configuration.TafConfiguration;
import com.ericsson.cifwk.taf.data.DataHandler;
import com.ericsson.cifwk.taf.datasource.DataRecord;
import com.ericsson.cifwk.taf.datasource.TestDataSource;
import com.ericsson.cifwk.taf.datasource.TestDataSourceFactory;
import com.ericsson.cifwk.taf.scenario.TestScenario;
import com.ericsson.cifwk.taf.scenario.TestScenarioRunner;
import com.ericsson.cifwk.taf.scenario.api.TestStepFlowBuilder;
import com.ericsson.nms.security.nscs.scenario.ScenarioUtil;
import com.ericsson.oss.testware.hostconfigurator.HostConfigurator;
import com.ericsson.oss.testware.nodeintegration.flows.NodeIntegrationFlows;
import com.ericsson.oss.testware.nodesecurity.flows.CrlCheckFlows;
import com.ericsson.oss.testware.nodesecurity.steps.TrustDistributeTestSteps;
import com.google.common.collect.Iterables;

/**
 * ScenarioUtil contains base scenario utilities.
 */
@SuppressWarnings({ "PMD.LawOfDemeter" })
public class ScenarioUtilityAgat extends ScenarioUtility {

    protected static final String INPUT_DATASOURCE_OAM = INPUT_DATASOURCE + "_OAM";
    protected static final String INPUT_DATASOURCE_IPSEC = INPUT_DATASOURCE + "_IPSEC";
    protected static final Boolean NSCS_LOGS_COLLECT = DataHandler.getConfiguration().getProperty("nscs.logs.collect", false, Boolean.class);
    public static final Boolean SL2_LOGS_COLLECT = DataHandler.getConfiguration().getProperty("sl2.logs.collect", false, Boolean.class);
    protected static final Integer LOG_PARALLEL_MANAGEMENT = DataHandler.getConfiguration().getProperty("log.parallel.management", 5, Integer.class);
    @Inject
    protected NodeIntegrationFlows nodeIntegrationFlows;
    @Inject
    protected CrlCheckFlows crLCheckFlows;

    public static void dataDrivenDataSource(final String dataSourceNew, final String testId, final String testName,
            final Iterable<? extends DataRecord> values) {
        dataDrivenDataSource(dataSourceNew, testId, testName, values, false);
    }

    public static void dataDrivenDataSource(final String dataSourceNew, final String testId, final String testName,
            final Iterable<? extends DataRecord> values, final boolean addNodeInTitle) {
        final TestContext context = TafTestContext.getContext();
        final TestDataSource<DataRecord> valueNew = TestDataSourceFactory.createDataSource();
        for (final Iterator iterator = values.iterator(); iterator.hasNext(); ) {
            final DataRecord next = (DataRecord) iterator.next();
            valueNew.addRecord().setFields(next).setField(TEST_CASE_ID, testId).setField(TEST_CASE_TITLE,
                    testName + (addNodeInTitle ? " - " + next.getFieldValue("networkElementId") : ""));
        }
        ScenarioUtil.debugScope(LOGGER, valueNew);
        context.addDataSource(dataSourceNew, shared(valueNew));
    }

    public static void doParallelDifferentCommandsPerNodesBase(final String dataSourceNew, final String testId, final String testName,
            final Iterable<? extends DataRecord> commandsPerNode, final Iterable<? extends DataRecord>
            users, final int numOfNodes) {
        final TestContext context = TafTestContext.getContext();
        final TestDataSource<DataRecord> valueNew = TestDataSourceFactory.createDataSource();
        final DataRecord[] arrayUsers = Iterables.toArray(users, DataRecord.class);
        final DataRecord[] arrayCommandsPerNodes = Iterables.toArray(commandsPerNode, DataRecord.class);
        final int arrayCommandsSize = Iterables.size(commandsPerNode);
        final int arrayUsersSize = Iterables.size(users);
        if (arrayCommandsSize != 0 && arrayUsersSize != 0) {
            int u = 0;
            do {
                int cn = 0;
                do {
                    final DataRecord command = arrayCommandsPerNodes[cn];
                    final DataRecord user = arrayUsers[u];
                    valueNew.addRecord().setFields(user).setFields(command)
                            .setField(TEST_CASE_ID, testId).setField(TEST_CASE_TITLE, testName);
                    cn++;
                } while (cn < arrayCommandsSize);
                u = u + 1;
            } while (u < arrayUsersSize);
            ScenarioUtil.debugScope(LOGGER, valueNew);
        }
        context.addDataSource(dataSourceNew, shared(valueNew));
    }

    public static void doParallelNodesBase(final String dataSourceNew,
                                           final String testId,
                                           final String testName,
                                           final Iterable<? extends DataRecord> nodes,
                                           final Iterable<? extends DataRecord> users) {
        final TestContext context = TafTestContext.getContext();
        final TestDataSource<DataRecord> valueNew = TestDataSourceFactory.createDataSource();
        final DataRecord[] arrayUsers = Iterables.toArray(users, DataRecord.class);
        final DataRecord[] arrayNodes = Iterables.toArray(nodes, DataRecord.class);
        final int arrayUsersSize = Iterables.size(users);
        final int arrayNodesSize = Iterables.size(nodes);
        if (arrayUsersSize != 0 && arrayNodesSize != 0) {
            int u = 0;;
            do {
                int n = 0;
                do {
                    final DataRecord user = arrayUsers[u];
                    final DataRecord node = arrayNodes[n];
                    valueNew.addRecord().setFields(user).setFields(node)
                            .setField(TEST_CASE_ID, testId).setField(TEST_CASE_TITLE, testName);
                    n++;
                } while (n < arrayNodesSize);
                u = u + 1;
            } while (u < arrayUsersSize);
            ScenarioUtil.debugScope(LOGGER, valueNew);
        }
        context.addDataSource(dataSourceNew, shared(valueNew));
    }

    public static void doParallelNodesBase(final String dataSourceNew,
                                           final String testId,
                                           final String testName,
                                           final Iterable<? extends DataRecord> commands,
                                           final Iterable<? extends DataRecord> nodes,
                                           final Iterable<? extends DataRecord> users) {
        final TestContext context = TafTestContext.getContext();
        final TestDataSource<DataRecord> valueNew = TestDataSourceFactory.createDataSource();
        final DataRecord[] arrayCommands = Iterables.toArray(commands, DataRecord.class);
        final DataRecord[] arrayUsers = Iterables.toArray(users, DataRecord.class);
        final DataRecord[] arrayNodes = Iterables.toArray(nodes, DataRecord.class);
        //        "commands": e.g.:
        //        REISSUE_OAM:
        //        Data value: {caName=NE_OAM_CA, certType=OAM, fileName=null}
        final int arrayCommandsSize = Iterables.size(commands);
        final int arrayUsersSize = Iterables.size(users);
        final int arrayNodesSize = Iterables.size(nodes);
        if (arrayCommandsSize != 0 && arrayUsersSize != 0 && arrayNodesSize != 0) {
            int c = 0;
            do {
                int u = 0;
                do {
                    int n = 0;
                    do {
                        final DataRecord command = arrayCommands[c];
                        final DataRecord user = arrayUsers[u];
                        final DataRecord node = arrayNodes[n];
                        valueNew.addRecord().setFields(user).setFields(command).setFields(node)
                                .setField(TEST_CASE_ID, testId).setField(TEST_CASE_TITLE, testName);
                        n++;
                    } while (n < arrayNodesSize);
                    u = u + 1;
                } while (u < arrayUsersSize);
                c++;
            } while (c < arrayCommandsSize);
            ScenarioUtil.debugScope(LOGGER, valueNew);
        }
        context.addDataSource(dataSourceNew, shared(valueNew));
    }

    protected void scenarioBase(final String scenarioName, final String dataSource, final TestStepFlowBuilder flowName, final int vUsers) {
        final TestScenario scenario = dataDrivenScenario(scenarioName)
                .addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(utilityFlows.recursiveCheckSyncNodeStatusCmFm())
                .addFlow(flowName)
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(dataSource).allowEmpty().bindTo(AVAILABLE_USERS).bindTo(NODES_TO_ADD).bindTo(ADDED_NODES))
                .doParallel(vUsers).build();
        final TestScenarioRunner runner = SetupAndTearDownUtil.getScenarioRunner();
        runner.start(scenario);
    }

    protected void scenarioBaseTrust(final String scenarioName, final String dataSource, final TestStepFlowBuilder flowName, final int vUsers) {
        final TestScenario scenario = dataDrivenScenario(scenarioName)
                .addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(utilityFlows.recursiveCheckSyncNodeStatusCmFm())
                .addFlow(flowName)
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(dataSource).allowEmpty().bindTo(AVAILABLE_USERS).bindTo(NODES_TO_ADD).bindTo(ADDED_NODES)
                        .bindTo(TrustDistributeTestSteps.DataSource.TRUST_DATASOURCE))
                .doParallel(vUsers).build();
        final TestScenarioRunner runner = SetupAndTearDownUtil.getScenarioRunner();
        runner.start(scenario);
    }

    protected void trustDistributeRemoveScenario(final String scenarioName, final String dataSource, final TestStepFlowBuilder flowNameDistribute,
            final TestStepFlowBuilder flowNameRemove, final int vUsers) {
        final TestScenario scenario = dataDrivenScenario(scenarioName)
                .addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(utilityFlows.recursiveCheckSyncNodeStatusCmFm())
                .addFlow(flowNameDistribute)
                .addFlow(flowNameRemove)
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(dataSource).allowEmpty().bindTo(AVAILABLE_USERS).bindTo(NODES_TO_ADD).bindTo(ADDED_NODES)
                        .bindTo(TrustDistributeTestSteps.DataSource.TRUST_DATASOURCE))
                .doParallel(vUsers).build();
        final TestScenarioRunner runner = SetupAndTearDownUtil.getScenarioRunner();
        runner.start(scenario);
    }

    protected void scenarioBaseCrlCheck(final String scenarioName, final String dataSource, final boolean isCorrectUser,
            final TestStepFlowBuilder flowName,
            final int vUsers) {
        final TestScenario scenario = dataDrivenScenario(scenarioName)
                .addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(isCorrectUser ? utilityFlows.verifySyncNodes() : flow("").build())
                .addFlow(flowName)
                .addFlow(isCorrectUser ? flow("Wait").pause(300, TimeUnit.MILLISECONDS) : flow(""))
                .addFlow(isCorrectUser ? crLCheckFlows.getCrlCheckStatusFlowBase() : flow(""))
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(dataSource).allowEmpty().bindTo(AVAILABLE_USERS).bindTo(NODES_TO_ADD).bindTo(ADDED_NODES))
                .doParallel((vUsers != 0) ? vUsers : 1).build();
        final TestScenarioRunner runner = SetupAndTearDownUtil.getScenarioRunner();
        runner.start(scenario);
    }

    @Deprecated
    public void evaluateNSCSDumpcapLogCollection(final String scriptString, final String scenario) {
        if (NSCS_LOGS_COLLECT && SetupAndTeardownScenario.isRealNode()) {
            if (!HostConfigurator.isPhysicalEnvironment() && !HostConfigurator.isVirtualEnvironment()) {
                LOGGER.info("RNL cENM environment detected - skipping dumpcap log collection on nodes");
            } else {
                LOGGER.info(String.format("RNL environment detected - %s NSCS_LOGS_COLLECT = %s", scenario, String.valueOf(NSCS_LOGS_COLLECT)));
                enableDisableLogs(scriptString, scenario);
            }
        }
    }

    @Deprecated
    public void evaluateSl2DumpcapLogCollection(final String method, final String scriptString, final String suiteName) {
        if (SL2_LOGS_COLLECT && (method.equalsIgnoreCase("sl2Activation") || method.equalsIgnoreCase("sl2DeActivation"))) {
            if (!HostConfigurator.isPhysicalEnvironment() && !HostConfigurator.isVirtualEnvironment()) {
                LOGGER.info("RNL cENM environment detected - skipping dumpcap log collection on nodes");
            } else {
                final String name = suiteName.split(" -")[0] + "_" + method;
                LOGGER.info(String.format("RNL environment detected - %s SL2_LOGS_COLLECT = %s", name, String.valueOf(SL2_LOGS_COLLECT)));
                enableDisableLogs(scriptString, name);
            }
        }
    }

    //
    // This method overwrites node sync retries and timeout for both node CPP and COMECIM
    // method is called only when RNL is detected.
    // see the issue faced in https://jira-oss.seli.wh.rnd.internal.ericsson.com/browse/TORF-618833?src=confmacro
    // CPP node
    // These values override the default ones in CM Test library (NodeIntegrationOperatorCpp.java)
    //
    // COMECIM node
    // These values override the default ones in CM Test library (NodeIntegrationOperatorComEcim.java)
    //
    public void setUpRnlSyncNodesTimeOut() {
        LOGGER.info("\nRNL environment detected - overwriting current Nodes Sync Retries and TimeOut parameters.");
        final int rnlSyncNodeTimeOut = DataHandler.getConfiguration().getProperty("rnl.node.sync.timeout", 5000, Integer.class);
        final int rnlSyncNodeRetries = DataHandler.getConfiguration().getProperty("rnl.node.sync.retries", 12, Integer.class);
        final String comEcimSyncTimeOut = "node.comecim.sync.timeout";
        final String comEcimSyncRetries = "node.comecim.sync.retries";
        final String cppSyncTimeOut = "node.cpp.sync.timeout";
        final String cppSyncRetries = "node.cpp.sync.retries";
        final TafConfiguration tafConfiguration = DataHandler.getConfiguration();
        // set new values into context
        tafConfiguration.setProperty(comEcimSyncTimeOut, rnlSyncNodeTimeOut);
        tafConfiguration.setProperty(comEcimSyncRetries, rnlSyncNodeRetries);
        tafConfiguration.setProperty(cppSyncTimeOut, rnlSyncNodeTimeOut);
        tafConfiguration.setProperty(cppSyncRetries, rnlSyncNodeRetries);
        // get new values from context and dump to screen.
        final String  comEcimSyncTimeOutNew = tafConfiguration.getProperty(comEcimSyncTimeOut, String.class);
        final String  comEcimSyncRetriesNew = tafConfiguration.getProperty(comEcimSyncRetries, String.class);
        final String  cppySncTimeOutNew = tafConfiguration.getProperty(cppSyncTimeOut, String.class);
        final String  cppSyncRetriesNew = tafConfiguration.getProperty(cppSyncRetries, String.class);
        LOGGER.info(String.format("\nNew values set:\n\t%s = %s\n\t%s = %s\n\t%s = %s\n\t%s = %s",
                comEcimSyncTimeOut, comEcimSyncTimeOutNew, comEcimSyncRetries, comEcimSyncRetriesNew,
                cppSyncTimeOut, cppySncTimeOutNew, cppSyncRetries, cppSyncRetriesNew));
    }
}
