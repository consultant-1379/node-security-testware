/*
 *  *******************************************************************************
 *  * COPYRIGHT Ericsson  2022
 *  *
 *  * The copyright to the computer program(s) herein is the property of
 *  * Ericsson Inc. The programs may be used and/or copied only with written
 *  * permission from Ericsson Inc. or in accordance with the terms and
 *  * conditions stipulated in the agreement/contract under which the
 *  * program(s) have been supplied.
 *  *******************************************************************************
 */
package com.ericsson.nms.security.nscs.arnlrfa250scenario;

import static com.ericsson.cifwk.taf.datasource.TafDataSources.filter;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.dataDrivenScenario;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.dataSource;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.runner;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.scenario;
import static com.ericsson.nms.security.nscs.predicate.PredicateUtil.isCppNode;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.ADDED_NODES;

import javax.inject.Inject;

import com.ericsson.cifwk.taf.data.DataHandler;
import com.ericsson.cifwk.taf.datasource.TafDataSources;
import com.ericsson.cifwk.taf.scenario.TestScenario;
import com.ericsson.cifwk.taf.scenario.TestScenarioRunner;
import com.ericsson.cifwk.taf.scenario.api.DataDrivenTestScenarioBuilder;
import com.ericsson.cifwk.taf.scenario.api.ScenarioExceptionHandler;
import com.ericsson.cifwk.taf.scenario.api.TestScenarioBuilder;
import com.ericsson.cifwk.taf.scenario.impl.LoggingScenarioListener;
import com.ericsson.oss.testware.flows.LogManagementFlows;
import com.google.common.collect.Iterables;

@SuppressWarnings({ "PMD.LawOfDemeter"})
public class LogScenarioUtility extends ScenarioUtilityAgat {
    private static final Boolean LOG_DEBUG_MODE = DataHandler.getConfiguration().getProperty("log.debug.mode", false, Boolean.class);

    public static final String LOG_ENABLE_SCRIPT_FILENAME = "EnableLog";
    public static final String LOG_DISABLE_SCRIPT_FILENAME = "DisableLog";

    @Inject
    private LogManagementFlows logManagementFlows;

    public void enableLogMng(final String fileName, final String tag) {
        if (NSCS_LOGS_COLLECT) {
            dataDrivenDataSource(INPUT_DATASOURCE, "LOG MANAGEMENT SETUP", "Enable Log Management '" + tag + "'",
                    filter(context.dataSource(ADDED_NODES), isCppNode), true);
            final int nodeNumber = Iterables.size(context.dataSource(INPUT_DATASOURCE));
            LOGGER.trace("Enable Log: Filtered Node Count --> {}", nodeNumber);
            if (nodeNumber > 0) {
                final DataDrivenTestScenarioBuilder enableLogBuilder = dataDrivenScenario("Enable Log (DataDriven Scenario)").addFlow(
                        logManagementFlows.enableLogManagementFlow(fileName)).withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(ADDED_NODES)).doParallel(nodeNumber);

                // This scenario configuration (LOGONLY) is normally enabled (the LOG enabling function must not cause the testware to fail, even if it
                //  fails): in the debug phase (flag 'LOG_DEBUG_MODE' to true) allows us to highlight the malfunction of the enabling / disabling of
                //  node LOGs.
                if (!LOG_DEBUG_MODE) {
                    enableLogBuilder.withExceptionHandler(ScenarioExceptionHandler.LOGONLY);
                }

                final TestScenario disableLog = enableLogBuilder.build();
                final TestScenarioRunner runner = runner().withListener(new LoggingScenarioListener()).build();
                runner.start(disableLog);
            } else {
                LOGGER.warn("Cannot enable LOG Collection because no CPP nodes available: SKIP");
            }
        }
    }

    public void enableLogManagement(final String filename, final String tag) {
        if (NSCS_LOGS_COLLECT) {
            context.addDataSource(ADDED_NODES, TafDataSources.shared(context.dataSource(ADDED_NODES)));
            int nodeCount = Iterables.size(filter(context.dataSource(ADDED_NODES), isCppNode));
            LOGGER.trace("Enable Log Management: Filtered Node Count --> {}", nodeCount);
            if (nodeCount > 0) {
                nodeCount = nodeCount > LOG_PARALLEL_MANAGEMENT ? LOG_PARALLEL_MANAGEMENT : nodeCount;
                final TestScenarioBuilder scenario = scenario("Enable Log Management '" + tag + "' (Scenario)")
                        .addFlow(logManagementFlows.enableLogManagementFlow(filename).alwaysRun()
                                .withDataSources(dataSource(ADDED_NODES).withFilter(isCppNode))
                                .withVusers(nodeCount))
                        .withExceptionHandler(LOG_DEBUG_MODE ? ScenarioExceptionHandler.PROPAGATE : ScenarioExceptionHandler.LOGONLY);

                final TestScenarioRunner runner = runner().withListener(new LoggingScenarioListener()).build();
                runner.start(scenario.build());
            } else {
                LOGGER.warn("Cannot enable LOG Collection because no CPP nodes available: SKIP");
            }
        }
    }

    public void disableLogMng(final String fileName, final String tag) {
        if (NSCS_LOGS_COLLECT) {
            dataDrivenDataSource(INPUT_DATASOURCE, "LOG MANAGEMENT SETUP", "Disable Log Management '" + tag + "'",
                    filter(context.dataSource(ADDED_NODES), isCppNode), true);
            final int nodeNumber = Iterables.size(context.dataSource(INPUT_DATASOURCE));
            LOGGER.trace("Disable Log: Filtered Node Count --> {}", nodeNumber);
            if (nodeNumber > 0) {
                final DataDrivenTestScenarioBuilder disableLogBuilder = dataDrivenScenario("Disable Log (DataDriven Scenario)").addFlow(
                        logManagementFlows.disableLogManagementFlow(fileName, tag)).withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(ADDED_NODES)).doParallel(nodeNumber);

                // This scenario configuration (LOGONLY) is normally enabled (the LOG enabling function must not cause the testware to fail, even if it
                //  fails): in the debug phase (flag 'LOG_DEBUG_MODE' to true) allows us to highlight the malfunction of the enabling / disabling of
                //  node LOGs.
                if (!LOG_DEBUG_MODE) {
                    disableLogBuilder.withExceptionHandler(ScenarioExceptionHandler.LOGONLY);
                }

                final TestScenario disableLog = disableLogBuilder.build();
                final TestScenarioRunner runner = runner().withListener(new LoggingScenarioListener()).build();
                runner.start(disableLog);
            } else {
                LOGGER.warn("Cannot disable LOG Collection because no CPP nodes available: SKIP");
            }
        }
    }

    public void disableLogManagement(final String filename, final String tag) {
        if (NSCS_LOGS_COLLECT) {
            context.addDataSource(ADDED_NODES, TafDataSources.shared(context.dataSource(ADDED_NODES)));
            int nodeCount = Iterables.size(filter(context.dataSource(ADDED_NODES), isCppNode));
            LOGGER.trace("Disable Log Management: Filtered Node Count --> {}", nodeCount);
            if (nodeCount > 0) {
                nodeCount = nodeCount > LOG_PARALLEL_MANAGEMENT ? LOG_PARALLEL_MANAGEMENT : nodeCount;
                final TestScenarioBuilder scenario = scenario("Disable Log Management '" + tag + "' (Scenario)").addFlow(
                                logManagementFlows.disableLogManagementFlow(filename, tag).alwaysRun().withDataSources(dataSource(ADDED_NODES).withFilter(isCppNode)).withVusers(nodeCount))
                        .withExceptionHandler(LOG_DEBUG_MODE ? ScenarioExceptionHandler.PROPAGATE : ScenarioExceptionHandler.LOGONLY);

                final TestScenarioRunner runner = runner().withListener(new LoggingScenarioListener()).build();
                runner.start(scenario.build());
            }
        } else {
            LOGGER.warn("Cannot disable LOG Collection because no CPP nodes available: SKIP");
        }
    }
}
