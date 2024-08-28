/*
 * ------------------------------------------------------------------------------
 * ******************************************************************************
 * COPYRIGHT Ericsson 2016
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 * ******************************************************************************
 * ----------------------------------------------------------------------------
 */

package com.ericsson.nms.security.nscs.arnlrfa250scenario;

import static com.ericsson.cifwk.taf.scenario.TestScenarios.runner;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import javax.inject.Inject;

import com.ericsson.cifwk.taf.TafTestBase;
import com.ericsson.cifwk.taf.TafTestContext;
import com.ericsson.cifwk.taf.TestContext;
import com.ericsson.cifwk.taf.datasource.DataRecord;
import com.ericsson.cifwk.taf.datasource.TestDataSource;
import com.ericsson.cifwk.taf.scenario.TestScenarioRunner;
import com.ericsson.cifwk.taf.scenario.impl.LoggingScenarioListener;
import com.ericsson.nms.security.nscs.datasource.RoleDefinitionSuiteNameDataSource;
import com.ericsson.nms.security.nscs.datasource.UsersToCreateTimeStampDataSource;
import com.google.common.base.Predicate;

/**
 * SetupAndTearDownUtil necessary operations that must be executed before and after every test suite.
 */
@SuppressWarnings({"PMD.LawOfDemeter"})
public abstract class SetupAndTearDownUtil extends TafTestBase {

    private static int numberOfNodes;
    private static int numberOfUsers;

    private static String suiteName;

    @Inject
    protected TestContext context;

    public abstract Predicate<DataRecord> netSimTest();

    public abstract Predicate<DataRecord> correctNodeType();

    public abstract List<String> rbacCustomRolesList();

    public abstract Iterable<DataRecord> filterUsers(Iterable<DataRecord> userList);

    public abstract Iterable<DataRecord> filterUsersForTbac();

    /**
     * Returns the number of users.
     *
     * @return the number of users
     */
    public static int getNumberOfUsers() {
        return numberOfUsers;
    }

    /**
     * Set number of users.
     */
    public static void setNumberOfUsers(final int value) {
        numberOfUsers = value;
    }

    /**
     * Returns the number of nodes.
     *
     * @return the number of nodes
     */
    public static int getNumberOfNodes() {
        return numberOfNodes;
    }

    /**
     * Set number of nodes.
     */
    public static void setNumberOfNodes(final int value) {
        numberOfNodes = value;
        System.setProperty(UsersToCreateTimeStampDataSource.NUM_OF_NODES, String.valueOf(value));
    }

    /**
     * Returns the number of nodes.
     *
     * @return the number of nodes
     */
    public static String getSuiteName() {
        return suiteName;
    }

    /**
     * Set number of nodes.
     */
    public static void setSuiteName(final String value) {
        suiteName = value;
        System.setProperty(RoleDefinitionSuiteNameDataSource.SUITE_NAME, String.valueOf(value));
    }

    /**
     * Return the test scenario runner.
     *
     * @return the test scenario
     */
    public static TestScenarioRunner getScenarioRunner() {
        return runner().withListener(new LoggingScenarioListener()).build();
    }

    public static void removeAndCreateTestDataSource(final String dataSourceName, final Iterable<DataRecord> nodesFiltered) {
        TafTestContext.getContext().removeDataSource(dataSourceName);
        final Iterator<DataRecord> localNameIterator = nodesFiltered.iterator();
        while (localNameIterator.hasNext()) {
            final DataRecord node = localNameIterator.next();
            TafTestContext.getContext().dataSource(dataSourceName).addRecord().setFields(node);
        }
    }

    public void cleanContext() {
        final Map<String, TestDataSource<DataRecord>> contextDataSource = context.getAllDataSources();
        final List<String> listUsed = new ArrayList<>();
        for (int i = 0; i < contextDataSource.keySet().size(); i++) {
            final String dataSource = (String) contextDataSource.keySet().toArray()[i];
            listUsed.add(dataSource);
        }
        for (int i = 0; i < listUsed.size(); i++) {
            context.removeDataSource(listUsed.get(i));
        }
    }

    /**
     * context.
     *
     * @return the context
     */
    public TestContext getContext() {
        return context;
    }
}