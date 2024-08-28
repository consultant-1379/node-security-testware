/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2017
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.nms.security.nscs.arnlrfa250scenario;

import com.ericsson.cifwk.taf.annotations.TestSuite;
import com.ericsson.cifwk.taf.datasource.DataRecord;
import com.ericsson.cifwk.taf.datasource.TestDataSourceFactory;
import com.ericsson.cifwk.taf.scenario.TestScenario;
import com.ericsson.cifwk.taf.scenario.api.DataDrivenTestScenarioBuilder;
import com.ericsson.nms.security.nscs.predicate.PredicateUtil;
import com.ericsson.oss.testware.nodesecurity.flows.FtpesFlows;
import com.google.common.base.Predicate;
import com.google.common.collect.Iterables;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import javax.inject.Inject;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;

import static com.ericsson.cifwk.taf.scenario.TestScenarios.*;
import static com.ericsson.nms.security.nscs.arnlrfa250scenario.SetupAndTeardownScenarioFtpes.*;
import static com.ericsson.nms.security.nscs.constants.UserRoleValues.ROLE_NODESECURITY_OPERATOR;
import static com.ericsson.nms.security.nscs.predicate.PredicateUtil.userRoleSuiteNamePredicate;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.ADDED_NODES;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.AVAILABLE_USERS;
import static com.ericsson.oss.testware.nodesecurity.utils.FtpesOperation.ACTIVATE;
import static com.ericsson.oss.testware.nodesecurity.utils.FtpesOperation.DEACTIVATE;
import static com.ericsson.oss.testware.nodesecurity.utils.FtpesOperation.GET;

import com.ericsson.oss.testware.nodesecurity.utils.FtpesOperation;

@SuppressWarnings({"PMD.LawOfDemeter"})
public class FtpesTestScenario extends ScenarioUtility {

    private static final String ROLES = "roles";

    @Inject
    private FtpesFlows ftpesFlows;

    private Iterable<DataRecord> getUserListPositive;
    private Iterable<DataRecord> getUserListNegative;

    @BeforeClass(groups = {"Functional", "NSS", "RFA250", "ARNL", "KGB"})
    public void beforeClass() {
        final Predicate<DataRecord> predicatePositive = userRoleSuiteNamePredicate(ROLES, positiveCustomRoles());
        final Predicate<DataRecord> predicateNegative = userRoleSuiteNamePredicate(ROLES, negativeCustomRoles());

        final List<String> getPositiveUserRoles = new ArrayList<>(SetupAndTeardownScenarioFtpes.positiveCustomRoles());
        getPositiveUserRoles.add(ROLE_NODESECURITY_OPERATOR);
        final List<String> getNegativeUserRoles = new ArrayList<>(SetupAndTeardownScenarioFtpes.negativeCustomRoles());
        getNegativeUserRoles.remove(ROLE_NODESECURITY_OPERATOR);

        final Predicate<DataRecord> getPredicatePositive = userRoleSuiteNamePredicate(ROLES, getPositiveUserRoles);
        final Predicate<DataRecord> getPredicateNegative = userRoleSuiteNamePredicate(ROLES, getNegativeUserRoles);

        super.beforeClass(predicatePositive, predicateNegative);
        getUserListPositive = availableUserFiltered(getPredicatePositive);
        getUserListNegative = availableUserFiltered(getPredicateNegative);
    }

    @BeforeMethod(groups = {"Functional", "NSS", "RFA250", "ARNL", "KGB"})
    public void beforeMethod(final Method method) {
        final String name = method.getName();
        if (name.startsWith("ftpesActivatePositive")) {
            final TestScenario beforeMethodScenario = scenario(String.format("Before Method %s node sync", name))
                    .addFlow(utilityFlows.login(PredicateUtil.nscsAdm(), vUser))
                    .addFlow(utilityFlows.syncNodes(true, PredicateUtil.netSimTestPredicate(), vUser))
                    .addFlow(utilityFlows.logout(PredicateUtil.nscsAdm(), vUser)).build();
            startScenario(beforeMethodScenario);
        } else if (name.startsWith("ftpesCommandsUnsyncNodes")) {
            final TestScenario beforeMethodScenario = scenario(String.format("Before Method %s disable supervision on nodes", name))
                    .addFlow(utilityFlows.login(PredicateUtil.nscsAdm(), vUser))
                    .addFlow(utilityFlows.disableSupervision())
                    .addFlow(utilityFlows.logout(PredicateUtil.nscsAdm(), vUser)).build();
            startScenario(beforeMethodScenario);
        }
    }

    @Test(enabled = true, priority = 1, groups = {"Functional", "NSS", "RFA250", "ARNL", "KGB"})
    @TestSuite
    public void ftpesActivatePositiveCase() {
        doParallelNodesBase(INPUT_DATASOURCE, "NSCS_FTPES_ACTIVATE_CorrectUserRole",
                context.dataSource(FTPES_POSITIVE_FILE_BASED_TEST),
                context.dataSource(ADDED_NODES), userListPositive);
        startScenario(getSingleFtpesCommandScenario("FTPES Activation Positive Scenario", true, ACTIVATE));
    }

    @Test(enabled = true, priority = 2, groups = {"Functional", "NSS", "RFA250", "ARNL", "KGB"})
    @TestSuite
    public void ftpesDeactivatePositiveCase() {
        doParallelNodesBase(INPUT_DATASOURCE, "NSCS_FTPES_DEACTIVATE_CorrectUserRole",
                context.dataSource(FTPES_POSITIVE_FILE_BASED_TEST),
                context.dataSource(ADDED_NODES), userListPositive);
        startScenario(getSingleFtpesCommandScenario("FTPES Deactivate Positive Scenario", true, DEACTIVATE));
    }

    @Test(enabled = true, priority = 3, groups = {"Functional", "NSS", "RFA250", "ARNL", "KGB"})
    @TestSuite
    public void ftpesGetPositiveCase() {
        doParallelNodesBase(INPUT_DATASOURCE, "NSCS_FTPES_GET_CorrectUserRole",
                context.dataSource(FTPES_POSITIVE_FILE_BASED_TEST),
                context.dataSource(ADDED_NODES), getUserListPositive);
        startScenario(getSingleFtpesCommandScenario("FTPES Get Positive Scenario", false, GET));
    }

    @Test(enabled = true, priority = 4, groups = {"Functional", "NSS", "KGB"})
    @TestSuite
    public void ftpesActivateNegativeCase() {
        doParallelNodesBase(INPUT_DATASOURCE, "NSCS_FTPES_ACTIVATE_WrongUserRole",
                context.dataSource(FTPES_NEGATIVE_WRONG_ROLE_TEST), context.dataSource(ADDED_NODES), userListNegative);
        startScenario(getSingleFtpesCommandScenario("FTPES Activate Wrong role Negative Scenario", false, ACTIVATE));
    }

    @Test(enabled = true, priority = 5, groups = {"Functional", "NSS", "KGB"})
    @TestSuite
    public void ftpesDeactivateNegativeCase() {
        doParallelNodesBase(INPUT_DATASOURCE, "NSCS_FTPES_DEACTIVATE_WrongUserRole",
                context.dataSource(FTPES_NEGATIVE_WRONG_ROLE_TEST), context.dataSource(ADDED_NODES), userListNegative);
        startScenario(getSingleFtpesCommandScenario("NSCS_FTPES_DEACTIVATE_WrongUserRole", false, DEACTIVATE));
    }

    @Test(enabled = true, priority = 6, groups = {"Functional", "NSS", "KGB"})
    @TestSuite
    public void ftpesGetNegative() {
        doParallelNodesBase(INPUT_DATASOURCE, "NSCS_FTPES_GET_WrongUserRole",
                context.dataSource(FTPES_NEGATIVE_WRONG_ROLE_TEST), context.dataSource(ADDED_NODES), getUserListNegative);
        startScenario(getSingleFtpesCommandScenario("FTPES Get Wrong role Negative Scenario", false, GET));
    }

    @Test(enabled = true, priority = 7, groups = {"Functional", "NSS", "KGB"})
    @TestSuite
    public void ftpesCommandsMultiNode() {
        super.setupMultiNodes();
        final Iterable<DataRecord> userMultiNode = availableUserFiltered(PredicateUtil.nscsAdm());
        final int skipped = (Iterables.size(userMultiNode) >= 1) ? Iterables.size(userMultiNode) - 1 : 1;
        doParallelNodesBase(INPUT_DATASOURCE, "NSCS_FTPES_COMMANDS_MULTINODE",
                context.dataSource(FTPES_POSITIVE_NODE_BASED_TEST), context.dataSource(NODES_TO_ADD_MULTINODES),
                Iterables.skip(userMultiNode, skipped));
        startScenario(getAllFtpesCommandsScenario("Ftpes commands: Multi nodes Positive Scenario"));
    }

    @Test(enabled = true, priority = 8, groups = {"Functional", "NSS", "KGB"})
    @TestSuite
    public void ftpesCommandsNotExistingNodes() {
        doParallelNodesBase(INPUT_DATASOURCE, "NSCS_FTPES_COMMANDS_NOT_EXISTING_NODES",
                context.dataSource(FTPES_NEGATIVE_NOT_EXISTING_NODES_TEST), context.dataSource(NODES_TO_ADD_NOT_EXIST),
                availableUserFiltered(PredicateUtil.nscsAdm()));
        startScenario(getAllFtpesCommandsScenario("FTPES commands: Not existing nodes Negative Scenario"));
    }

    @Test(enabled = true, priority = 9, groups = {"Functional", "NSS", "KGB"})
    @TestSuite
    public void ftpesCommandsUnsyncNodes() {
        doParallelNodesBase(INPUT_DATASOURCE, "NSCS_FTPES_COMMANDS_UNSYNCH_NODES",
                context.dataSource(FTPES_NEGATIVE_UNSYNC_NODES_TEST), context.dataSource(ADDED_NODES),
                availableUserFiltered(PredicateUtil.nscsAdm()));
        startScenario(getAllFtpesCommandsScenario("FTPES commands: Unsync nodes Negative Scenario"));
    }

    @Test(enabled = true, priority = 10, groups = {"Functional", "KGB"})
    @TestSuite
    public void ftpesCommandsUnsupportedNodes() {
        super.setupKgbOnlyNoSync();
        final DataRecord firstUser = Iterables.filter(context.dataSource(AVAILABLE_USERS), PredicateUtil.nscsAdm()).iterator().next();
        doParallelNodesBase(INPUT_DATASOURCE, "NSCS_FTPES_COMMANDS_UNSUPPORTED_NODES",
                context.dataSource(FTPES_NEGATIVE_UNSUPP_TYPE_TEST), context.dataSource(ADDED_NODES),
                TestDataSourceFactory.createDataSource(firstUser.getAllFields()));
        final TestScenario scenario = dataDrivenScenario("FTPES command Unsupported nodes Negative scenario")
                .addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(ftpesFlows.getFtpes())
                .addFlow(ftpesFlows.setFtpes(true, ACTIVATE))
                .addFlow(ftpesFlows.setFtpes(true, DEACTIVATE))
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(AVAILABLE_USERS).bindTo(ADDED_NODES))
                .doParallel(vUserKgbOnly).build();
        startScenario(scenario);
        super.teardownKgbOnly();
    }

    private TestScenario getAllFtpesCommandsScenario(final String testCaseName) {
        return dataDrivenScenario(testCaseName)
                .addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(ftpesFlows.getFtpes())
                .addFlow(ftpesFlows.setFtpes(true, ACTIVATE))
                .addFlow(ftpesFlows.setFtpes(true, DEACTIVATE))
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(AVAILABLE_USERS).bindTo(ADDED_NODES))
                .doParallel(vUser).build();
    }

    private TestScenario getSingleFtpesCommandScenario(final String testCaseName, final boolean requireJobMonitor,
                                                       final FtpesOperation operation) {
        final DataDrivenTestScenarioBuilder scenario = dataDrivenScenario(testCaseName)
                .addFlow(loginLogoutRestFlows.loginBuilder());

        if (operation.equals(GET)) {
            scenario.addFlow(ftpesFlows.getFtpes());
        } else {
            scenario.addFlow(ftpesFlows.setFtpes(requireJobMonitor, operation));
        }

        return scenario.addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(AVAILABLE_USERS).bindTo(ADDED_NODES))
                .doParallel(vUser).build();
    }
}
