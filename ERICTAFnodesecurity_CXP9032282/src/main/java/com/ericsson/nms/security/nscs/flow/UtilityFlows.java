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

import static com.ericsson.cifwk.taf.datasource.TafDataSources.copy;
import static com.ericsson.cifwk.taf.datasource.TafDataSources.shareDataSource;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.annotatedMethod;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.dataSource;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.flow;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.resetDataSource;
import static com.ericsson.nms.security.nscs.predicate.PredicateUtil.contextFilter;
import static com.ericsson.nms.security.nscs.predicate.PredicateUtil.isCppNode;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.ADDED_NODES;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.AVAILABLE_ROLES;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.AVAILABLE_USERS;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.FM_NODES;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.NODES_TO_ADD;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.ROLE_TO_CREATE;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.ROLE_TO_DELETE;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.USERS_TO_DELETE;
import static com.ericsson.oss.testware.fm.api.constants.FmCommonDataSources.SUPERVISION_DISABLE_NODES;
import static com.ericsson.oss.testware.fm.api.constants.FmCommonDataSources.SUPERVISION_ENABLE_NODES;
import static com.ericsson.oss.testware.fm.api.constants.FmCommonDataSources.SUPERVISION_STATUS_NODES;
import static com.ericsson.oss.testware.nodesecurity.steps.GetSyncTestSteps.ASSERT_IF_NOT_SYNCH;
import static com.ericsson.oss.testware.security.gim.flows.GimCleanupFlows.CLEAN_UP_ROLE_FLOW;

import java.util.concurrent.TimeUnit;

import javax.inject.Inject;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.cifwk.taf.TafTestContext;
import com.ericsson.cifwk.taf.TestContext;
import com.ericsson.cifwk.taf.data.DataHandler;
import com.ericsson.cifwk.taf.datasource.DataRecord;
import com.ericsson.cifwk.taf.datasource.TafDataSources;
import com.ericsson.cifwk.taf.datasource.TestDataSource;
import com.ericsson.cifwk.taf.scenario.TestStepFlow;
import com.ericsson.cifwk.taf.scenario.api.ScenarioExceptionHandler;
import com.ericsson.cifwk.taf.scenario.api.TestStepFlowBuilder;
import com.ericsson.nms.security.nscs.predicate.PredicateUtil;
import com.ericsson.oss.testware.fm.flows.FmAlarmSupervisionFlows;
import com.ericsson.oss.testware.fm.flows.FmFunctionFlows;
import com.ericsson.oss.testware.network.teststeps.NetworkElementTestSteps;
import com.ericsson.oss.testware.nodeintegration.flows.NodeIntegrationFlows;
import com.ericsson.oss.testware.nodeintegration.teststeps.NodeIntegrationTestSteps;
import com.ericsson.oss.testware.nodesecurity.flows.Sl2Flows;
import com.ericsson.oss.testware.nodesecurity.steps.GetSyncTestSteps;
import com.ericsson.oss.testware.security.authentication.flows.LoginLogoutRestFlows;
import com.ericsson.oss.testware.security.gim.flows.RoleManagementTestFlows;
import com.ericsson.oss.testware.security.gim.flows.TargetGroupManagementTestFlows;
import com.ericsson.oss.testware.security.gim.flows.UserManagementTestFlows;
import com.ericsson.oss.testware.security.gim.steps.RoleManagementTestSteps;
import com.google.common.base.Predicate;
import com.google.common.base.Predicates;
import com.google.common.collect.Iterables;

/**
 * SetupAndTeardownScenarioRealNode necessary operations that must be executed before and after every test suite.
 */
@SuppressWarnings({ "PMD.LawOfDemeter", "PMD.ExcessiveImports", "PMD.DoNotUseThreads" })
public class UtilityFlows {

    public static final Integer USER_ROLES_DELAY = DataHandler.getConfiguration().getProperty("nscs.rbac.delay", 70, Integer.class);
    protected static final Logger LOGGER = LoggerFactory.getLogger(UtilityFlows.class);
    private static final String EMPTY_FLOW = "Empty";

    @Inject
    RoleManagementTestSteps roleManagementTestSteps;
    @Inject
    RoleManagementTestFlows roleManagementFlows;
    @Inject
    UserManagementTestFlows userManagementTestFlows;
    @Inject
    LoginLogoutRestFlows loginLogoutRestFlows;
    @Inject
    NetworkElementTestSteps networkElementTestSteps;
    @Inject
    NodeIntegrationFlows nodeIntegrationFlows;
    @Inject
    FmAlarmSupervisionFlows fmSupervisionFlows;
    @Inject
    FmFunctionFlows fmFunctionFlows;
    @Inject
    TargetGroupManagementTestFlows targetGroupManagementTestFlows;
    @Inject
    Sl2Flows sl2Flows;
    @Inject
    NodeIntegrationTestSteps nodeIntegrationTestSteps;

    @Inject
    GetSyncTestSteps getSyncTestStep;

    /**
     * Flow for gim clean.
     *
     * @return a TestStepFlow
     */
    public TestStepFlow gimRoleCleanUp() {
        return flow("Clean up User Roles")
                .addSubFlow(loginLogoutRestFlows.loginDefaultUser())
                .addTestStep(annotatedMethod(roleManagementTestSteps, RoleManagementTestSteps.TEST_STEP_CLEAN_UP_ROLE))
                .addSubFlow(loginLogoutRestFlows.logout())
                .withDataSources(dataSource(CLEAN_UP_ROLE_FLOW)).build();
    }

    /**
     * Flow for getting user role.
     *
     * @return a TestStepFlow
     */
    public TestStepFlowBuilder getUserRoles(final boolean isRequested) {
        return isRequested ? flow("Create Users").addSubFlow(roleManagementFlows.queryActiveRoles()).afterFlow(afterGetUserRole())
                : flow(EMPTY_FLOW);
    }

    /**
     * Flow for user role creation.
     *
     * @return a TestStepFlowBuilder
     */
    public TestStepFlowBuilder createUserRoles(final boolean isRequested, final int vUser, final boolean logOnly) {
        TestStepFlowBuilder basic = flow("Create Role")
                .beforeFlow(resetDataSource(ROLE_TO_CREATE)).beforeFlow(shareDataSource(ROLE_TO_CREATE))
                .addSubFlow(roleManagementFlows.createRole()).pause(USER_ROLES_DELAY, TimeUnit.SECONDS)
                .withVusers(vUser);
        basic = logOnly ? basic.pause(USER_ROLES_DELAY, TimeUnit.SECONDS).withExceptionHandler(ScenarioExceptionHandler.LOGONLY) : basic;
        return isRequested ? basic : flow(EMPTY_FLOW);
    }

    /**
     * Flow for user role deletion.
     *
     * @return a TestStepFlowBuilder
     */
    public TestStepFlowBuilder deleteUserRoles(final boolean isRequested, final int vUser, final boolean logOnly) {
        TestStepFlowBuilder basic = flow("Delete Role - Precondition")
                .beforeFlow(resetDataSource(ROLE_TO_DELETE)).beforeFlow(shareDataSource(ROLE_TO_DELETE))
                .addSubFlow(roleManagementFlows.deleteRole()).withVusers(vUser);
        basic = logOnly ? basic.withExceptionHandler(ScenarioExceptionHandler.LOGONLY) : basic;
        return isRequested ? basic : flow(EMPTY_FLOW);
    }

    /**
     * Flow for user creation.
     * the user
     *
     * @return a TestStepFlow
     */
    public TestStepFlowBuilder createUsers(final int vUser) {
        return userManagementTestFlows.createUser().withVusers(vUser);
    }

    /**
     * Flow for user deletion.
     *
     * @param vUser
     *         the user
     *
     * @return a TestStepFlow
     */
    public TestStepFlowBuilder deleteUsers(final int vUser) {
        return flow("Delete Users").beforeFlow(beforeDeleteUsers())
                .addSubFlow(userManagementTestFlows.deleteUser()).withVusers(vUser);
    }

    /**
     * Adds the datasource for 'delete users' operation.
     *
     * @return runnable
     */
    public static Runnable beforeDeleteUsers() {
        return new Runnable() {
            @Override
            public void run() {
                final TestContext context = TafTestContext.getContext();
                context.removeDataSource(USERS_TO_DELETE);
                context.addDataSource(USERS_TO_DELETE, context.dataSource(AVAILABLE_USERS));
            }
        };
    }

    /**
     * Flow for login user with filter.
     *
     * @param user
     *         the filter
     *
     * @return a TestStepFlowBuilder
     */
    public TestStepFlowBuilder login(final Predicate user) {
        return loginLogoutRestFlows.loginBuilder()
                .beforeFlow(resetDataSource(AVAILABLE_USERS)).beforeFlow(TafDataSources.copyDataSource(AVAILABLE_USERS))
                .withDataSources(dataSource(AVAILABLE_USERS).withFilter(user));
    }

    /**
     * subFlow used in REST TEST
     *
     * Login to ENM with functional user with proper capability and roles
     */

    public TestStepFlowBuilder loginFunctionalUser(final String predicate) {
        return flow("Login Functional user")
                .addSubFlow(loginLogoutRestFlows.login(contextFilter(predicate)));
    }

    /**
     * Flow for login user with filter.
     *
     * @param user
     *            the filter
     * @param vUser
     *            the user
     *
     * @return a TestStepFlow
     */
    public TestStepFlow login(final Predicate user, final int vUser) {
        return loginLogoutRestFlows.loginBuilder()
                .beforeFlow(resetDataSource(AVAILABLE_USERS)).beforeFlow(TafDataSources.copyDataSource(AVAILABLE_USERS))
                .withDataSources(dataSource(AVAILABLE_USERS).withFilter(user)).withVusers(vUser).build();
    }

    /**
     * Flow for login user with filter.
     *
     * @param user
     *            the filter
     *
     * @return a TestStepFlowBuilder
     */
    public TestStepFlowBuilder logout(final Predicate user) {
        return loginLogoutRestFlows.logoutBuilder()
                .beforeFlow(resetDataSource(AVAILABLE_USERS)).beforeFlow(TafDataSources.copyDataSource(AVAILABLE_USERS))
                .withDataSources(dataSource(AVAILABLE_USERS).withFilter(user));
    }

    /**
     * Flow for login user with filter.
     *
     * @param user
     *            the filter
     * @param vUser
     *            the user
     *
     * @return a TestStepFlow
     */
    public TestStepFlow logout(final Predicate user, final int vUser) {
        return loginLogoutRestFlows.logoutBuilder()
                .beforeFlow(resetDataSource(AVAILABLE_USERS)).beforeFlow(TafDataSources.copyDataSource(AVAILABLE_USERS))
                .withDataSources(dataSource(AVAILABLE_USERS).withFilter(user)).withVusers(vUser).build();
    }

    /**
     * Flow for starting netsim nodes after creation.
     *
     * @param user
     *            the user
     *
     * @return a TestStepFlowBuilder
     */
    public TestStepFlowBuilder startNetsimNodes(final Predicate user) {
        return flow("Start Netsim Nodes")
                .beforeFlow(shareDataSource(NODES_TO_ADD)).beforeFlow(resetDataSource(NODES_TO_ADD))
                .addTestStep(annotatedMethod(networkElementTestSteps, NetworkElementTestSteps.StepIds.START_NODE))
                .withDataSources(dataSource(NODES_TO_ADD).withFilter(user).allowEmpty());
    }

    /**
     * Flow for creating nodes.
     *
     * @param vUser
     *            the user
     *
     * @return a TestStepFlow
     */
    public TestStepFlow createNodes(final Predicate user, final int vUser) {
        return flow("Create Nodes")
                .beforeFlow(shareDataSource(NODES_TO_ADD)).beforeFlow(resetDataSource(NODES_TO_ADD))
                .afterFlow(shareDataSource(NODES_TO_ADD)).afterFlow(resetDataSource(NODES_TO_ADD))
                .afterFlow(shareDataSource(ADDED_NODES)).afterFlow(resetDataSource(ADDED_NODES))
                .addSubFlow(nodeIntegrationFlows.addNode())
                .withDataSources(dataSource(NODES_TO_ADD).withFilter(user).allowEmpty())
                .withVusers(vUser).build();
    }

    /**
     * Flow for synch nodes.
     *
     * @param isRequested
     *            the user
     *
     * @return a TestStepFlow
     */
    public TestStepFlowBuilder syncNodes(final boolean isRequested, final Predicate user, final int vUser) {
        return isRequested ? flow("Synch Nodes")
                .beforeFlow(shareDataSource(NODES_TO_ADD)).beforeFlow(resetDataSource(NODES_TO_ADD))
                .afterFlow(resetDataSource(NODES_TO_ADD))
                .addSubFlow(nodeIntegrationFlows.syncNode())
                .withDataSources(dataSource(NODES_TO_ADD).withFilter(user).allowEmpty())
                .withVusers(vUser) : flow(EMPTY_FLOW);
    }

    /**
     * Flow for trigerring action sync on node.
     *
     * @param vUser
     *            the user
     *
     * @return a TestStepFlow
     */
    public TestStepFlow actionSyncNodeOnNodes(final int vUser) {
        return flow("Verify action Synch Nodes")
                .beforeFlow(shareDataSource(ADDED_NODES)).beforeFlow(resetDataSource(ADDED_NODES))
                .addSubFlow(nodeIntegrationFlows.actionSyncNode())
                .withDataSources(dataSource(ADDED_NODES)).withVusers(vUser).build();
    }

    /**
     * Flow for enabling CM supervision on node.
     *
     * @param vUser
     *            the user
     *
     * @return a TestStepFlow
     */
    public TestStepFlow enableCMSupervisionOnNodes(final int vUser) {
        return flow("Enable CM supervision on Nodes")
                .beforeFlow(shareDataSource(ADDED_NODES)).beforeFlow(resetDataSource(ADDED_NODES))
                .addSubFlow(nodeIntegrationFlows.enableCMSupervision())
                .withDataSources(dataSource(ADDED_NODES)).withVusers(vUser).build();
    }

    /**
     * Flow for synch nodes.
     *
     * @return a TestStepFlow
     */
    public TestStepFlow verifySyncNodes() {
        return flow("Verify Synch Nodes")
                .addSubFlow(nodeIntegrationFlows.verifySynchNodeBuilder()).build();
    }

    /**
     * Flow for synch nodes.
     *
     * @param vUser
     *            the user
     *
     * @return a TestStepFlow
     */
    public TestStepFlow verifySyncNodes(final int vUser) {
        return flow("Verify Synch Nodes")
                .beforeFlow(shareDataSource(ADDED_NODES)).beforeFlow(resetDataSource(ADDED_NODES))
                .addSubFlow(nodeIntegrationFlows.verifySynchNodeBuilder())
                .withDataSources(dataSource(ADDED_NODES)).withVusers(vUser).build();
    }

    public TestStepFlow recursiveCheckSyncNodeStatus(final int vUser) {
        return flow("recursive check Cm Sync node status")
                .beforeFlow(shareDataSource(ADDED_NODES)).beforeFlow(resetDataSource(ADDED_NODES))
                .addTestStep(annotatedMethod(getSyncTestStep, GetSyncTestSteps.RECURSIVE_CHECK_NODE_SYNC_STATUS))
                .withDataSources(dataSource(ADDED_NODES)).withVusers(vUser)
                .build();
    }

    public TestStepFlowBuilder recursiveCheckSyncNodeStatusCmFm() {
        return flow("Recursive check Cm Sync and Fm currentService node status")
                .addSubFlow(nodeIntegrationFlows.verifySynchNodeBuilder())
                .addTestStep(annotatedMethod(getSyncTestStep, GetSyncTestSteps.RECURSIVE_CHECK_FM_FUNCTION_CURRENT_SERVICE_STATE));
    }

    public TestStepFlow recursiveCheckSyncNodeStatusWithAssertion(final int vUser) {
        return flow("Recursive check Cm Sync node status")
                .beforeFlow(shareDataSource(ADDED_NODES)).beforeFlow(resetDataSource(ADDED_NODES))
                .addTestStep(annotatedMethod(getSyncTestStep, GetSyncTestSteps.RECURSIVE_CHECK_NODE_SYNC_STATUS)
                        .withParameter(ASSERT_IF_NOT_SYNCH, true))
                .withDataSources(dataSource(ADDED_NODES)).withVusers(vUser)
                .build();
    }

    public TestStepFlow recursiveCheckFmStatus(final int vUser) {
        return flow("Recursive check Fm currentService node status")
                .beforeFlow(shareDataSource(ADDED_NODES)).beforeFlow(resetDataSource(ADDED_NODES))
                .addTestStep(annotatedMethod(getSyncTestStep, GetSyncTestSteps.RECURSIVE_CHECK_FM_FUNCTION_CURRENT_SERVICE_STATE))
                .withDataSources(dataSource(ADDED_NODES)).withVusers(vUser)
                .build();
    }

    public TestStepFlow checkSyncNodeStatusOnce(final int vUser) {
        return flow("Check Cm Sync node status - NO Recursive")
                .beforeFlow(shareDataSource(ADDED_NODES)).beforeFlow(resetDataSource(ADDED_NODES))
                .addTestStep(annotatedMethod(getSyncTestStep, GetSyncTestSteps.CHECK_NODE_SYNC_STATUS_ONCE))
                .withDataSources(dataSource(ADDED_NODES)).withVusers(vUser)
                .build();
    }

    /**
     * Flow to verify synch nodes in Deactivation of Sl2.
     *
     * @return a TestStepFlow
     */
    public TestStepFlow recursiveVerifySyncNode() {
        return flow("Verify Synch Nodes recursively")
                .beforeFlow(shareDataSource(NODES_TO_ADD)).beforeFlow(resetDataSource(NODES_TO_ADD))
                .addSubFlow(nodeIntegrationFlows.verifySynchNodeRepeatBuilder()).build();
    }

    /**
     * Flow for delete nodes.
     *
     * @param vUser
     *            the user
     *
     * @return a TestStepFlow
     */
    public TestStepFlow deleteNodes(final Predicate user, final int vUser) {
        return flow("Delete Nodes")
                .beforeFlow(shareDataSource(ADDED_NODES))
                .afterFlow(resetDataSource(ADDED_NODES))
                .addSubFlow(nodeIntegrationFlows.deleteNode())
                .withDataSources(dataSource(ADDED_NODES).withFilter(user).allowEmpty())
                .withVusers(vUser).build();
    }

    /**
     * Flow for disabling supervision on nodes.
     *
     * @return a TestStepFlow
     */
    public TestStepFlow disableSupervision() {
        return flow("Supervision Disable")
                .beforeFlow(shareDataSource(ADDED_NODES)).beforeFlow(resetDataSource(ADDED_NODES))
                .addTestStep(annotatedMethod(nodeIntegrationTestSteps, NodeIntegrationTestSteps.DISABLE_SUPERVISION))
                .withDataSources(dataSource(ADDED_NODES)).build();
    }

    /**
     * Tests Supervision Enable and Current Service State.
     *
     * @param isRequested
     *            - count of vusers to execute this flow
     *
     * @return a TestStepFlowBuilder
     */
    public TestStepFlowBuilder subscriptionEnableTest(final boolean isRequested, final int vUser) {
        LOGGER.trace("subscriptionEnableTest: isRequested -> " + isRequested);
        final TestContext context = TafTestContext.getContext();
        final boolean isEmpty = Iterables.isEmpty(context.dataSource(SUPERVISION_ENABLE_NODES));
        LOGGER.trace("subscriptionEnableTest: isEmpty -> " + isEmpty);
        return isRequested && !isEmpty ? flow("Subscription Enable")
                .beforeFlow(shareDataSource(SUPERVISION_ENABLE_NODES), shareDataSource(FM_NODES))
                .beforeFlow(resetDataSource(SUPERVISION_ENABLE_NODES))
                .addSubFlow(fmSupervisionFlows.verifySupervisionFlow())
                .addSubFlow(fmSupervisionFlows.subscriptionEnableFlow())
                .addSubFlow(fmFunctionFlows.checkCurrentServiceStateFlow())
                .withDataSources(dataSource(SUPERVISION_ENABLE_NODES).withFilter(isCppNode).bindTo(FM_NODES).allowEmpty())
                .withExceptionHandler(ScenarioExceptionHandler.LOGONLY)
                .withVusers(vUser) : flow(EMPTY_FLOW);
    }

    public TestStepFlowBuilder restoreAlarmSupervisionState(final boolean isRequested, final int vUser) {
        LOGGER.trace("restoreAlarmSupervisionState: isRequested -> " + isRequested);
        final TestContext context = TafTestContext.getContext();
        final boolean isEmpty = Iterables.isEmpty(context.dataSource(SUPERVISION_STATUS_NODES));
        LOGGER.trace("restoreAlarmSupervisionState: isEmpty -> " + isEmpty);
        return isRequested && !isEmpty ? flow("Subscription Restore")
                .beforeFlow(shareDataSource(SUPERVISION_STATUS_NODES))
                .beforeFlow(resetDataSource(SUPERVISION_STATUS_NODES))
                .addSubFlow(fmSupervisionFlows.resetSupervisionState())
                .withDataSources(dataSource(SUPERVISION_STATUS_NODES).withFilter(isCppNode).allowEmpty())
                .withVusers(vUser) : flow(EMPTY_FLOW);
    }

    /**
     * Tests Supervision Disable.
     *
     * @param isRequested
     *            - count of vusers to execute this flow
     *
     * @return a TestStepFlowBuilder
     */
    public TestStepFlowBuilder subscriptionDisableTest(final boolean isRequested, final int vUser) {
        return isRequested ? flow("Subscription Disable")
                .beforeFlow(shareDataSource(SUPERVISION_DISABLE_NODES), shareDataSource(FM_NODES))
                .beforeFlow(resetDataSource(SUPERVISION_DISABLE_NODES))
                .addSubFlow(fmSupervisionFlows.subscriptionDisableFlow())
                .withDataSources(dataSource(SUPERVISION_DISABLE_NODES).withFilter(isCppNode).bindTo(FM_NODES).allowEmpty())
                .withVusers(vUser) : flow(EMPTY_FLOW);
    }

    /**
     * Flow for target group create.
     *
     * @return a TestStepFlow
     */
    public TestStepFlow createTargetGroup(final boolean isRequested) {
        return isRequested ? flow("Create Target Group").addSubFlow(targetGroupManagementTestFlows.createTargetGroup()).build()
                : flow(EMPTY_FLOW).build();
    }

    /**
     * Flow for target group delete.
     *
     * @return a TestStepFlowBuilder
     */
    public TestStepFlowBuilder deleteTargetGroup(final boolean isRequested) {
        return isRequested ? flow("Delete Target Group").addSubFlow(targetGroupManagementTestFlows.deleteTargetGroup()).alwaysRun()
                : flow(EMPTY_FLOW);
    }

    /**
     * Flow for target to target group assign.
     *
     * @return a TestStepFlow
     */
    public TestStepFlow assignTargetsToTargetGroup(final boolean isRequested) {
        return isRequested ? flow("Assign Targets To Target Group").addSubFlow(targetGroupManagementTestFlows.assignTargetsToTargetGroup()).build()
                : flow(EMPTY_FLOW).build();
    }

    /**
     * Test step for user update for TBAC.
     *
     * @param vUser
     *            the user
     *
     * @return a TestStepFlow
     */
    public TestStepFlow updateUsersForTbac(final boolean isRequested, final int vUser) {
        return isRequested ? flow("Update Users For TBAC").addSubFlow(userManagementTestFlows.updateUserTBAC()).withVusers(vUser).build()
                : flow(EMPTY_FLOW).build();
    }

    // AVAILABLE_ROLES

    /**
     * Adds the datasource for 'delete users' operation.
     *
     * @return runnable
     */
    public static Runnable afterGetUserRole() {
        return new Runnable() {
            @Override
            public void run() {
                final TestContext context = TafTestContext.getContext();
                final TestDataSource<DataRecord> roleCreate = copy(context.dataSource(ROLE_TO_CREATE));
                final TestDataSource<DataRecord> roleAvailable = copy(context.dataSource(AVAILABLE_ROLES));
                context.removeDataSource(ROLE_TO_CREATE);
                context.removeDataSource(ROLE_TO_DELETE);
                context.dataSource(ROLE_TO_CREATE);
                context.dataSource(ROLE_TO_DELETE);
                for (final DataRecord create : roleCreate) {
                    boolean find = false;
                    for (final DataRecord available : roleAvailable) {
                        final String createValue = create.getFieldValue("name");
                        final String availableValue = available.getFieldValue("name");
                        if (createValue.equals(availableValue)) {
                            find = true;
                            break;
                        }
                    }
                    if (!find) {
                        context.dataSource(ROLE_TO_CREATE).addRecord().setFields(create);
                        context.dataSource(ROLE_TO_DELETE).addRecord().setFields(create);
                    }
                }
                LOGGER.debug("\n" + Iterables.toString(context.dataSource(ROLE_TO_CREATE)).replace(", Data value: ", ",\nData value: ") + "\n");
            }
        };
    }

    /**
     * Flow for sl get on the nodes.
     *
     * @param isRequested
     *            the user
     *
     * @return a TestStepFlow
     */
    public TestStepFlowBuilder getSecurityLevel(final boolean isRequested, final int vUser) {
        return isRequested ? sl2Flows.getStatusSlFlowBuilder()
                .withDataSources(dataSource(NODES_TO_ADD).bindTo(ADDED_NODES).allowEmpty())
                .withExceptionHandler(ScenarioExceptionHandler.LOGONLY)
                .withVusers(vUser) : flow(EMPTY_FLOW);
    }
}
