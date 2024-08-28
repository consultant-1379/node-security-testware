package com.ericsson.nms.security.nscs.flow;

import static com.ericsson.cifwk.taf.scenario.TestScenarios.annotatedMethod;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.dataSource;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.flow;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.fromTestStepResult;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.ADDED_NODES;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.NODES_TO_ADD;
import static com.ericsson.oss.testware.nodeintegration.teststeps.NodeIntegrationTestSteps.ADD_NODE;
import static com.ericsson.oss.testware.nodeintegration.teststeps.NodeIntegrationTestSteps.CONFIRM_NODE_ADDED;
import static com.ericsson.oss.testware.nodeintegration.teststeps.NodeIntegrationTestSteps.DELETE_NODE;
import static com.ericsson.oss.testware.nodeintegration.teststeps.NodeIntegrationTestSteps.SYNC_NODE;

import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import javax.inject.Inject;

import com.ericsson.cifwk.taf.TafTestContext;
import com.ericsson.cifwk.taf.TestContext;
import com.ericsson.cifwk.taf.datasource.DataRecord;
import com.ericsson.cifwk.taf.datasource.DataRecordImpl;
import com.ericsson.cifwk.taf.datasource.TestDataSource;
import com.ericsson.cifwk.taf.datasource.TestDataSourceFactory;
import com.ericsson.cifwk.taf.scenario.TestScenarios;
import com.ericsson.cifwk.taf.scenario.TestStepFlow;
import com.ericsson.cifwk.taf.scenario.api.TafDataSourceDefinitionBuilder;
import com.ericsson.nms.security.nscs.constants.SecurityConstants;
import com.ericsson.nms.security.nscs.datasource.PredicatesExt;
import com.ericsson.nms.security.nscs.teststep.GenericTestSteps;
import com.ericsson.nms.security.nscs.teststep.SpecificCredentialTestSteps;
import com.ericsson.oss.testware.enmbase.data.NetworkNode;
import com.ericsson.oss.testware.enmbase.provider.DefaultNodeSecurityProvider;
import com.ericsson.oss.testware.nodeintegration.teststeps.NodeIntegrationTestSteps;
import com.ericsson.oss.testware.nodesecurity.steps.CredentialTestSteps;
import com.google.common.base.Predicate;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Flows to manage the node.
 */
@SuppressWarnings({"PMD.LawOfDemeter", "PMD.ExcessiveImports", "PMD.DoNotUseThreads"})
public class AddRemoveNodesFlow extends BaseFlow {

    private static final Logger LOGGER = LoggerFactory.getLogger(AddRemoveNodesFlow.class);

    public static final String NODES_TO_ADD_WITH_CREDENTIALS = "addedNodesWithCredentials";

    @Inject
    private CredentialTestSteps credentialTestSteps;
    @Inject
    private NodeIntegrationTestSteps nodeIntegrationTestSteps;
    @Inject
    private GenericTestSteps genericTestSteps;
    @Inject
    private SpecificCredentialTestSteps specificCredentialTestSteps;

    private static Runnable fillDataSourceWithDefaultCredential() {
        return new Runnable() {
            @Override
            public void run() {
                final TestContext context = TafTestContext.getContext();
                final List<Map<String, Object>> iterableDataSource = Lists.newArrayList();
                final TestDataSource<DataRecord> nodesDataSource = context.dataSource(ADDED_NODES);
                TestScenarios.resetDataSource(ADDED_NODES);
                final Iterator<DataRecord> nodeIterator = nodesDataSource.iterator();
                for (final DataRecord node : Lists.newArrayList(nodeIterator)) {
                    final DataRecordImpl dataRecord = fillRecordDataSource(node);
                    final Map<String, Object> dr = Maps.newHashMap(dataRecord.getAllFields());
                    iterableDataSource.add(dr);
                }
                context.addDataSource(NODES_TO_ADD_WITH_CREDENTIALS, TestDataSourceFactory.createDataSource(iterableDataSource));
            }
        };
    }

    private static DataRecordImpl fillRecordDataSource(final DataRecord node) {
        final Map<String, Object> nodeToBeModified = Maps.newHashMap(node.getAllFields());
        nodeToBeModified.put(DefaultNodeSecurityProvider.NORMAL_USER_NAME_KEY, SecurityConstants.NETSIM_DEFAULT_USER_NAME);
        nodeToBeModified.put(DefaultNodeSecurityProvider.NORMAL_PASSWORD_KEY, SecurityConstants.NETSIM_DEFAULT_USER_NAME);
        nodeToBeModified.put(DefaultNodeSecurityProvider.ROOT_USER_NAME_KEY, SecurityConstants.NETSIM_DEFAULT_USER_NAME);
        nodeToBeModified.put(DefaultNodeSecurityProvider.ROOT_PASSWORD_KEY, SecurityConstants.NETSIM_DEFAULT_USER_NAME);
        nodeToBeModified.put(DefaultNodeSecurityProvider.SECURE_USER_NAME_KEY, SecurityConstants.NETSIM_DEFAULT_USER_NAME);
        nodeToBeModified.put(DefaultNodeSecurityProvider.SECURE_PASSWORD_KEY, SecurityConstants.NETSIM_DEFAULT_USER_NAME);
        return new DataRecordImpl(nodeToBeModified);
    }

    /**
     * Add the nodes specified in 'ADDED_NODES' datasource, filtered with 'byProfile' Predicate
     * This method is used by following scenarios (used in "old fashioned" suites): BaseScenario.createIscfSetup(),
     * CredentialServiceApiSetUpTearDownScenario.createCredentialServiceApiSetupScenario() (copied by previous ISCF method),
     * CliScriptingScenario.getCredentials(@Input(SCRIPT_TO_ADD) final CliScriptingValue value)
     *
     * @return TestStepFlow
     */
    public TestStepFlow addNodes() {
        return flow("Add Node").addTestStep(annotatedMethod(nodeIntegrationTestSteps, ADD_NODE))
                .withDataSources(dataSource(NODES_TO_ADD).withFilter(PredicatesExt.byProfile)).withVusers(SecurityConstants.V_USERS).build();
    }

    /**
     * Check that the nodes in 'ADDED_NODES' datasource, filtered with 'byProfile' Predicate, have been added successfully
     * This method is used by the following scenarios (used in "old fashioned" suites): BaseScenario.createIscfSetup(),
     * CredentialServiceApiSetUpTearDownScenario.createCredentialServiceApiSetupScenario() (copied by previous ISCF method)
     *
     * @return TestStepFlow
     */
    public TestStepFlow confirmAddedNodes() {
        return flow("Confirm Added Nodes").addTestStep(annotatedMethod(nodeIntegrationTestSteps, CONFIRM_NODE_ADDED))
                .withDataSources(dataSource(NODES_TO_ADD).withFilter(PredicatesExt.byProfile)).withVusers(SecurityConstants.V_USERS).build();
    }

    /**
     * Add the nodes specified in ADDED_NODES datasource, filtered with 'byProfile' Predicate, and check they've been added successfully
     * This method is used by the following scenarios (in "old style" suites): BaseScenario.createSetupRbac(), BaseScenario.createSetupFull(),
     * BaseScenario.createSetupCrlCheckForG1(), BaseScenario.createSetupCrlCheckForG1Rbac()
     *
     * @return TestStepFlow
     */
    public TestStepFlow addConfirmNodes() {
        return flow("Add Confirm Node").addTestStep(annotatedMethod(nodeIntegrationTestSteps, ADD_NODE))
                .addTestStep(annotatedMethod(nodeIntegrationTestSteps, CONFIRM_NODE_ADDED))
                .withDataSources(dataSource(NODES_TO_ADD).withFilter(PredicatesExt.byProfile)).withVusers(SecurityConstants.V_USERS).build();
    }

    /**
     * Add nodes specified in input datasource and check they've been added successfully
     * This method is used by the following scenario (used in all "new style" suites): BaseScenario.createSetup()
     *
     * @param nodesToAddDataSource
     *         datasource with nodes to be added
     *
     * @return TestStepFlow
     */
    public TestStepFlow addConfirmNodes(final TafDataSourceDefinitionBuilder<NetworkNode> nodesToAddDataSource) {
        return flow("Add Confirm Node")
                .addTestStep(annotatedMethod(nodeIntegrationTestSteps, ADD_NODE))
                .addTestStep(annotatedMethod(nodeIntegrationTestSteps, CONFIRM_NODE_ADDED).withParameter(NODES_TO_ADD, fromTestStepResult(ADD_NODE))
                        .collectResultToDatasource(ADDED_NODES)).withDataSources(nodesToAddDataSource.bindTo(NODES_TO_ADD))
                .withVusers(SecurityConstants.V_USERS).build();
    }

    /**
     * TRIAL METHOD to add nodes in parallel Note: it's not used, as it's not yet working
     *
     * @return TestStepFlow
     */
    public TestStepFlow addConfirmNodesParallel() {
        //        return flow("Add Confirm Node Parallel")
        //                .addSubFlow(
        //                        flow("subflow add confirm node").addTestStep(annotatedMethod(nodeIntegrationTestSteps, NodeIntegrationTestSteps
        // .ADD_NODE))
        //                                .addTestStep(annotatedMethod(nodeIntegrationTestSteps, NodeIntegrationTestSteps.CONFIRM_NODE_ADDED)))
        //                .withDataSources(dataSource(NODES_TO_ADD).withFilter(PredicatesExt.byProfile)).withVusers(15).build();
        return flow("Add Confirm Node Parallel").addTestStep(annotatedMethod(nodeIntegrationTestSteps, ADD_NODE))
                .addTestStep(annotatedMethod(nodeIntegrationTestSteps, CONFIRM_NODE_ADDED))
                .withDataSources(dataSource(NODES_TO_ADD).withFilter(PredicatesExt.byProfile)).build();
    }

    /**
     * Delete NetworkElementSecurity objects and nreate default credentials.
     *
     * @param predicate
     *         Predicate filter
     *
     * @return TestStepFlow
     */
    public TestStepFlow createDefaultCredential(final Predicate<DataRecord> predicate) {
        return flow("Create default credential").beforeFlow(fillDataSourceWithDefaultCredential())
                .addTestStep(annotatedMethod(specificCredentialTestSteps, SpecificCredentialTestSteps.DELETE_SECURITY_INFO_WITH_CHECK))
                .addTestStep(annotatedMethod(credentialTestSteps, CredentialTestSteps.CRED_CREATE))
                .withDataSources(dataSource(NODES_TO_ADD_WITH_CREDENTIALS).withFilter(predicate).bindTo(ADDED_NODES))
                .withVusers(SecurityConstants.V_USERS).build();
    }

    /**
     * Sync the nodes specified in 'ADDED_NODES' datasource filtered with 'predicate' Predicate
     * This method is used by the following scenarios (in "old style" suites): BaseScenario.createSetupRbac(), BaseScenario.createSetupFull(),
     * BaseScenario.createSetupCrlCheckForG1(), BaseScenario.createSetupCrlCheckForG1Rbac(), BaseScenario.createSetupParallel() (only as an attempt)
     *
     * @param predicate
     *         Predicate filter
     *
     * @return TestStepFlow
     */
    public TestStepFlow syncNodes(final Predicate<DataRecord> predicate) {
        return flow("Sync Node").addTestStep(annotatedMethod(nodeIntegrationTestSteps, SYNC_NODE))
                .withDataSources(dataSource(ADDED_NODES).withFilter(predicate).bindTo(NODES_TO_ADD)).withVusers(SecurityConstants.V_USERS).build();
    }

    /**
     * Sync the nodes specified in 'syncNodesDataSource' datasource
     * This method is used by the following scenario (used in all "new style" suites): BaseScenario.createSetup()
     *
     * @param syncNodesDataSource
     *         datasource with the nodes to be synchronized
     *
     * @return
     */
    public TestStepFlow syncNodes(final TafDataSourceDefinitionBuilder<NetworkNode> syncNodesDataSource) {
        return flow("Sync node").addTestStep(annotatedMethod(nodeIntegrationTestSteps, SYNC_NODE))
                .withDataSources(syncNodesDataSource.bindTo(NODES_TO_ADD)).withVusers(SecurityConstants.V_USERS).build();
    }

    /**
     * Check that the nodes specified in 'NODES_TO_ADD' datasource, filtered with 'predicate' Predicate, are synchronized.
     *
     * @param predicate
     *         Predicate filter
     *
     * @return TestStepFlow
     */
    public TestStepFlow confirmSyncNodes(final Predicate<DataRecord> predicate) {
        return flow("Sync Node").addTestStep(annotatedMethod(nodeIntegrationTestSteps, NodeIntegrationTestSteps.CONFIRM_NODE_SYNCED))
                .withDataSources(dataSource(NODES_TO_ADD).withFilter(predicate)).withVusers(SecurityConstants.V_USERS).build();
    }

    /**
     * Enable alarm supervision on the nodes specified in 'NODES_TO_ADD' datasource, filtered with 'predicate' Predicate
     *
     * @param predicate
     *         Predicate filter
     *
     * @return TestStepFlow
     */
    public TestStepFlow fmEnableAlarmSupervision(final Predicate<DataRecord> predicate) {
        return flow("Fm Enable Alarm Supervision").addTestStep(annotatedMethod(genericTestSteps, GenericTestSteps.ENABLE_ALARM_SUPERVISION))
                .withDataSources(dataSource(NODES_TO_ADD).withFilter(predicate).bindTo(ADDED_NODES)).withVusers(SecurityConstants.V_USERS).build();
    }

    /**
     * Delete the nodes specified in 'ADDED_NODES' datasource, filtered with 'predicate' Predicate
     * This method is used by following scenarios (used in "old fashioned" suites): BaseScenario.createIscfTeardown(),
     * CredentialServiceApiSetUpTearDownScenario.createCredentialServiceApiTeardownScenario() (copied by previous ISCF method)
     *
     * @param predicate
     *         Predicate filter
     *
     * @return TestStepFlow
     */
    public TestStepFlow deleteNodes(final Predicate<DataRecord> predicate) {
        return flow("Delete Node").addTestStep(annotatedMethod(nodeIntegrationTestSteps, DELETE_NODE))
                .withDataSources(dataSource(ADDED_NODES).withFilter(predicate)).withVusers(SecurityConstants.V_USERS).build();
    }

    /**
     * Delete the nodes specified in 'nodesToDeleteDataSource' datasource
     * This method is used by the following scenario (used both in "new style" and "old style" suites): BaseScenario.createTeardown()
     *
     * @param nodesToDeleteDataSource
     *         datasource with the nodes to be deleted
     *
     * @return
     */
    public TestStepFlow deleteNodes(final TafDataSourceDefinitionBuilder<NetworkNode> nodesToDeleteDataSource) {
        return flow("Delete Node").addTestStep(annotatedMethod(nodeIntegrationTestSteps, DELETE_NODE))
                .withDataSources(nodesToDeleteDataSource.bindTo(ADDED_NODES)).withVusers(SecurityConstants.V_USERS).build();
    }

    /**
     * Wait flow
     *
     * @param pause
     *         how long to wait
     * @param timeunit
     *         Time Unit
     *
     * @return TestStepFlow
     */
    public TestStepFlow addDelay(final Integer pause, final TimeUnit timeunit) {
        LOGGER.debug("addDelay(): pausing for [{}] [{}]", pause, timeunit);
        return flow("Add Delay").pause(pause, timeunit).withVusers(SecurityConstants.V_USERS).build();
    }

}
