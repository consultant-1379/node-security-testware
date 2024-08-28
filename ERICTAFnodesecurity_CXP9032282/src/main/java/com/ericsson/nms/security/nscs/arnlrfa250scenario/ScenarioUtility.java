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

import static com.ericsson.cifwk.taf.datasource.TafDataSources.copy;
import static com.ericsson.cifwk.taf.datasource.TafDataSources.fromCsv;
import static com.ericsson.cifwk.taf.datasource.TafDataSources.merge;
import static com.ericsson.cifwk.taf.datasource.TafDataSources.shared;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.scenario;
import static com.ericsson.cifwk.taf.scenario.api.DataDrivenTestScenarioBuilder.TEST_CASE_ID;
import static com.ericsson.nms.security.nscs.arnlrfa250scenario.SetupAndTeardownScenario.isRealNode;
import static com.ericsson.nms.security.nscs.arnlrfa250scenario.SetupAndTeardownScenarioLdap.LDAP_CLEANUP_PROXY_DATA_SOURCE;
import static com.ericsson.nms.security.nscs.arnlrfa250scenario.SetupAndTeardownScenarioLdap.PATH_LDAP;
import static com.ericsson.nms.security.nscs.predicate.PredicateUtil.userRoleSuiteNamePredicate;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.ADDED_NODES;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.AVAILABLE_USERS;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.NODES_TO_ADD;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.USERS_TO_CREATE;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.USERS_TO_DELETE;
import static com.ericsson.oss.testware.nodesecurity.operators.ExtIdpImpl.BIND_DN;
import static com.ericsson.oss.testware.nodesecurity.steps.ProxyAccountTestSteps.EXPECTED_RESPONSE_SET;
import static com.ericsson.oss.testware.nodesecurity.steps.ProxyAccountTestSteps.EXPECTED_RESPONSE_SUCCESS;
import static com.ericsson.oss.testware.nodesecurity.steps.ProxyAccountTestSteps.N_OF_BIND_DN;
import static com.ericsson.oss.testware.nodesecurity.utils.SecurityUtil.dumpStringParameter;
import static com.ericsson.oss.testware.nodesecurity.utils.SecurityUtil.enableDisableTELogsInAMOS;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import javax.inject.Inject;

import com.ericsson.cifwk.taf.scenario.api.ScenarioExceptionHandler;
import com.ericsson.oss.testware.nodesecurity.flows.ProxyAccountFlows;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.cifwk.taf.TafTestBase;
import com.ericsson.cifwk.taf.TafTestContext;
import com.ericsson.cifwk.taf.TestContext;
import com.ericsson.cifwk.taf.data.DataHandler;
import com.ericsson.cifwk.taf.datasource.DataRecord;
import com.ericsson.cifwk.taf.datasource.DataRecordImpl;
import com.ericsson.cifwk.taf.datasource.TestDataSource;
import com.ericsson.cifwk.taf.datasource.TestDataSourceFactory;
import com.ericsson.cifwk.taf.scenario.TestScenario;
import com.ericsson.cifwk.taf.scenario.TestScenarioRunner;
import com.ericsson.cifwk.taf.scenario.api.TestScenarioBuilder;
import com.ericsson.nms.security.nscs.flow.UtilityFlows;
import com.ericsson.nms.security.nscs.predicate.PredicateUtil;
import com.ericsson.nms.security.nscs.scenario.ScenarioUtil;
import com.ericsson.oss.testware.nodesecurity.flows.PibSecurityCommandFlows;
import com.ericsson.oss.testware.nodesecurity.utils.ProxyAccountsUtils;
import com.ericsson.oss.testware.security.authentication.flows.LoginLogoutRestFlows;
import com.google.common.base.Preconditions;
import com.google.common.base.Predicate;
import com.google.common.collect.Iterables;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import com.jcraft.jsch.JSchException;
import com.jcraft.jsch.SftpException;

/**
 * ScenarioUtil contains base scenario utilities.
 */
@SuppressWarnings({ "PMD.LawOfDemeter", "PMD.ExcessiveImports", "PMD.DoNotUseThreads", "PMD.GodClass" })
public class ScenarioUtility extends TafTestBase {

    public static final String LINE_SEPARATOR = "\n###############################################################";
    public static final String LINE_EMPTY = "\n";
    public static final String STARTING_FILLING_CHARS = "##";
    public static final String BLANK = " ";
    public static final String STARTING_MESSAGE = LINE_EMPTY + STARTING_FILLING_CHARS + BLANK + "Starting:" + BLANK;
    public static final String FINISHED_MESSAGE = LINE_EMPTY + STARTING_FILLING_CHARS + BLANK + "Finished:" + BLANK;
    public static final String NO_DATA = "No Data in Data Source ";
    public static final String ENABLE_LOGS_SCRIPT = "enable_TE_log.sh";
    public static final String DISABLE_LOGS_SCRIPT = "disable_TE_log.sh";

    protected static final String DATASOURCE_ERROR = "No Data in Data Source: %s";
    protected static final String INPUT_DATASOURCE = "InputDataSource";
    protected static final String INPUT_NBI_DATASOURCE = "InputNbiDataSource";
    protected static final String INPUT_NBI_DATASOURCE_NEGATIVE = "InputNbiNegativeDataSource";
    protected static final Logger LOGGER = LoggerFactory.getLogger(ScenarioUtility.class);

    protected static final String NODES_TO_ADD_MULTINODES = NODES_TO_ADD + "MultiNodes";

    protected int vUser;
    protected int vUserKgbOnly;

    protected Iterable<DataRecord> userListPositive;
    protected Iterable<DataRecord> userListNegative;
    protected Iterable<DataRecord> userListPositiveLdap;
    protected Iterable<DataRecord> userListNbiPositive;
    protected Iterable<DataRecord> userListNbiNegative;

    protected Iterable<DataRecord> userList;

    @Inject
    protected TestContext context;

    @Inject
    protected LoginLogoutRestFlows loginLogoutRestFlows;

    @Inject
    protected UtilityFlows utilityFlows;

    @Inject
    SetupAndTeardownScenarioSl2 setupAndTeardownScenarioSl2;

    @Inject
    PibSecurityCommandFlows pibSecurityCommandFlow;

    @Inject
    private ProxyAccountFlows proxyAccountFlows;

    static void startScenario(final TestScenario scenario) {
        final TestScenarioRunner runner = SetupAndTearDownUtil.getScenarioRunner();
        runner.start(scenario);
    }

    protected void configureTlsVersion(final String tlsVersion) {
        final TestScenarioBuilder scenarioBuilder = scenario("Setup Scenario - configure TLS version protocol")
                .addFlow(loginLogoutRestFlows.loginDefaultUser())
                .addFlow(pibSecurityCommandFlow.configureTlsVersionFlow(tlsVersion))
                .addFlow(loginLogoutRestFlows.logout())
                .alwaysRun();
        SetupAndTearDownUtil.getScenarioRunner().start(scenarioBuilder.build());
    }

    protected void configureTlsComEcimVersion(final String tlsVersion) {
        final TestScenarioBuilder scenarioBuilder = scenario("Setup Scenario - configure TLS COM ECIM version protocol")
                .addFlow(loginLogoutRestFlows.loginDefaultUser())
                .addFlow(pibSecurityCommandFlow.configureTlsComEcimVersionFlow(tlsVersion))
                .addFlow(loginLogoutRestFlows.logout())
                .alwaysRun();
        SetupAndTearDownUtil.getScenarioRunner().start(scenarioBuilder.build());
    }

    protected void configureTlsCPPVersion(final String tlsVersion) {
        final TestScenarioBuilder scenarioBuilder = scenario("Setup Scenario - configure TLS CPP version protocol")
                .addFlow(loginLogoutRestFlows.loginDefaultUser())
                .addFlow(pibSecurityCommandFlow.configureTlsCPPVersionFlow(tlsVersion))
                .addFlow(loginLogoutRestFlows.logout())
                .alwaysRun();
        SetupAndTearDownUtil.getScenarioRunner().start(scenarioBuilder.build());
    }

    protected void configureTlsExtLdapVersion(final String tlsVersion) {
        final TestScenarioBuilder scenarioBuilder = scenario("Setup Scenario - configure TLS Ext Ldapversion protocol")
                .addFlow(loginLogoutRestFlows.loginDefaultUser())
                .addFlow(pibSecurityCommandFlow.configureTlsExtLdapVersionFlow(tlsVersion))
                .addFlow(loginLogoutRestFlows.logout())
                .alwaysRun();
        SetupAndTearDownUtil.getScenarioRunner().start(scenarioBuilder.build());
    }

    protected void setupKgbOnly() {
        context.addDataSource(NODES_TO_ADD + "TEMP", context.dataSource(NODES_TO_ADD));
        context.addDataSource(ADDED_NODES + "TEMP", context.dataSource(ADDED_NODES));
        context.removeDataSource(NODES_TO_ADD);
        context.removeDataSource(ADDED_NODES);
        final TestDataSource<DataRecord> kgbOnlyNodeType = fromCsv("nodesToAdd/nodesToAddKgbOnly.csv");
        final Iterable<DataRecord> nodesFiltered =
                Iterables.filter(kgbOnlyNodeType, PredicateUtil.suiteNamePredicate("suiteName",
                        SetupAndTearDownUtil.getSuiteName()));
        LOGGER.debug("\n kgbOnlyNodes \n" + Iterables.toString(kgbOnlyNodeType).replace(", Data value: ", ",\nData value: "));
        SetupAndTearDownUtil.removeAndCreateTestDataSource(NODES_TO_ADD, nodesFiltered);
        SetupAndTearDownUtil.removeAndCreateTestDataSource(ADDED_NODES, nodesFiltered);
        vUserKgbOnly = Iterables.size(nodesFiltered);
        final TestScenarioBuilder scenarioBuilder = scenario("Setup Kgb Only Nodes ")
                .addFlow(utilityFlows.startNetsimNodes(PredicateUtil.netSimTestPredicate()).withVusers(vUserKgbOnly))
                .addFlow(loginLogoutRestFlows.loginDefaultUser())
                .addFlow(utilityFlows.createNodes(PredicateUtil.netSimTestPredicate(), vUserKgbOnly))
                .addFlow(utilityFlows.syncNodes(true, PredicateUtil.netSimTestPredicate(), vUserKgbOnly))
                .addFlow(loginLogoutRestFlows.logout())
                .alwaysRun();
        SetupAndTearDownUtil.getScenarioRunner().start(scenarioBuilder.build());
    }

    protected void setupKgbOnlyNoSync() {
        context.addDataSource(NODES_TO_ADD + "TEMP", context.dataSource(NODES_TO_ADD));
        context.addDataSource(ADDED_NODES + "TEMP", context.dataSource(ADDED_NODES));
        context.removeDataSource(NODES_TO_ADD);
        context.removeDataSource(ADDED_NODES);
        final TestDataSource<DataRecord> kgbOnlyNodeType = fromCsv("nodesToAdd/nodesToAddKgbOnly.csv");
        final Iterable<DataRecord> nodesFiltered =
                Iterables.filter(kgbOnlyNodeType, PredicateUtil.suiteNamePredicate("suiteName",
                        SetupAndTearDownUtil.getSuiteName()));
        LOGGER.debug("\n kgbOnlyNodes \n" + Iterables.toString(kgbOnlyNodeType).replace(", Data value: ", ",\nData value: "));
        SetupAndTearDownUtil.removeAndCreateTestDataSource(NODES_TO_ADD, nodesFiltered);
        vUserKgbOnly = Iterables.size(nodesFiltered);
        final TestScenarioBuilder scenarioBuilder = scenario("Setup Kgb Only Nodes ")
                .addFlow(loginLogoutRestFlows.loginDefaultUser())
                .addFlow(utilityFlows.createNodes(PredicateUtil.netSimTestPredicate(), vUserKgbOnly))
                .addFlow(loginLogoutRestFlows.logout())
                .alwaysRun();
        SetupAndTearDownUtil.getScenarioRunner().start(scenarioBuilder.build());
    }

    protected void teardownKgbOnly() {
        final TestScenarioBuilder scenarioBuilder = scenario("Teardown Kgb Only Nodes ")
                .addFlow(loginLogoutRestFlows.loginDefaultUser())
                .addFlow(utilityFlows.deleteNodes(PredicateUtil.netSimTestPredicate(), vUserKgbOnly))
                .addFlow(loginLogoutRestFlows.loginDefaultUser())
                .alwaysRun();
        SetupAndTearDownUtil.getScenarioRunner().start(scenarioBuilder.build());
        context.removeDataSource(NODES_TO_ADD);
        context.removeDataSource(ADDED_NODES);
        context.addDataSource(NODES_TO_ADD, context.dataSource(NODES_TO_ADD + "TEMP"));
        context.addDataSource(ADDED_NODES, context.dataSource(ADDED_NODES + "TEMP"));
    }

    private void oneRecordFromDataSources() {
        final TestDataSource<DataRecord> nodeSource = context.dataSource(ADDED_NODES);
        final DataRecord singleNode = Iterables.getFirst(nodeSource, null);
        final StringBuilder summaryNode = new StringBuilder();
        final StringBuilder summaryNodeIp = new StringBuilder();
        final StringBuilder summaryNodeType = new StringBuilder();
        for (final Iterator<DataRecord> iterator = nodeSource.iterator(); iterator.hasNext();) {
            final DataRecord next = iterator.next();
            next.getFieldValue("networkElementId");
            summaryNode.append((String) next.getFieldValue("networkElementId")); // Could be also cast to (StringBuffer)
            if (iterator.hasNext()) {
                summaryNode.append(",");
            }
        }
        for (final Iterator<DataRecord> iterator = nodeSource.iterator(); iterator.hasNext();) {
            final DataRecord next = iterator.next();
            next.getFieldValue("ipAddress");
            summaryNodeIp.append((String) next.getFieldValue("ipAddress")); // Could be also cast to (StringBuffer)
            if (iterator.hasNext()) {
                summaryNodeIp.append(",");
            }
        }
        for (final Iterator<DataRecord> iterator = nodeSource.iterator(); iterator.hasNext();) {
            final DataRecord next = iterator.next();
            next.getFieldValue("nodeType");
            summaryNodeType.append((String) next.getFieldValue("nodeType")); // Could be also cast to (StringBuffer)
            if (iterator.hasNext()) {
                summaryNodeType.append(",");
            }
        }
        final Map<String, Object> multinodeMap = Maps.newHashMap(singleNode.getAllFields());
        multinodeMap.put("networkElementId", summaryNode.toString());
        multinodeMap.put("ipAddress", summaryNodeIp.toString());
        multinodeMap.put("nodeType", summaryNodeType.toString());
        context.dataSource(NODES_TO_ADD_MULTINODES).addRecord().setFields(new DataRecordImpl(multinodeMap));
        ScenarioUtility.debugScope(LOGGER, NODES_TO_ADD_MULTINODES);
    }

    protected void setupMultiNodes() {
        oneRecordFromDataSources();
    }

    private void verifyDataSource() {
        ScenarioUtility.dumpDataSource();
        Preconditions.checkArgument(context.dataSource(AVAILABLE_USERS).iterator().hasNext(),
                ScenarioUtility.NO_DATA + AVAILABLE_USERS);
        Preconditions.checkArgument(!Iterables.isEmpty(context.dataSource(ADDED_NODES)),
                String.format(DATASOURCE_ERROR, ADDED_NODES));
        vUser = Iterables.size(context.dataSource(ADDED_NODES));
    }

    void beforeClass() {
        verifyDataSource();
    }

    public void beforeClass(final Predicate<DataRecord> positive, final Predicate<DataRecord> negative) {
        verifyDataSource();
        userListPositive = availableUserFiltered(positive);
        userListNegative = availableUserFiltered(negative);
    }

    public void beforeClass(final Predicate<DataRecord> positiveLdap, final Predicate<DataRecord> positive, final Predicate<DataRecord> negative) {
        verifyDataSource();
        userListPositive = availableUserFiltered(positive);
        userListNegative = availableUserFiltered(negative);
        userListPositiveLdap = availableUserFiltered(positiveLdap);
    }

    public void beforeClassCustomLdap(final Predicate<DataRecord> positiveLdap, final Predicate<DataRecord> positive) {
        verifyDataSource();
        if (isRealNode()) {
            userList = availableUserFiltered(PredicateUtil.nsuAdm());
        } else {
            userList = availableUserFiltered(PredicateUtil.nsuLdap());
        }
        LOGGER.info("Functional User: " + userList.toString());
    }

    public Iterable<DataRecord> availableUserFiltered(final Predicate<DataRecord> predicate) {
        final Iterable<DataRecord> userList = Iterables.filter(context.dataSource(AVAILABLE_USERS), predicate);
        return userList;
    }

    public static String debugInfo(final TestDataSource<? extends DataRecord> values) {
        final Iterable iterableValues = Iterables.unmodifiableIterable(values);
        final Iterator iteratorValues = iterableValues.iterator();
        String loggerInfo = "";
        final ArrayList myList = Lists.newArrayList(iteratorValues);
        for (int i = 0; i < myList.size(); ++i) {
            final DataRecord next = (DataRecord) myList.get(i);
            final String value = next.toString();
            loggerInfo = loggerInfo.concat(value + "\n");
        }
        if (myList.size() != 0) {
            return loggerInfo;
        } else {
            return "TestDataSource EMPTY --- " + values.toString();
        }
    }

    public static void debugScope(final Logger logger, final TestDataSource<? extends DataRecord> values) {
        final String dump = debugInfo(values);
        logger.debug(dump);
    }

    /**
     * Only for debug scope: this function prints each single row of a datasource.
     *
     * @param logger
     *            logger
     * @param name
     *            key name of the datasource
     */
    public static void debugScope(final Logger logger, final String name) {
        String logInfo = " \n" + name.toUpperCase() + " \n";
        final TestContext context = TafTestContext.getContext();
        if (context.doesDataSourceExist(name)) {
            logInfo = logInfo.concat(debugInfo(context.dataSource(name)));
        } else {
            logInfo = logInfo.concat("INPUT DATASOURCE {} DOES NOT EXIST");
        }
        logger.debug(logInfo);
    }

    public static void dumpDataSource() {
        debugScope(LOGGER, USERS_TO_CREATE);
        debugScope(LOGGER, AVAILABLE_USERS);
        debugScope(LOGGER, USERS_TO_DELETE);
        debugScope(LOGGER, NODES_TO_ADD);
        debugScope(LOGGER, ADDED_NODES);
    }

    public void traceScope(final String place, final int nLines) {
        final StringBuilder msg = new StringBuilder();
        msg.append(LINE_EMPTY);
        for (int i = 0; i < nLines; i++) {
            msg.append(LINE_SEPARATOR);
        }
        final int fillingCharsLengthCandidate = LINE_SEPARATOR.length() - (place.length() + BLANK.length());
        final int fillingCharsLength = fillingCharsLengthCandidate > 0 ? fillingCharsLengthCandidate : 0;
        final String fillingChars = StringUtils.repeat("#", fillingCharsLength);
        msg.append(place + BLANK + fillingChars);
        for (int i = 0; i < nLines; i++) {
            msg.append(LINE_SEPARATOR);
        }
        msg.append(LINE_EMPTY);
        final String msg2string = msg.toString();
        LOGGER.trace(msg2string);
    }

    public static void dataDrivenDataSource(final String dataSourceNew, final String testId, final Iterable<? extends DataRecord> values) {
        final TestContext context = TafTestContext.getContext();
        final TestDataSource<DataRecord> valueNew = TestDataSourceFactory.createDataSource();
        for (final Iterator iterator = values.iterator(); iterator.hasNext();) {
            final DataRecord next = (DataRecord) iterator.next();
            valueNew.addRecord().setFields(next).setField(TEST_CASE_ID, testId);
        }
        ScenarioUtil.debugScope(LOGGER, valueNew);
        context.addDataSource(dataSourceNew, shared(valueNew));
    }

    public static void dataDrivenDataSourceSyntax(final String dataSourceNew, final String testId,
            final Iterable<? extends DataRecord> commands, final Iterable<? extends DataRecord> nodes, final Iterable<? extends DataRecord> users) {
        final TestContext context = TafTestContext.getContext();
        final TestDataSource<DataRecord> valueNew = TestDataSourceFactory.createDataSource();
        final DataRecord[] arrayUsers = Iterables.toArray(users, DataRecord.class);
        final DataRecord[] arrayNodes = Iterables.toArray(nodes, DataRecord.class);
        final DataRecord[] arrayCommands = Iterables.toArray(commands, DataRecord.class);
        if (arrayUsers.length != 0 && arrayNodes.length != 0 && arrayCommands.length != 0) {
            int iNode = 0;
            for (int iUser = 0; iUser < arrayUsers.length; iUser++) {
                final DataRecord user = arrayUsers[iNode];
                for (int iCommand = 0; iCommand < arrayCommands.length; iCommand++) {
                    final DataRecord command = arrayCommands[iCommand];
                    for (iNode = 0; iNode < arrayNodes.length; iNode++) {
                        final DataRecord node = arrayNodes[iNode];
                        valueNew.addRecord().setFields(user).setFields(command).setFields(node)
                                .setField(TEST_CASE_ID, testId);
                    }
                }
            }
            ScenarioUtil.debugScope(LOGGER, valueNew);
        }
        context.addDataSource(dataSourceNew, shared(valueNew));
    }

    public static TestDataSource<DataRecord> addDataRecordForEachDataSourceFields(final DataRecord dataRecord,
            final Iterable<? extends DataRecord> multiRow) {
        final TestDataSource<DataRecord> valueNew = TestDataSourceFactory.createDataSource();
        for (final Iterator iterator = multiRow.iterator(); iterator.hasNext();) {
            final DataRecord multiDataRecord = (DataRecord) iterator.next();
            final Map<String, Object> securityDetails = new HashMap<>();
            securityDetails.putAll(multiDataRecord.getAllFields());
            securityDetails.putAll(dataRecord.getAllFields());
            valueNew.addRecord().setFields(TestDataSourceFactory.createDataRecord(securityDetails));
        }
        debugScope(LOGGER, valueNew);
        return valueNew;
    }

    /**
     * Adds the datasource for 'delete users' operation.
     *
     * @return runnable
     */
    public static Runnable dumpDataSourceRunnable() {
        return new Runnable() {
            @Override
            public void run() {
                dumpDataSource();
            }
        };
    }

    public static void doParallelDifferentCommandsPerNodesBase(final String dataSourceNew, final String testId,
            final Iterable<? extends DataRecord> commandsPerNode, final Iterable<? extends DataRecord> users, final int numOfNodes) {
        final TestContext context = TafTestContext.getContext();
        final TestDataSource<DataRecord> valueNew = TestDataSourceFactory.createDataSource();
        final DataRecord[] arrayUsers = Iterables.toArray(users, DataRecord.class);
        final DataRecord[] arrayCommandsPerNodes = Iterables.toArray(commandsPerNode, DataRecord.class);
        final int arrayCommandsSize = Iterables.size(commandsPerNode);
        final int arrayUsersSize = Iterables.size(users);
        if (arrayUsers.length != 0 && arrayCommandsPerNodes.length != 0) {
            int u = 0;
            do {
                int cn = 0;
                do {
                    final DataRecord command = arrayCommandsPerNodes[cn];
                    final DataRecord user = arrayUsers[u];
                    valueNew.addRecord().setFields(user).setFields(command)
                            .setField(TEST_CASE_ID, testId);
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
                                           final Iterable<? extends DataRecord> nodes,
                                           final Iterable<? extends DataRecord> users) {
        final TestContext context = TafTestContext.getContext();
        final TestDataSource<DataRecord> valueNew = TestDataSourceFactory.createDataSource();
        final DataRecord[] arrayUsers = Iterables.toArray(users, DataRecord.class);
        final DataRecord[] arrayNodes = Iterables.toArray(nodes, DataRecord.class);
        final int arrayUsersSize = Iterables.size(users);
        final int arrayNodesSize = Iterables.size(nodes);
        if (arrayUsers.length != 0 && arrayNodes.length != 0) {
            int u = 0;
            do {
                int n = 0;
                do {
                    final DataRecord user = arrayUsers[u];
                    final DataRecord node = arrayNodes[n];
                    valueNew.addRecord().setFields(user).setFields(node)
                            .setField(TEST_CASE_ID, testId);
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
                                           final Iterable<? extends DataRecord> commands,
                                           final Iterable<? extends DataRecord> nodes,
                                           final Iterable<? extends DataRecord> users) {
        final TestContext context = TafTestContext.getContext();
        final TestDataSource<DataRecord> valueNew = TestDataSourceFactory.createDataSource();
        final DataRecord[] arrayCommands = Iterables.toArray(commands, DataRecord.class);
        final DataRecord[] arrayUsers = Iterables.toArray(users, DataRecord.class);
        final DataRecord[] arrayNodes = Iterables.toArray(nodes, DataRecord.class);
        // "commands": e.g.:
        // REISSUE_OAM:
        // Data value: {caName=NE_OAM_CA, certType=OAM, fileName=null}
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
                                .setField("testCaseId", testId);
                        n++;
                    } while (n < arrayNodesSize);
                    u = u + 1;
                } while (u < arrayUsersSize);
                c++;
            } while (c < arrayCommandsSize);
        }
        ScenarioUtil.debugScope(LOGGER, valueNew);
        context.addDataSource(dataSourceNew, shared(valueNew));
    }

    /**
     * <pre>
     * Name: reorderDatasourceWithOriginalone()       [public]
     * Description: This method could be used to reorder 'reorderingDataSource' with 'originalDataSource' sequence, using 'orderingKeyWord' keyword.
     *              It follows each DataRecord of first DataSource (originalDataSource) search in second DataSource (reorderingDataSource) a record
     *              with same 'orderingKeyWord' field and put this one in New DataSource (reorderedDataSource).
     * </pre>
     *
     * @param originalDataSource
     *            DataSource from which the order of the records must be copied using the KeyWord #orderingKeyWord.
     * @param reorderingDataSource
     *            DataSource to reorder.
     * @param orderingKeyWord
     *            Keyword to use for reordering (it must be unique)
     * @return Reordered DataSource
     */
    public TestDataSource<? extends DataRecord> reorderDatasourceWithOriginalone(final TestDataSource<DataRecord> originalDataSource,
            final TestDataSource<DataRecord> reorderingDataSource, final String orderingKeyWord) {
        final List<Map<String, Object>> reorderedDataSource = Lists.newArrayList();
        final Iterator<DataRecord> originalDatasourceIterator = originalDataSource.iterator();
        while (originalDatasourceIterator.hasNext()) {
            final DataRecord originalRecord = originalDatasourceIterator.next();
            final Iterator<DataRecord> reorderingDatasourceIterator = reorderingDataSource.iterator();
            for (final DataRecord reorderingDataRecord : Lists.newArrayList(reorderingDatasourceIterator)) {
                if (reorderingDataRecord.getFieldValue(orderingKeyWord).equals(originalRecord.getFieldValue(orderingKeyWord))) {
                    reorderedDataSource.add(originalRecord.getAllFields());
                }
            }
        }
        return TestDataSourceFactory.createDataSource(reorderedDataSource);
    }

    public void singlenode(final String newDataSource, final TestDataSource<DataRecord> originalDataSource) {
        final DataRecord first = Iterables.getFirst(originalDataSource, null);
        context.removeDataSource(newDataSource);
        context.dataSource(newDataSource).addRecord().setFields(first);
        debugScope(LOGGER, newDataSource);
    }

    public void fetchSingleNodeFromCsv(final String newDataSource, final TestDataSource<DataRecord> originalDataSource, final int i) {
        final DataRecord last = Iterables.get(originalDataSource, i);
        context.removeDataSource(newDataSource);
        context.dataSource(newDataSource).addRecord().setFields(last);
        debugScope(LOGGER, newDataSource);
    }

    public void fetchSpecificNodeFromCsv(final String newDataSource, final TestDataSource<DataRecord> originalDataSource, final Predicate predicate) {
        try {
            final DataRecord dr = Iterables.find(originalDataSource, predicate);
            context.removeDataSource(newDataSource);
            context.dataSource(newDataSource).addRecord().setFields(dr);
            debugScope(LOGGER, newDataSource);
        } catch (final Exception e) {
            LOGGER.info("\n WARNING !!! fetchSpecificNodeFromCsv did NOT produce any value --> DataRecord isEmpty !!!\n");
            e.printStackTrace();
        }
    }

    /**
     * This method merges 2 datasource Strings and returns merged datasource String
     *
     * @param dataSource1
     *            name of dataSource1
     * @param dataSource2
     *            name of dataSource2.
     * @return mergedDatasource
     */
    public static TestDataSource<DataRecord> mergeDataSources(final String dataSource1, final String dataSource2) {
        final TestContext context = TafTestContext.getContext();
        if (context.doesDataSourceExist(dataSource1) && context.doesDataSourceExist(dataSource2)) {
            final TestDataSource<DataRecord> source1 = copy(context.dataSource(dataSource1));
            final TestDataSource<DataRecord> source2 = copy(context.dataSource(dataSource2));
            final TestDataSource<DataRecord> mergedSource = merge(source1, source2);
            return mergedSource;
        } else {
            LOGGER.debug("INPUT DATA SOURCES {}, {} DO NOT EXIST", dataSource1, dataSource2);
        }
        return null;
    }

    /**
     * This method merges 2 datasource Strings and crates a new one <dataSourceNew>.
     * @param  dataSourceNew
     *             name of new dataSource to be adding to the context
     * @param dataSource1
     *            name of dataSource1
     * @param dataSource2
     *            name of dataSource2.
     */
    public static void mergeDataSourcesTwo(final String dataSourceNew, final String dataSource1, final String dataSource2) {
        final TestContext context = TafTestContext.getContext();
        context.removeDataSource(dataSourceNew);
        if (context.doesDataSourceExist(dataSource1) && context.doesDataSourceExist(dataSource2)) {
            final TestDataSource<DataRecord> source1 = copy(context.dataSource(dataSource1));
            final TestDataSource<DataRecord> source2 = copy(context.dataSource(dataSource2));
            final TestDataSource<DataRecord> mergedSource = merge(source1, source2);
            context.addDataSource(dataSourceNew, shared(mergedSource));
            debugScope(LOGGER, dataSourceNew);
        } else {
            LOGGER.debug("INPUT DATA SOURCES {}, {} DO NOT EXIST", dataSource1, dataSource2);
        }
    }

    @Deprecated
    public boolean isRealNodeAndSl2On() {
        final boolean isRealNodeAndSl2On = SetupAndTeardownScenario.isRealNode() && SetupAndTeardownScenario.isSl2On();
        LOGGER.info(" ***** Detected node in SL2 state - isRealNodeAndSl2On = " + String.valueOf(isRealNodeAndSl2On));
        return isRealNodeAndSl2On;
    }

    /**
     * Set MOs Data collection for debug to nscs.MOsDataCollectionForDebug TAF property
     *
     * @param get_MOs_for_debug_purpose
     *            String
     */
    public static void MOsDataCollectionForDebug(final String get_MOs_for_debug_purpose) {
        DataHandler.getConfiguration().setProperty("nscs.MOsDataCollectionForDebug", get_MOs_for_debug_purpose);
        LOGGER.info("nscs.MOsDataCollectionForDebug =" + DataHandler.getConfiguration().getProperty("nscs.MOsDataCollectionForDebug").toString());
    }

    @Deprecated
    public void enableDisableLogs(final String scriptString, final String scenario) {
        final Predicate<DataRecord> predicateAmos = userRoleSuiteNamePredicate("roles", SetupAndTeardownScenarioSl2.amosRolesList());
        final DataRecord amosUserDataRecord = Iterables.getFirst(availableUserFiltered(predicateAmos), null);

        final TestDataSource<DataRecord> nodesList = context.dataSource(NODES_TO_ADD);
        for (final Iterator<DataRecord> it = nodesList.iterator(); it.hasNext();) {
            String nodeName = "";
            final DataRecord next = it.next();
            if (next.getFieldValue("platformType").equals("CPP")) {
                nodeName = next.getFieldValue("networkElementId");
                LOGGER.info("Starting dumpcap logs collection procedure on node " + nodeName);
                try {
                    enableDisableTELogsInAMOS(nodeName, amosUserDataRecord, scriptString, scenario);
                } catch (final IOException e) {
                    LOGGER.error(String.format("Caught IOException: %s", e.getMessage()));
                } catch (final JSchException e) {
                    LOGGER.error(String.format("Caught JSchException: %s", e.getMessage()));
                } catch (final SftpException e) {
                    LOGGER.error(String.format("Caught SftpException: %s", e.getMessage()));
                }
            }
        }
    }

    /**
     *
     * This Scenario method cleanUp the proxyAccounts created in Ldap Test Scenarios (CLI and REST use cases)
     *
     */
    public void cleanUpProxyAccount() {
        final TestDataSource<DataRecord> ldapRemoveProxyAccount = fromCsv(PATH_LDAP + "Ldap_RemoveProxyAccount.csv");
        context.addDataSource(LDAP_CLEANUP_PROXY_DATA_SOURCE, merge(ldapRemoveProxyAccount, buildProxyAccountSpecificDataSource()));
        debugScope(LOGGER, LDAP_CLEANUP_PROXY_DATA_SOURCE);
        final TestScenario cleanUpProxyAccounts = scenario("CleanUp Proxy Accounts")
                .addFlow(utilityFlows.login(PredicateUtil.nsuLdap(), vUser))
                .addFlow(proxyAccountFlows.cleanUpProxyAccount(LDAP_CLEANUP_PROXY_DATA_SOURCE))
                .addFlow(utilityFlows.logout(PredicateUtil.nsuLdap(), vUser))
                .alwaysRun().withExceptionHandler(ScenarioExceptionHandler.LOGONLY)
                .build();
        startScenario(cleanUpProxyAccounts);
    }

    /**
     * This method creates a specific DataSource to be used in the "Tear Down" Ldap Scenarios
     * to remove the orphans proxy accounts created.
     * bindDnList is retrieved by method "ProxyAccountsUtils.getBindDnList()" that must
     * populate with the proper bindDn(s) to remove during the Ldap scenarios execution.
     *
     * @return TestDataSource
     */
    public static TestDataSource<DataRecord> buildProxyAccountSpecificDataSource() {
        final Map<String, Object> map = new java.util.HashMap<>();
        final List<Map<String, Object>> data = new java.util.ArrayList<>();

        final List<String> bindDnList = ProxyAccountsUtils.getBindDnList();
        int index = 0;
        String dump = "\n\nRemoving bindDn:\n";
        for (final String bindDn : bindDnList) {
            index++;
            map.put(BIND_DN + index, bindDn);
            dump = dump.concat("\t" + bindDn + "\n");
        }
        LOGGER.info(dump);
        map.put(N_OF_BIND_DN, String.valueOf(index));
        map.put(EXPECTED_RESPONSE_SET, String.format("Successfully updated all %s proxy accounts.", index));
        map.put(EXPECTED_RESPONSE_SUCCESS, String.format("Successfully deleted all %s proxy accounts.", index));
        data.add(map);
        final TestDataSource<DataRecord> dr = TestDataSourceFactory.createDataSource(data);
        return dr;
    }

}
