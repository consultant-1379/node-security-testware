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
import static com.ericsson.cifwk.taf.datasource.TafDataSources.fromTafDataProvider;
import static com.ericsson.cifwk.taf.datasource.TafDataSources.merge;
import static com.ericsson.cifwk.taf.datasource.TafDataSources.shareDataSource;
import static com.ericsson.cifwk.taf.datasource.TafDataSources.shared;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.dataSource;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.scenario;
import static com.ericsson.nms.security.nscs.constant.Constants.NO_PROFILE;
import static com.ericsson.nms.security.nscs.constant.Constants.PROFILE_CREATE_NODES;
import static com.ericsson.nms.security.nscs.constant.Constants.PROFILE_HYDRA;
import static com.ericsson.nms.security.nscs.constant.Constants.PROFILE_LOCAL_INFO;
import static com.ericsson.nms.security.nscs.constant.Constants.PROFILE_MAINTRACK;
import static com.ericsson.nms.security.nscs.constant.Constants.PROFILE_MAINTRACK_GATONCLOUD;
import static com.ericsson.nms.security.nscs.constant.Constants.PROFILE_REMOTE;
import static com.ericsson.nms.security.nscs.constant.Constants.PROFILE_TDM_INFO;
import static com.ericsson.nms.security.nscs.constant.Constants.PROFILE_TESTARNL_INFO;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.ADDED_NODES;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.FM_NODES;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.NODES_TO_ADD;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.ROLE_TO_CREATE;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.ROLE_TO_DELETE;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.TARGET_GROUP_TO_CREATE;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.TARGET_GROUP_TO_DELETE;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.TARGET_TO_ASSIGN;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.USERS_TO_CREATE;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.USERS_TO_DELETE;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.USERS_TO_UPDATE;
import static com.ericsson.oss.testware.fm.api.constants.FmCommonDataSources.SUPERVISION_DISABLE_NODES;
import static com.ericsson.oss.testware.fm.api.constants.FmCommonDataSources.SUPERVISION_ENABLE_NODES;
import static com.ericsson.oss.testware.fm.api.constants.FmCommonDataSources.SUPERVISION_STATUS_NODES;
import static com.ericsson.oss.testware.network.operators.netsim.NetsimDataProvider.updateDataSourceFromNetsim;
import static com.ericsson.oss.testware.nodesecurity.steps.Sl2TestSteps.SlDataSource.SL_GET_STATUS;
import static com.google.common.collect.Iterables.filter;
import static com.google.common.truth.Truth.assertThat;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import javax.inject.Inject;

import org.assertj.core.api.Assertions;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testng.ITestContext;
import org.testng.annotations.AfterSuite;
import org.testng.annotations.BeforeSuite;
import org.testng.annotations.Optional;
import org.testng.annotations.Parameters;

import com.ericsson.cifwk.taf.TafTestContext;
import com.ericsson.cifwk.taf.TestContext;
import com.ericsson.cifwk.taf.configuration.TafConfiguration;
import com.ericsson.cifwk.taf.data.DataHandler;
import com.ericsson.cifwk.taf.data.pool.DataPoolStrategy;
import com.ericsson.cifwk.taf.datasource.DataRecord;
import com.ericsson.cifwk.taf.datasource.DataRecordImpl;
import com.ericsson.cifwk.taf.datasource.MapSource;
import com.ericsson.cifwk.taf.datasource.TafDataSourceFactory;
import com.ericsson.cifwk.taf.datasource.TestDataSource;
import com.ericsson.cifwk.taf.datasource.TestDataSourceFactory;
import com.ericsson.cifwk.taf.datasource.UnknownDataSourceTypeException;
import com.ericsson.cifwk.taf.scenario.TestScenario;
import com.ericsson.cifwk.taf.scenario.TestScenarioRunner;
import com.ericsson.cifwk.taf.scenario.api.TestScenarioBuilder;
import com.ericsson.nms.security.nscs.datasource.DataSourceException;
import com.ericsson.nms.security.nscs.flow.AddRemoveNodesFlow;
import com.ericsson.nms.security.nscs.flow.UtilityFlows;
import com.ericsson.nms.security.nscs.predicate.PredicateUtil;
import com.ericsson.nms.security.nscs.utils.Utils;
import com.ericsson.oss.testware.fm.flows.CommonCsvLoader;
import com.ericsson.oss.testware.fm.flows.CommonFlowHelper;
import com.ericsson.oss.testware.fm.flows.FmAlarmSupervisionFlows;
import com.ericsson.oss.testware.nodesecurity.utils.SecurityUtil;
import com.ericsson.oss.testware.scenario.PrintDatasourceHelper;
import com.google.common.base.Predicate;
import com.google.common.base.Predicates;
import com.google.common.collect.Iterables;
import com.google.common.collect.Maps;

/**
 * SetupAndTeardownScenarioRealNode necessary operations that must be executed before and after every test suite.
 */
@SuppressWarnings({"PMD.LawOfDemeter", "PMD.ExcessiveImports", "PMD.GodClass", "PMD.NcssCount", "PMD.AvoidCatchingGenericException"})
public abstract class SetupAndTeardownScenario extends SetupAndTearDownUtil {

    public static final String TARGET_GROUP_TO_CREATE_CSV = "tbac/targetGroupToCreate.csv";
    public static final String TARGETS_TO_ASSIGN_CSV = "tbac/targetsToAssign.csv";
    public static final String TARGET_GROUP_TO_ASSIGN_CSV = "tbac/targetGroupToAssign.csv";
    public static final String LOCAL_CSV_FILE = "nodesToAdd/nodesToAdd.csv";

    private static final String LOGGER_INFO_SIZE_ONLY = "\n \t %s: SIZE = %s\n";
    private static final String LOGGER_INFO = "\n \t %s (SIZE = %s)\n %s \n";
    private static final String SUITE_NAME = "suiteName";
    private static boolean isRfa250;
    private static boolean isRealNode;
    private static String profile;

    private static String agat;

    @Inject
    protected UtilityFlows utilityFlows;
    @Inject
    protected ScenarioUtility scenarioUtility;
    @Inject
    protected PrintDatasourceHelper printDatasourceHelper;
    @Inject
    protected AddRemoveNodesFlow addRemoveNodesFlow;

    private String[] groups; // Must be defined as 'String[]' not 'String'

    public static String getProfile() {
        return profile;
    }

    public static boolean isRfa250() {
        return isRfa250;
    }

    public static boolean isRealNode() {
        return isRealNode;
    }

    public static String getAgat() {
        return agat;
    }

    public static void setAgat(final String agatValue) {
        agat = agatValue;
    }

    public static boolean isAgat() {
        return agat != null && Boolean.valueOf(agat).booleanValue();
    }

    private static final Logger LOGGER = LoggerFactory.getLogger(SetupAndTeardownScenario.class);

    public static boolean isSl2On() {

        LOGGER.info("******** SL_GET_STATUS DataSource value  ************ " );
        ScenarioUtility.debugScope(LOGGER, SL_GET_STATUS);

        final TestContext context = TafTestContext.getContext();
        final Iterable<DataRecord> securityLevel = Iterables.filter(
                context.dataSource(SL_GET_STATUS),
                PredicateUtil.genericPredicate("Node Security Level", Arrays.asList("level 2")));
        final boolean isSL2StateON = !Iterables.isEmpty(securityLevel);
        LOGGER.info("isSL2StateON detected = " + String.valueOf(isSL2StateON));
        return !Iterables.isEmpty(securityLevel);
    }

    protected Logger getLogger() {
        return LoggerFactory.getLogger(this.getClass());
    }

    protected boolean isRbacRequested() {
        getLogger().info("\n  isRfa250 [{}] groups [{}] groups.length [{}]\n", isRfa250, Arrays.toString(groups), groups.length);
        // groups.length = 0 or groups.length > 1
        final boolean isRbacRequested = !isRfa250 || isRfa250 && groups.length != 1;
        getLogger().info("\n  isRbacRequested [{}]\n", isRbacRequested);
        return isRbacRequested;
    }

    protected boolean isTbacRequested() {
        return false;
    }

    protected boolean isSynchNodeRequested() {
        return true;
    }

    protected boolean isFmSupervisionRequested() {
        return true;
    }

    protected boolean isSlGetRequested() {
        return false;
    }

    protected boolean isCredentialsCreateRequested() {
        return true;
    }

    private Predicate<DataRecord> userMngCustomRole() {
        return PredicateUtil.userRoleSuiteNamePredicate("roles", rbacCustomRolesList());
    }

    private Predicate<DataRecord> roleMngCustomRole() {
        return PredicateUtil.userRoleSuiteNamePredicate("name", rbacCustomRolesList());
    }

    //Http timeouts [https://jira-oss.seli.wh.rnd.internal.ericsson.com/browse/TORF-650322]
    private final String HTTP_CONNECTION_TIME_TO_LIVE = "connection.time.to.live";
    private final String HTTP_IDLE_CONNECTION_TIMEOUT = "idle.connection.timeout";

    @Override
    public Predicate<DataRecord> netSimTest() {
        return PredicateUtil.netSimTestPredicate();
    }

    @Override
    public Predicate<DataRecord> correctNodeType() {
        getLogger().debug("\n SetupAndTeardownScenario correctNodeType \n");
        return PredicateUtil.passTrue();
    }

    @Override
    public List<String> rbacCustomRolesList() {
        getLogger().debug("\n SetupAndTeardownScenario rbacCustomRoles \n");
        return Arrays.asList();
    }

    @Override
    public Iterable<DataRecord> filterUsers(final Iterable<DataRecord> userList) {
        return Iterables.filter(userList, isRfa250 ? PredicateUtil.nscsAdm() : userMngCustomRole());
    }

    @Override
    public Iterable<DataRecord> filterUsersForTbac() {
        return Iterables.filter(context.dataSource(USERS_TO_CREATE), Predicates.or(PredicateUtil.nscsAdm(), PredicateUtil.nscsOper()));
    }

    @BeforeSuite(alwaysRun = true, groups = { "Functional", "NSS", "RFA250", "ARNL", "KGB", "ENM_EXTERNAL_TESTWARE" })
    @Parameters({ "agat" })
    public void onBeforeSuite(final ITestContext suiteContext, @Optional final String agat) {
        onBeforeSuiteMethod(suiteContext, agat);
    }

    protected void configureTlsVersion(final String tlsVersion) {
        scenarioUtility.configureTlsVersion(tlsVersion);
    }

    /**
     * Sequence of operations to be performed before the execution of the scenario.
     */
    protected void onBeforeSuiteMethod(final ITestContext suiteContext, final String isAgat) {
        SetupAndTeardownScenario.setAgat(isAgat);
        getLogger().info("\n onBeforeSuiteMethod START \n");
        //
        // Set HTTP connection timeouts according to [https://jira-oss.seli.wh.rnd.internal.ericsson.com/browse/TORF-650322].
        //
        System.setProperty(HTTP_CONNECTION_TIME_TO_LIVE, SecurityUtil.getPropertyKeyString(HTTP_CONNECTION_TIME_TO_LIVE));
        System.setProperty(HTTP_IDLE_CONNECTION_TIMEOUT, SecurityUtil.getPropertyKeyString(HTTP_IDLE_CONNECTION_TIMEOUT));
        LOGGER.info("[TORF-650322]onBeforeSuite System.getProperty - HTTP connection.time.to.live = " + System.getProperty(HTTP_CONNECTION_TIME_TO_LIVE));
        LOGGER.info("[TORF-650322]onBeforeSuite System.getProperty - HTTP idle.connection.timeout = " + System.getProperty(HTTP_IDLE_CONNECTION_TIMEOUT));
        // Fetch current profile
        final TafConfiguration tafConfiguration = DataHandler.getConfiguration();
        setupRelevantParameter(tafConfiguration, suiteContext);
        // Initialize DataSources
        try {
            standardDataSourceFromProfileConfiguration(profile);
        } catch (final DataSourceException e) {
            e.printStackTrace();
        }
        setupSpecificDataSource();
        realignStandardDataSourceAfterSetupSpecificDataSource(profile);
        setupRbacDataSource();
        setupTbacDataSource();
        scenarioSetupAfterBeforeSuite();
        final TestScenario scenario = beforeSuiteScenarioBuilder().build();
        final TestScenarioRunner runner = getScenarioRunner();
        runner.start(scenario);
    }

    protected TestScenarioBuilder beforeSuiteScenarioBuilder() {
        int correctVusers = getNumberOfUsers() >= 6 ? 6 : getNumberOfUsers();
        int vUser = getNumberOfNodes();
        int vRolesToCreate = Iterables.size(context.dataSource(ROLE_TO_CREATE));
        vRolesToCreate = vRolesToCreate > 0 ? vRolesToCreate : 1;
        vUser = vUser != 0 ? vUser : 1;
        correctVusers = correctVusers != 0 ? correctVusers : 1;
        final TestScenarioBuilder scenarioBuilder = scenario("Before Suite Scenario")
                .addFlow(utilityFlows.deleteUserRoles(isRbacRequested(), vRolesToCreate, true))
                .addFlow(utilityFlows.createUserRoles(isRbacRequested(), vRolesToCreate, true))
                //SUITE SETUP
                .split(utilityFlows.startNetsimNodes(netSimTest()).withVusers(vUser),
                        utilityFlows.createUsers(getNumberOfUsers()))
                .addFlow(utilityFlows.login(PredicateUtil.nscsSetupTeardownAdm(), vUser))
                .addFlow(isCredentialsCreateRequested() ? utilityFlows.createNodes(netSimTest(), vUser) : addRemoveNodesFlow.addConfirmNodes(dataSource(NODES_TO_ADD).withFilter(netSimTest())))
                .addFlow(utilityFlows.syncNodes(isSynchNodeRequested(), netSimTest(), vUser))
                .addFlow(utilityFlows.subscriptionEnableTest(isFmSupervisionRequested(), vUser))
                //SECURITY LEVEL GET no longer used here
                //.addFlow(utilityFlows.getSecurityLevel(isSlGetRequested(), vUser))
                .addFlow(utilityFlows.logout(PredicateUtil.nscsSetupTeardownAdm(), vUser))
                //TBAC SETUP
                .addFlow(utilityFlows.createTargetGroup(isTbacRequested()))
                .addFlow(utilityFlows.assignTargetsToTargetGroup(isTbacRequested()))
                .addFlow(utilityFlows.updateUsersForTbac(isTbacRequested(), getNumberOfUsers()))
                .alwaysRun();
        return scenarioBuilder;
    }

    @AfterSuite(alwaysRun = true, groups = { "Functional", "NSS", "RFA250", "ARNL", "KGB", "ENM_EXTERNAL_TESTWARE" })
    public void onAfterSuite() {
        onAfterSuiteMethod();
    }

    /**
     * Sequence of operations to be performed after the execution of the scenario.
     */
    protected void onAfterSuiteMethod() {
        LOGGER.info("[TORF-650322]onAfterSuite System.getProperty - HTTP connection.time.to.live = " + System.getProperty(HTTP_CONNECTION_TIME_TO_LIVE));
        LOGGER.info("[TORF-650322]onAfterSuite System.getProperty - HTTP idle.connection.timeout = " + System.getProperty(HTTP_IDLE_CONNECTION_TIMEOUT));
        teardownSpecificDataSource();
        final TestScenarioRunner runner = getScenarioRunner();
        final TestScenario scenario = afterSuiteScenarioBuilder().build();
        runner.start(scenario);
        if (SetupAndTeardownScenario.isAgat()) {
            this.cleanContext();
        }
    }

    protected TestScenarioBuilder afterSuiteScenarioBuilder() {
        int vUser = Iterables.size(context.dataSource(ADDED_NODES));
        int vRolesToDelete = getNumberOfNodes();
        vRolesToDelete = vRolesToDelete > 0 ? vRolesToDelete : 1;
        vUser = vUser != 0 ? vUser : 1;
        final TestScenarioBuilder scenarioBuilder = addFlowsAfterScenario()
                .addFlow(utilityFlows.login(PredicateUtil.nscsSetupTeardownAdm(), vUser))
                .addFlow(utilityFlows.restoreAlarmSupervisionState(isFmSupervisionRequested() && isAgat(), vUser))
                // removed the subscription disable if NOT AGAT
                //.addFlow(utilityFlows.subscriptionDisableTest(isFmSupervisionRequested() && !isAgat(), vUser))
                .addFlow(utilityFlows.deleteNodes(netSimTest(), vUser)).alwaysRun()
                .addFlow(utilityFlows.logout(PredicateUtil.nscsSetupTeardownAdm(), vUser)).alwaysRun()
                .addFlow(utilityFlows.deleteUsers(getNumberOfUsers())).alwaysRun()
                .addFlow(utilityFlows.deleteUserRoles(isRbacRequested(), vRolesToDelete, true))
                .addFlow(utilityFlows.deleteTargetGroup(isTbacRequested()))
                .alwaysRun();
        return scenarioBuilder;
    }

    protected TestScenarioBuilder addFlowsAfterScenario() {
        return scenario("After Suite Scenario");
    }

    /**
     * Meant to be overridden by child classes if more specific DataSources are needed.
     */
    protected abstract void setupSpecificDataSource();

    /**
     * Meant to be overridden by child classes if more specific DataSources are needed.
     */
    protected void teardownSpecificDataSource() {
    }

    /**
     * setupRelevantParameter.
     */
    private void setupRelevantParameter(final TafConfiguration tafConfiguration, final ITestContext suiteContext) {
        setSuiteName(suiteContext.getSuite().getName());
        getLogger().debug("\n SUITE NAME  = " + getSuiteName() + "\n");
        if (getSuiteName().contains("SPEC:")) {
            final int pos = getSuiteName().indexOf("SPEC:") - 1;
            setSuiteName(getSuiteName().substring(0, pos));
            getLogger().debug("\n SUITE NAME WITHOUT SPEC: =" + getSuiteName() + "\n");
        }
        profile = (String) tafConfiguration.getProperty("taf.profiles");

        groups = suiteContext.getIncludedGroups();

        final List<String> groupsList;
        if (groups.length != 0) {
            groupsList = Arrays.asList(groups);
            // Use 'contains' in place of 'equals'
            isRfa250 = groupsList.contains("RFA250") || groupsList.contains("ARNL") || groupsList.contains("ENM_EXTERNAL_TESTWARE");
        }
        // If 'groups' is not specified, default value of 'isRfa250' is kept

        // Use ad-hoc "empty(profile)" in place of standard "profile.isEmpty()", to avoid Null Pointer Exception if 'profile' value is 'null'
        if (Utils.empty(profile)) {
            profile = NO_PROFILE;
        }
        getLogger().info("\n\n The test is running with profile [{}] and groups [{}]", profile, Arrays.toString(groups));
    }

    /**
     * Method to fill in users and nodes datasources depending on the current profile.
     */
    private void standardDataSourceFromProfileConfiguration(final String profile) {
        final TestDataSource<DataRecord> localCsv;
        final Iterable<DataRecord> nodesFiltered;
        final Map<String, Object> emptyMap = Maps.newHashMap();
        TestDataSource<DataRecord> nodesListReadFromDataProvider = TestDataSourceFactory.createDataSource(emptyMap);
        Iterable<DataRecord> finalNodelList = null;

        getLogger().info("\nprofile.toLowerCase()[{}]\n", profile.toLowerCase());

        switch (profile.toLowerCase()) {
            case PROFILE_MAINTRACK:
            case PROFILE_MAINTRACK_GATONCLOUD:
                localCsv = fromCsv(LOCAL_CSV_FILE);
                Assertions.assertThat(0).as("LOCAL CSV FILE EMPTY").isNotEqualTo(Iterables.size(localCsv));
                getLogger().debug(String.format(LOGGER_INFO_SIZE_ONLY, "LOCAL FILE", Iterables.size(localCsv)));
                nodesFiltered = Iterables.filter(localCsv, PredicateUtil.suiteNamePredicate(SUITE_NAME, getSuiteName()));
                Assertions.assertThat(0)
                .as("LOCAL FILE FILTERED BY SUITE NAME EMPTY").isNotEqualTo(Iterables.size(nodesFiltered));
                final HashMap configuration = new HashMap();
                configuration.put("class", "com.ericsson.oss.testware.network.operators.netsim.NetsimDataProvider");
                configuration.put("nodes.maintrack.id", getSuiteName());
                final MapSource configurationSource = new MapSource(configuration);
                try {
                    nodesListReadFromDataProvider = TafDataSourceFactory.dataSourceOfType("class", configurationSource, DataPoolStrategy.STOP_ON_END);
                } catch (final UnknownDataSourceTypeException e) {
                    e.printStackTrace();
                }
                getLogger().debug(String.format(LOGGER_INFO, "REMOTE FILE",
                        Iterables.size(nodesListReadFromDataProvider), Iterables.toString(nodesListReadFromDataProvider))
                        .replace(", Data value: ", ",\nData value: "));
                Assertions.assertThat(Iterables.size(nodesFiltered)).isNotEqualTo(0)
                .as("\n REMOTE FILE IS EMPTY \n");
                SetupAndTearDownUtil.removeAndCreateTestDataSource(NODES_TO_ADD + "_LOCAL", nodesFiltered);
                final TestDataSource<DataRecord> mergedNodeList = merge(context.dataSource(NODES_TO_ADD + "_LOCAL"), nodesListReadFromDataProvider);
                getLogger().debug(String.format(LOGGER_INFO, "MERGED FILE",
                        Iterables.size(mergedNodeList), Iterables.toString(mergedNodeList)).replace(", Data value: ", ",\nData value: "));
                finalNodelList = Iterables.filter(mergedNodeList, correctNodeType());
                Assertions.assertThat(Iterables.size(finalNodelList)).isNotEqualTo(0).as(" \n MERGE MT AND LOCAL FILE FAILED \n");
                SetupAndTearDownUtil.removeAndCreateTestDataSource(NODES_TO_ADD, finalNodelList);
                context.removeDataSource(NODES_TO_ADD + "_LOCAL");
                break;
            case PROFILE_REMOTE:
            case PROFILE_TDM_INFO:
            case PROFILE_HYDRA:
                try {
                    nodesListReadFromDataProvider = copy(fromTafDataProvider(NODES_TO_ADD));
                } catch (final NullPointerException e) {
                    final String message = e.getMessage() == null ? "" : e.getMessage();
                    throw new DataSourceException(message);
                }
                nodesFiltered = filter(nodesListReadFromDataProvider,
                        PredicateUtil.suiteNamePredicate(SUITE_NAME, getSuiteName()));
                finalNodelList = filter(nodesFiltered, correctNodeType());
                SetupAndTearDownUtil.removeAndCreateTestDataSource(NODES_TO_ADD, finalNodelList);
                break;
            case PROFILE_TESTARNL_INFO:
            case PROFILE_LOCAL_INFO:
            case PROFILE_CREATE_NODES:
            case NO_PROFILE:
                localCsv = fromCsv(LOCAL_CSV_FILE);
                Assertions.assertThat(0).as("LOCAL CSV FILE EMPTY").isNotEqualTo(Iterables.size(localCsv));
                getLogger().debug(String.format(LOGGER_INFO_SIZE_ONLY, "LOCAL FILE", Iterables.size(localCsv)));
                nodesFiltered = Iterables.filter(localCsv, PredicateUtil.suiteNamePredicate(SUITE_NAME, getSuiteName()));
                Assertions.assertThat(0)
                .as("LOCAL FILE FILTERED BY SUITE NAME EMPTY").isNotEqualTo(Iterables.size(nodesFiltered));
                final Iterable<DataRecord> nodesWithIp = Iterables.transform(
                        nodesFiltered, updateDataSourceFromNetsim());
                Assertions.assertThat(Iterables.size(nodesFiltered))
                .as("LOCAL FILE FILTERED BY SUITE NAME AND IP EMPTY").isNotEqualTo(0);
                finalNodelList = Iterables.filter(nodesWithIp, correctNodeType());
                getLogger().debug("\n NODE FROM CSV SPECIFIC SUITE NAME FILTERED BY NODETYPE \n" + Iterables.toString(finalNodelList)
                .replace(", Data value: ", ",\nData value: ") + "\n");
                assertThat(Iterables.size(finalNodelList)).isNotEqualTo(0);
                SetupAndTearDownUtil.removeAndCreateTestDataSource(NODES_TO_ADD, finalNodelList);
                break;
            default:
                Assertions.assertThat(true).as("Incorrect taf.profiles value specified: " + profile).isFalse();
                break;
        }
        int numOfRowint = Iterables.size(context.dataSource(NODES_TO_ADD));
        numOfRowint = numOfRowint != 0 ? numOfRowint : 1;
        setNumberOfNodes(numOfRowint);
        isRealNode = Iterables.isEmpty(Iterables.filter(context.dataSource(NODES_TO_ADD), netSimTest()));
    }

    /**
     * Method to fill in users and nodes datasources depending on the current profile.
     */
    private void realignStandardDataSourceAfterSetupSpecificDataSource(final String profile) {
        CommonCsvLoader.initLibraryDataSource();
        CommonFlowHelper.initFmNodesFromNodeToAdd();
        FmAlarmSupervisionFlows.subscriptionEnableDataSource();
        FmAlarmSupervisionFlows.subscriptionDisableDataSource();
        context.addDataSource(FM_NODES, shared(context.dataSource(FM_NODES)));
        switch (profile.toLowerCase()) {
            case PROFILE_TESTARNL_INFO:
            case PROFILE_REMOTE:
            case PROFILE_TDM_INFO:
            case PROFILE_HYDRA:
                context.addDataSource(ADDED_NODES, context.dataSource(NODES_TO_ADD));
                shareDataSource(ADDED_NODES);
                break;
            default:
                break;
        }
        // Fill in users datasources based on current profile.
        // We want to add a timestamp only for Local and Maintrack.
        final TestDataSource originalDataSource = fromTafDataProvider(USERS_TO_CREATE);
        printDatasourceHelper.printDataSource(originalDataSource, "Users from DataProvider");
        final Iterable<DataRecord> userList = copy(originalDataSource);
        printDatasourceHelper.printDataSource(userList, "Users after Copy");

        // final Iterable<DataRecord> userList = copy(fromTafDataProvider(USERS_TO_CREATE));
        getLogger().info("\n userList \n" + Iterables.toString(userList).replace(", Data value: ", ",\nData value: "));
        final Iterable<DataRecord> userListFilter = filterUsers(userList);
        final int numUsers = Iterables.size(userListFilter);
        removeAndCreateTestDataSource(USERS_TO_CREATE, userListFilter);
        ScenarioUtility.debugScope(getLogger(), USERS_TO_CREATE);
        //context.addDataSource(USERS_TO_CREATE, copy(userList));
        context.addDataSource(USERS_TO_DELETE, context.dataSource(USERS_TO_CREATE));
        setNumberOfUsers(numUsers);
        getLogger().info("\n \n TESTWARE DATASOURCES SETUP-TEAR - DEBUG DUMP -- START ");
        ScenarioUtility.dumpDataSource();
        ScenarioUtility.debugScope(getLogger(), SUPERVISION_ENABLE_NODES);
        ScenarioUtility.debugScope(getLogger(), SUPERVISION_DISABLE_NODES);
        ScenarioUtility.debugScope(getLogger() , SUPERVISION_STATUS_NODES);
        getLogger().info("\n \n TESTWARE DATASOURCES SETUP-TEAR - DEBUG DUMP -- END ");
    }

    protected void setupRbacDataSource() {
        if (isRbacRequested()) {
            final TestDataSource<DataRecord> rbacRoles = copy(fromTafDataProvider(ROLE_TO_CREATE));
            getLogger().debug("\n RBAC USER ROLES \n" + Iterables.toString(rbacRoles).replace(", Data value: ", ",\nData value: ") + " \n");
            final Iterable<DataRecord> roleFiltered = Iterables.filter(rbacRoles, roleMngCustomRole());
            getLogger()
            .debug("\n RBAC USER ROLES FILTERED \n" + Iterables.toString(roleFiltered).replace(", Data value: ", ",\nData value: ") + " \n");
            removeAndCreateTestDataSource(ROLE_TO_CREATE, roleFiltered);
            context.addDataSource(ROLE_TO_DELETE, shared(context.dataSource(ROLE_TO_CREATE)));
            ScenarioUtility.debugScope(getLogger(), ROLE_TO_CREATE);
            ScenarioUtility.debugScope(getLogger(), ROLE_TO_DELETE);
        }
    }

    private void setupTbacDataSource() {
        getLogger().debug("\n \n SETUP TBAC DATASOURCE START \n");
        final Iterable<DataRecord> users = filterUsersForTbac();
        getLogger().debug("\n users \n" + Iterables.toString(users).replace(", Data value: ", ",\nData value: ") + "\n");
        final TestDataSource<DataRecord> targetGroupToCreate = fromCsv(TARGET_GROUP_TO_CREATE_CSV);
        final TestDataSource<DataRecord> targetGroupToAssign = fromCsv(TARGET_GROUP_TO_ASSIGN_CSV);
        final DataRecord tgToCreateRecord = Iterables.getFirst(targetGroupToCreate, null);
        final DataRecord tgToAssignRecord = Iterables.getFirst(targetGroupToAssign, null);
        String tgName = "";
        final long nanoTime = System.nanoTime();
        for (final Iterator<DataRecord> it = users.iterator(); it.hasNext(); ) {
            final DataRecord userRecord = it.next();
            final String username = userRecord.getFieldValue("username");
            final String firstName = userRecord.getFieldValue("firstName");
            final String[] roles = userRecord.getFieldValue("roles");
            final StringBuilder roleName = new StringBuilder("");
            for (final String role : roles) {
                final String str = role + ",";
                roleName.append(str);
            }
            roleName.deleteCharAt(roleName.length() - 1);
            tgName = tgToCreateRecord.getFieldValue("targetGroupName") + String.valueOf(nanoTime / 100000);
            final Map<String, Object> tgToAssignMap = Maps.newHashMap(tgToAssignRecord.getAllFields());
            tgToAssignMap.put("username", username);
            tgToAssignMap.put("firstName", firstName);
            tgToAssignMap.put("roleName", roleName);
            tgToAssignMap.put("targetGroupName", tgName);
            context.dataSource(USERS_TO_UPDATE).addRecord().setFields(new DataRecordImpl(tgToAssignMap));
        }
        context.dataSource(TARGET_GROUP_TO_CREATE).addRecord().setFields(tgToCreateRecord).setField("targetGroupName", tgName);
        context.addDataSource(TARGET_GROUP_TO_DELETE, context.dataSource(TARGET_GROUP_TO_CREATE));
        final TestDataSource<DataRecord> targetsToAssign = fromCsv(TARGETS_TO_ASSIGN_CSV);
        final DataRecord targetsToAssignRecord = Iterables.getFirst(targetsToAssign, null);
        final Map<String, Object> targetsToAssignMap = Maps.newHashMap(targetsToAssignRecord.getAllFields());
        final List<String> targets = new ArrayList<>();
        final TestDataSource<DataRecord> nodesList = context.dataSource(NODES_TO_ADD);
        for (final Iterator<DataRecord> it = nodesList.iterator(); it.hasNext(); ) {
            final DataRecord nodeRecord = it.next();
            final String str = nodeRecord.getFieldValue("networkElementId");
            targets.add(str);
        }
        targetsToAssignMap.put("targets", targets);
        targetsToAssignMap.put("targetGroup", tgName);
        context.dataSource(TARGET_TO_ASSIGN).addRecord().setFields(new DataRecordImpl(targetsToAssignMap));
        getLogger().debug("\n TARGET_GROUP_TO_CREATE \n " + Iterables.toString(context.dataSource(TARGET_GROUP_TO_CREATE))
        .replace(", Data value: ", ",\nData value: ") + "\n");
        getLogger().debug("\n TARGET_GROUP_TO_DELETE \n " + Iterables.toString(context.dataSource(TARGET_GROUP_TO_DELETE))
        .replace(", Data value: ", ",\nData value: ") + "\n");
        getLogger().debug("\n TARGET_TO_ASSIGN \n " + Iterables.toString(context.dataSource(TARGET_TO_ASSIGN))
        .replace(", Data value: ", ",\nData value: ")
        + "\n");
        getLogger()
        .debug("\n USERS_TO_UPDATE \n " + Iterables.toString(context.dataSource(USERS_TO_UPDATE)).replace(", Data value: ", ",\nData value: ")
                + "\n");
        getLogger().debug("\n SETUP TBAC DATASOURCE END \n \n");
    }

    protected void scenarioSetupAfterBeforeSuite() {
    }
}
