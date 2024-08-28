package com.ericsson.nms.security.nscs.scenario;

import static com.ericsson.cifwk.taf.datasource.TafDataSources.fromCsv;
import static com.ericsson.cifwk.taf.datasource.TafDataSources.fromTafDataProvider;
import static com.ericsson.cifwk.taf.datasource.TafDataSources.shared;
import static com.ericsson.cifwk.taf.datasource.TafDataSources.transform;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.dataSource;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.runner;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.scenario;
import static com.ericsson.nms.security.nscs.constant.Constants.NO_PROFILE;
import static com.ericsson.nms.security.nscs.constants.CsvDataSourceConstants.CUSTOM_ROLES_TESTS_CSV;
import static com.ericsson.nms.security.nscs.constants.CsvDataSourceConstants.SECURITY_NODES_LOCAL_CSV;
import static com.ericsson.nms.security.nscs.constants.CsvDataSourceConstants.SECURITY_NODES_G1_CRLCHECK_LOCAL_CSV;
import static com.ericsson.nms.security.nscs.constants.CsvDataSourceConstants.SECURITY_NODES_CIPHER_MODERNIZATION_LOCAL_CSV;
import static com.ericsson.nms.security.nscs.constants.CsvDataSourceConstants.SECURITY_NODES_RBAC_LOCAL_CSV;
import static com.ericsson.nms.security.nscs.constants.CsvDataSourceConstants.SECURITY_NODES_RTSEL_LOCAL_CSV;

import static com.ericsson.nms.security.nscs.constants.SecurityConstants.NETWORK_ELEMENT_RANGE;
import static com.ericsson.nms.security.nscs.constants.SecurityConstants.SUITE_PROFILE;
import static com.ericsson.nms.security.nscs.flow.UtilityFlows.USER_ROLES_DELAY;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.NODES_TO_ADD;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.ADDED_NODES;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.ROLE_TO_CREATE;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.ROLE_TO_DELETE;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.USERS_TO_CREATE;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.USERS_TO_DELETE;
import static java.util.concurrent.TimeUnit.SECONDS;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.*;

import javax.inject.Inject;

import com.ericsson.cifwk.taf.configuration.TafConfiguration;
import com.ericsson.cifwk.taf.datasource.TafDataSources;
import com.ericsson.nms.security.nscs.constant.Constants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.cifwk.taf.TafTestBase;
import com.ericsson.cifwk.taf.TestContext;
import com.ericsson.cifwk.taf.data.DataHandler;
import com.ericsson.cifwk.taf.data.pool.DataPoolStrategy;
import com.ericsson.cifwk.taf.datasource.DataRecord;
import com.ericsson.cifwk.taf.datasource.DataRecordImpl;
import com.ericsson.cifwk.taf.datasource.TestDataSource;
import com.ericsson.cifwk.taf.datasource.TestDataSourceFactory;
import com.ericsson.cifwk.taf.handlers.netsim.domain.NetworkElement;
import com.ericsson.cifwk.taf.scenario.TestScenario;
import com.ericsson.cifwk.taf.scenario.api.ScenarioExceptionHandler;
import com.ericsson.cifwk.taf.scenario.impl.LoggingScenarioListener;
import com.ericsson.oss.testware.enmbase.data.ENMUser;
import com.ericsson.oss.testware.enmbase.scenarios.DebugLogger;
import com.ericsson.nms.security.nscs.constants.SecurityConstants;
import com.ericsson.nms.security.nscs.datasource.PredicatesExt;
import com.ericsson.nms.security.nscs.flow.*;
import com.ericsson.nms.security.nscs.utils.UtilContext;
import com.ericsson.nms.security.nscs.utils.Utils;
import com.ericsson.oss.testware.network.operators.netsim.NetsimOperator;
import com.ericsson.oss.testware.security.authentication.flows.LoginLogoutRestFlows;
import com.ericsson.oss.testware.security.gim.flows.RoleManagementTestFlows;
import com.ericsson.oss.testware.security.gim.flows.UserManagementTestFlows;
import com.google.common.base.Function;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;

@SuppressWarnings({"PMD.LawOfDemeter", "PMD.ExcessiveImports", "PMD.AvoidCatchingGenericException"})
public class BaseScenario extends TafTestBase {

    private static final Logger log = LoggerFactory.getLogger(BaseScenario.class);

    @Inject
    private RoleManagementTestFlows roleManagementFlows;

    @Inject
    private UserManagementTestFlows userManagementFlows;

    @Inject
    private AddRemoveNodesFlow addRemoveNodesFlow;

    @Inject
    private LoginLogoutRestFlows loginLogoutFlow;

    @Inject
    private NetSimFlow netsimFlow;

    @Inject
    private PkiCommandFlow pkiCommandFlow;

    @Inject
    private TestContext context;

    @Inject
    private NetsimOperator netSimOperator;

    public void executeScenario(final TestScenario scenario) {
        runner().withListener(new LoggingScenarioListener()).withListener(new DebugLogger()).build().start(scenario);
    }

    public ScenarioExceptionHandler addExceptionHandler() {
        return SecurityConstants.PROFILE_MAINTRACK.equals(UtilContext.makeUtilContext().readSuiteProfile()) ? ScenarioExceptionHandler.PROPAGATE
                : ScenarioExceptionHandler.LOGONLY;
    }

    public TestDataSource<DataRecord> loadNodes(final String fileNameNodes, final String dataSourceNameTmp) {
        log.debug("loading csv [{}]", Utils.getSourcePath() + fileNameNodes);
        context.addDataSource(dataSourceNameTmp, fromCsv(Utils.getSourcePath() + fileNameNodes, DataPoolStrategy.STOP_ON_END));
        final List<Map<String, Object>> rows = Utils.copyDataSource(context.dataSource(dataSourceNameTmp), dataSourceNameTmp);
        final List<Map<String, Object>> nodesToAddDataSource = new ArrayList<>();
        for (final Map<String, Object> row : rows) {
            final String suiteProfile = (String) row.get(SUITE_PROFILE);
            if (PredicatesExt.filterByProfile(suiteProfile)) {
                final String nodeNameRange = (String) row.get(NETWORK_ELEMENT_RANGE);
                final List<String> nodeList = Utils.generateNodeNames(nodeNameRange);
                if (nodeList != null && !nodeList.isEmpty()) {
                    for (final String nodeName : nodeList) {
                        final Map<String, Object> m = addRow(row, nodesToAddDataSource);
                        m.put(SecurityConstants.NETWORK_ELEMENT_ID, nodeName);
                        m.put(SecurityConstants.OSS_PREFIX, "MeContext=" + nodeName);
                        m.remove(NETWORK_ELEMENT_RANGE);
                    }
                } else {
                    addRow(row, nodesToAddDataSource);
                }
            }
        }
        return TestDataSourceFactory.createDataSource(nodesToAddDataSource);
    }

    private Map<String, Object> addRow(final Map<String, Object> row, final List<Map<String, Object>> nodesToAddDataSource) {
        final Map<String, Object> m = new HashMap<>();
        m.putAll(row);
        nodesToAddDataSource.add(m);
        return m;
    }

    public void loadDefaultUsersToCreate(final List<String> requestedRoles, final String userPathCsv) {
        log.info("loading csv [{}]", userPathCsv);
        for (final DataRecord ds : Lists.newArrayList(fromCsv(userPathCsv, ENMUser.class).iterator())) {
            final Map<String, Object> changedUser = Maps.newHashMap();
            changedUser.putAll(ds.getAllFields());
            final String roles = ds.getFieldValue("roles");
            if (requestedRoles.contains(roles)) {
                final DataRecordImpl changedUserImpl = new DataRecordImpl(changedUser);
                context.dataSource(USERS_TO_CREATE).addRecord().setFields(changedUserImpl);
                context.dataSource(USERS_TO_DELETE).addRecord().setFields(changedUserImpl);
            }
        }
    }

    public void loadCustomRolesToCreate(final List<String> requestedRoles) {
        log.info("loading csv [{}]", CUSTOM_ROLES_TESTS_CSV);
        for (final DataRecord ds : Lists.newArrayList(fromCsv(CUSTOM_ROLES_TESTS_CSV, ENMUser.class).iterator())) {
            final Map<String, Object> changedUser = Maps.newHashMap();
            changedUser.putAll(ds.getAllFields());
            final String roles = ds.getFieldValue("name");
            if (requestedRoles.contains(roles)) {
                final DataRecordImpl changedUserImpl = new DataRecordImpl(changedUser);
                context.dataSource(ROLE_TO_CREATE).addRecord().setFields(changedUserImpl);
                context.dataSource(ROLE_TO_DELETE).addRecord().setFields(changedUserImpl);
            }
        }
    }

    public void createUserRoleScenario() {
        final TestScenario scenario = scenario("Secadm Rbac Create Role Definition scenario").addFlow(roleManagementFlows.createRole())
                .addFlow(addRemoveNodesFlow.addDelay(USER_ROLES_DELAY, SECONDS))
                .addFlow(userManagementFlows.createUser()).build();
        executeScenario(scenario);
    }

    public void cleanSetupEnvironment() {
        final TestScenario scenario = scenario("Secadm Rbac Clean Setup Environment").addFlow(userManagementFlows.deleteUser())
                .addFlow(roleManagementFlows.deleteRole()).withExceptionHandler(ScenarioExceptionHandler.LOGONLY).build();
        executeScenario(scenario);
    }

    public void loadDataSourcesByProfile(final String dataprovidername) {
        log.info("\n------- loadDataSourceByProfile -------\n");

        // From 'SetupAndTeardownScenario' (is it: "maintrack_gatoncloud"): Begin... ?
        final TafConfiguration tafConfiguration = DataHandler.getConfiguration();
        String tafProfile = tafConfiguration.getProperty("taf.profiles", "", String.class);
        if (tafProfile.isEmpty()) {
            tafProfile = NO_PROFILE;
        }
        log.info("The test is running with profile (-Dtaf.profiles): [{}]" + tafProfile);
        // From 'SetupAndTeardownScenario': ...End.

        final String suiteProfile = UtilContext.makeUtilContext().readSuiteProfile();
        if (SecurityConstants.PROFILE_MAINTRACK.equals(suiteProfile) ||
                (!SecurityConstants.PROFILE_MAINTRACK.equals(suiteProfile) && Constants.PROFILE_MAINTRACK_GATONCLOUD.equals(tafProfile))) {
            // Insert into context - in nodesToAdd key, the TestDataSource<DataRecord> datasource - returned by fromTafDataProvider(dataprovidername)
            final TestDataSource<DataRecord> netSimNode = fromTafDataProvider(dataprovidername);
            if ("nodesToAdd_Rbac".equals(dataprovidername)) {
                log.info("\n------- ENTERED IF \"nodesToAdd_Rbac\" -------\n");
                final TestDataSource<DataRecord> noNetSimNode = fromCsv(
                        "profiles/nodes/SecurityNodeList_Rbac_NoNetSimNode.csv");
                context.addDataSource(NODES_TO_ADD, TafDataSources.combine(netSimNode, noNetSimNode));
            } else {
                log.info("\n------- ENTERED ELSE -------\n");
                context.addDataSource(NODES_TO_ADD, netSimNode);
            }
        } else {
            final String dataSourceNameTmp = "nodesToAddTmp";
            final TestDataSource<DataRecord> nodeDS = loadNodes(SECURITY_NODES_LOCAL_CSV, dataSourceNameTmp);
            context.addDataSource(NODES_TO_ADD, shared(transform(nodeDS, getIpFromNetSim())));
        }
    }

    public void loadDataSourcesForG1ByProfile(final String dataprovidername) {
        log.info("\n------- loadDataSourceByProfile For G1 CRLCheck-------\n");
        if (SecurityConstants.PROFILE_MAINTRACK.equals(UtilContext.makeUtilContext().readSuiteProfile())) {
            context.addDataSource(NODES_TO_ADD, fromTafDataProvider(dataprovidername));
        } else {
            final String dataSourceNameTmp = "nodesToAddTmp";
            final TestDataSource<DataRecord> nodeDS = loadNodes(SECURITY_NODES_G1_CRLCHECK_LOCAL_CSV, dataSourceNameTmp);
            context.addDataSource(NODES_TO_ADD, shared(transform(nodeDS, getIpFromNetSim())));
        }
    }

    public void beforeSuite(final String dataprovidername, final String suiteNscsProfiles) {
        log.info("******** setUpEnvironment ********");
        UtilContext.makeUtilContext().setProfile(suiteNscsProfiles);
        final String profile = UtilContext.makeUtilContext().readSuiteProfile();
        log.info("Suite starting with [{}] profile", profile);
        loadDataSourcesByProfile(dataprovidername);
        if (profile.equals(SecurityConstants.PROFILE_MAINTRACK)) {
            createSetup();
            //            createSetupParallel();
        } else {
            createSetupFull();
        }
    }

    public void beforeSuiteForRbac(final String dataprovidername) {
        loadDataSourcesByProfile(dataprovidername);
        createSetupRbac();
    }

    private void createSetup() {
        final TestScenario scenario = scenario("Setup Scenario").addFlow(loginLogoutFlow.loginDefaultUser())
                .addFlow(addRemoveNodesFlow.addConfirmNodes(dataSource(NODES_TO_ADD).withFilter(PredicatesExt.byProfile)))
                .addFlow(netsimFlow.startNode()).addFlow(netsimFlow.radioNode())
                .addFlow(addRemoveNodesFlow.createDefaultCredential(PredicatesExt.nodesToSync))
                .addFlow(addRemoveNodesFlow.syncNodes(dataSource(ADDED_NODES).withFilter(PredicatesExt.nodesToSync)))
                .addFlow(pkiCommandFlow.enableSha1()).addFlow(loginLogoutFlow.logout()).build();
        executeScenario(scenario);
    }

    public void createSetupRbac() {
        final TestScenario scenario = scenario("Setup Scenario Rbac").addFlow(loginLogoutFlow.loginDefaultUser())
                .addFlow(addRemoveNodesFlow.addConfirmNodes(dataSource(NODES_TO_ADD).withFilter(PredicatesExt.byProfile)))
                .addFlow(netsimFlow.startNode()).addFlow(addRemoveNodesFlow.createDefaultCredential(PredicatesExt.nodesToSync))
                .addFlow(addRemoveNodesFlow.syncNodes(dataSource(ADDED_NODES).withFilter(PredicatesExt.nodesToSync)))
                .addFlow(pkiCommandFlow.enableSha1()).addFlow(loginLogoutFlow.logout()).build();
        executeScenario(scenario);
    }

    private void createSetupFull() {
        log.info("starting createSetupFull... profile " + UtilContext.makeUtilContext().readSuiteProfile());
        try {
            final TestScenario scenario = scenario("Setup Scenario Full").addFlow(loginLogoutFlow.loginDefaultUser())
                    .addFlow(addRemoveNodesFlow.addConfirmNodes(dataSource(NODES_TO_ADD).withFilter(PredicatesExt.byProfile)))
                    .addFlow(netsimFlow.startNode()).addFlow(netsimFlow.radioNode())
                    .addFlow(addRemoveNodesFlow.createDefaultCredential(PredicatesExt.nodesToSync))
                    .addFlow(addRemoveNodesFlow.syncNodes(dataSource(ADDED_NODES).withFilter(PredicatesExt.nodesToSync)))
                    .addFlow(pkiCommandFlow.enableSha1()).addFlow(netsimFlow.addPatch()).addFlow(loginLogoutFlow.logout()).build();
            executeScenario(scenario);
        } catch (final Exception ex) {
            log.error("error on createSetupFull... " + ex.getMessage(), ex);
        }
    }

    public void createTeardown() {
        final TestScenario scenario = scenario("Teardown Scenario").addFlow(loginLogoutFlow.loginDefaultUser())
                .addFlow(addRemoveNodesFlow.deleteNodes(dataSource(ADDED_NODES).withFilter(PredicatesExt.deleteNodes)))
                .addFlow(loginLogoutFlow.logout()).build();
        executeScenario(scenario);
    }

    /**
     * Used only for <b>local</b> tests (nscs.profile=extra, nscs.profile=full). Adjust node ip address with Netsim
     *
     * @return Function DataRecord
     */
    public Function<DataRecord, DataRecord> getIpFromNetSim() {
        return new Function<DataRecord, DataRecord>() {
            @Override
            public DataRecord apply(final DataRecord input) {
                final Map<String, Object> data = Maps.newHashMap(input.getAllFields());
                final String nodeName = input.getFieldValue("networkElementId");
                log.trace("Adjusting NetSim IP Address for NodeName: " + nodeName);
                final NetworkElement networkElement = netSimOperator.getNetworkElement(nodeName);
                if (networkElement != null) {
                    final String ipAddress = networkElement.getIp();
                    log.trace(String.format("Getting ipAddress [%s] from Netsim", ipAddress));
                    try {
                        final InetAddress inetaddr = InetAddress.getByName(ipAddress);
                        if (inetaddr instanceof Inet4Address || inetaddr instanceof Inet6Address) {
                            log.trace("host address [{}]", inetaddr.getHostAddress());
                            data.put("ipAddress", inetaddr.getHostAddress());
                        }
                    } catch (final UnknownHostException e) {
                        log.warn(e.getMessage());
                    }
                } else {
                    log.trace("node [{}] NOT on Netsim", nodeName);
                }
                return new DataRecordImpl(data);
            }
        };
    }

    public void beforeSuiteCrlCheck(final String dataprovidername, final String suiteNscsProfiles) {
        log.info("******** setUpEnvironment for CRL Check ********");
        UtilContext.makeUtilContext().setProfile(suiteNscsProfiles);
        final String profile = UtilContext.makeUtilContext().readSuiteProfile();
        log.info("Suite starting with [{}] profile", profile);
        loadDataSourcesForG1ByProfile(dataprovidername);
        prepareSetup("G1_Crl_Check");
    }

    private void prepareSetup(final String setupScenarioName) {
        log.info("Starting Profile : " + setupScenarioName + UtilContext.makeUtilContext().readSuiteProfile());
        try {
            final TestScenario scenario = scenario("Setup " + setupScenarioName).addFlow(loginLogoutFlow.loginDefaultUser())
                    .addFlow(addRemoveNodesFlow.addConfirmNodes(dataSource(NODES_TO_ADD).withFilter(PredicatesExt.byProfile)))
                    .addFlow(netsimFlow.startNode()).addFlow(addRemoveNodesFlow.createDefaultCredential(PredicatesExt.nodesToSync))
                    .addFlow(addRemoveNodesFlow.syncNodes(dataSource(ADDED_NODES).withFilter(PredicatesExt.nodesToSync)))
                    .addFlow(pkiCommandFlow.enableSha1()).addFlow(loginLogoutFlow.logout()).build();
            executeScenario(scenario);
        } catch (final Exception ex) {
            log.error("Error on " + setupScenarioName + ex.getMessage(), ex);
        }
    }

    public void loadDataSourcesForG1RbacByProfile(final String dataprovidername) {
        log.info("\n------- loadDataSources for G1 Rbac ByProfile -------\n");
        if (SecurityConstants.PROFILE_MAINTRACK.equals(UtilContext.makeUtilContext().readSuiteProfile())) {
            context.addDataSource(NODES_TO_ADD, fromTafDataProvider(dataprovidername));
        } else {
            final String dataSourceNameTmp = "nodesToAddTmp";
            final TestDataSource<DataRecord> nodeDS = loadNodes(SECURITY_NODES_RBAC_LOCAL_CSV, dataSourceNameTmp);
            context.addDataSource(NODES_TO_ADD, shared(transform(nodeDS, getIpFromNetSim())));
        }
    }

    public void beforeSuiteCipherModernization(final String dataprovidername, final String suiteNscsProfiles) {
        log.info("******** setUpEnvironment for Cipher Modernization ********");
        UtilContext.makeUtilContext().setProfile(suiteNscsProfiles);
        final String profile = UtilContext.makeUtilContext().readSuiteProfile();
        log.info("Suite starting with [{}] profile", profile);
        loadDataSourcesForCipherModernization(dataprovidername);
        prepareSetup("Cipher_Modernization");
    }

    public void loadDataSourcesForCipherModernization(final String dataprovidername) {
        log.info("\n------- loadDataSourceByProfile For Cipher Modernization -------\n");
        if (SecurityConstants.PROFILE_MAINTRACK.equals(UtilContext.makeUtilContext().readSuiteProfile())) {
            context.addDataSource(NODES_TO_ADD, fromTafDataProvider(dataprovidername));
        } else {
            final String dataSourceNameTmp = "nodesToAddTmp";
            final TestDataSource<DataRecord> nodeDS = loadNodes(SECURITY_NODES_CIPHER_MODERNIZATION_LOCAL_CSV, dataSourceNameTmp);
            context.addDataSource(NODES_TO_ADD, shared(transform(nodeDS, getIpFromNetSim())));
        }
    }

    public void createCRLCheckUserRoleScenario() {
        final TestScenario scenario = scenario("CRL Check Role Definition scenario").addFlow(userManagementFlows.createUser()).build();
        executeScenario(scenario);
    }

    public void beforeSuiteRTSEL(final String dataprovidername, final String suiteNscsProfiles) {
        log.info("******** SetUpEnvironment for RTSEL ********");
        UtilContext.makeUtilContext().setProfile(suiteNscsProfiles);
        final String profile = UtilContext.makeUtilContext().readSuiteProfile();
        log.info("Suite starting with [{}] profile", profile);
        loadDataSourcesForRTSELByProfile(dataprovidername);
        prepareSetup("RTSEL");
    }

    public void loadDataSourcesForRTSELByProfile(final String dataprovidername) {
        log.info("\n------- loadDataSourceByProfile For RTSEL-------\n");
        if (SecurityConstants.PROFILE_MAINTRACK.equals(UtilContext.makeUtilContext().readSuiteProfile())) {
            context.addDataSource(NODES_TO_ADD, fromTafDataProvider(dataprovidername));
        } else {
            final String dataSourceNameTmp = "nodesToAddTmp";
            final TestDataSource<DataRecord> nodeDS = loadNodes(SECURITY_NODES_RTSEL_LOCAL_CSV, dataSourceNameTmp);
            context.addDataSource(NODES_TO_ADD, shared(transform(nodeDS, getIpFromNetSim())));
        }
    }
}
