/*
 * ------------------------------------------------------------------------------
 ******************************************************************************* COPYRIGHT Ericsson 2016
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 ******************************************************************************* ----------------------------------------------------------------------------
 */

package com.ericsson.nms.security.nscs.arnlrfa250scenario;

import static com.ericsson.cifwk.taf.scenario.TestScenarios.dataSource;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.scenario;
import static com.ericsson.nms.security.nscs.constants.UserRoleValues.ROLE_NODESECURITY_ADMIN;
import static com.ericsson.nms.security.nscs.constants.UserRoleValues.ROLE_NODESECURITY_OPERATOR;
import static com.ericsson.nms.security.nscs.constants.UserRoleValues.ROLE_OAM;
import static com.ericsson.nms.security.nscs.constants.UserRoleValues.ROLE_SSH_KEY;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.ADDED_NODES;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.NODES_TO_ADD;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.PKI_DATASOURCE;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.ROLE_TO_CREATE;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import org.testng.ITestContext;
import org.testng.annotations.AfterSuite;
import org.testng.annotations.BeforeSuite;
import org.testng.annotations.Optional;
import org.testng.annotations.Parameters;

import com.ericsson.cifwk.taf.data.DataHandler;
import com.ericsson.cifwk.taf.datasource.DataRecord;
import com.ericsson.cifwk.taf.datasource.TafDataSources;
import com.ericsson.cifwk.taf.datasource.TestDataSourceFactory;
import com.ericsson.cifwk.taf.scenario.api.TestScenarioBuilder;
import com.ericsson.nms.security.nscs.predicate.PredicateUtil;
import com.ericsson.nms.security.pki.data.ConfigMngValue;
import com.ericsson.nms.security.pki.util.DefaultConfigMngProvider;
import com.google.common.base.Predicate;
import com.google.common.collect.Iterables;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;

/**
 * SetupAndTeardownScenarioTLS13version contains necessary operations that must be executed to enable TLSv1.3 test suite.
 */
@SuppressWarnings({ "PMD.LawOfDemeter", "PMD.ExcessiveImports" })
public class SetupAndTeardownScenarioTLS13version extends SetupAndTeardownScenario {

    public static final String nodeTypes = DataHandler.getConfiguration().getProperty("tls13Version.nodeTypes", "RadioNode,FRONTHAUL-6020",
            String.class);

    @Override
    public Predicate<DataRecord> netSimTest() {
        return PredicateUtil.netSimTestPredicate();
    }

    @Override
    public Predicate<DataRecord> correctNodeType() {
        getLogger().debug("\n SetupAndTeardownScenarioTLS13version correctNodeType \n");
        return PredicateUtil.genericPredicate("nodeType", Arrays.asList(nodeTypes.split(",")));
    }

    public static List<String> positiveCustomRolesList() {
        return Arrays.asList(ROLE_NODESECURITY_ADMIN, ROLE_OAM);
    }

    public static List<String> negativeCustomRolesList() {
        return Arrays.asList(ROLE_NODESECURITY_OPERATOR, ROLE_SSH_KEY);
    }

    protected void configureTlsComEcimVersion(final String tlsVersion) {
        scenarioUtility.configureTlsComEcimVersion(tlsVersion);
    }

    @Override
    public List<String> rbacCustomRolesList() {
        getLogger().debug("\n SetupAndTeardownScenarioTlsv1.3 rbacCustomRoles \n");
        final List<String> newList = new ArrayList<String>();
        newList.addAll(positiveCustomRolesList());
        newList.addAll(negativeCustomRolesList());
        return newList;
    }

    @Override
    protected boolean isSynchNodeRequested() {
        return false;
    }

    @Override
    protected boolean isFmSupervisionRequested() {
        return false;
    }

    @Override
    protected void setupSpecificDataSource() {
        final Map<String, Object> cmdConfigMng = Maps.newHashMap();
        cmdConfigMng.put(DefaultConfigMngProvider.ALGO_NAME_KEY, DefaultConfigMngProvider.ALGO_NAME_VALUE_SHA1);
        cmdConfigMng.put(DefaultConfigMngProvider.ALGO_STATUS_KEY, DefaultConfigMngProvider.ALGO_STATUS_VALUE_ENABLE);
        final List<Map<String, Object>> result = Lists.newArrayList();
        result.add(cmdConfigMng);
        context.addDataSource(PKI_DATASOURCE, TestDataSourceFactory.createDataSource(result));
        context.addDataSource(PKI_DATASOURCE, context.dataSource(PKI_DATASOURCE, ConfigMngValue.class));
        TafDataSources.shareDataSource(PKI_DATASOURCE);
        ScenarioUtility.debugScope(getLogger(), NODES_TO_ADD);
    }

    @Override
    @BeforeSuite(alwaysRun = true, groups = { "Functional", "NSS", "RFA250" })
    @Parameters({ "agat" })
    public void onBeforeSuite(final ITestContext suiteContext, @Optional final String agat) {
        //TLS1.3 available as default
        //configureTlsComEcimVersion(TLS_VERSION_1_2 + "," + TLS_VERSION_1_3);
        onBeforeSuiteMethod(suiteContext, agat);
    }

    @Override
    @AfterSuite(alwaysRun = true, groups = { "Functional", "NSS", "RFA250" })
    public void onAfterSuite() {
        //leaving enabled protocols as per default values
        //configureTlsComEcimVersion(TLS_VERSION_1_2);
        onAfterSuiteMethod();
    }

    @Override
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
                // SUITE SETUP
                .split(utilityFlows.startNetsimNodes(netSimTest()).withVusers(vUser),
                        utilityFlows.createUsers(getNumberOfUsers()))
                .addFlow(utilityFlows.login(PredicateUtil.nscsSetupTeardownAdm(), vUser))
                .addFlow(isCredentialsCreateRequested() ? utilityFlows.createNodes(netSimTest(), vUser)
                        : addRemoveNodesFlow.addConfirmNodes(dataSource(NODES_TO_ADD).withFilter(netSimTest())))
                .addFlow(utilityFlows.enableCMSupervisionOnNodes(vUser))
                .addFlow(utilityFlows.logout(PredicateUtil.nscsSetupTeardownAdm(), vUser))
                .alwaysRun();
        return scenarioBuilder;
    }

    @Override
    protected TestScenarioBuilder afterSuiteScenarioBuilder() {
        int vUser = Iterables.size(context.dataSource(ADDED_NODES));
        int vRolesToDelete = getNumberOfNodes();
        vRolesToDelete = vRolesToDelete > 0 ? vRolesToDelete : 1;
        vUser = vUser != 0 ? vUser : 1;
        final TestScenarioBuilder scenarioBuilder = addFlowsAfterScenario()
                .addFlow(utilityFlows.login(PredicateUtil.nscsSetupTeardownAdm(), vUser))
                .addFlow(utilityFlows.deleteNodes(netSimTest(), vUser)).alwaysRun()
                .addFlow(utilityFlows.logout(PredicateUtil.nscsSetupTeardownAdm(), vUser)).alwaysRun()
                .addFlow(utilityFlows.deleteUsers(getNumberOfUsers())).alwaysRun()
                .addFlow(utilityFlows.deleteUserRoles(isRbacRequested(), vRolesToDelete, true))
                .addFlow(utilityFlows.deleteTargetGroup(isTbacRequested()))
                .alwaysRun();
        return scenarioBuilder;
    }

}
