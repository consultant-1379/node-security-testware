/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2018
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.nms.security.nscs.arnlrfa250scenario;

import static com.ericsson.cifwk.taf.datasource.TafDataSources.copy;
import static com.ericsson.cifwk.taf.datasource.TafDataSources.fromCsv;
import static com.ericsson.cifwk.taf.datasource.TafDataSources.fromTafDataProvider;
import static com.ericsson.nms.security.nscs.constants.UserRoleValues.ROLE_CM_NORMAL;
import static com.ericsson.nms.security.nscs.constants.UserRoleValues.ROLE_NODESECURITY_ADMIN;
import static com.ericsson.nms.security.nscs.constants.UserRoleValues.ROLE_NODESECURITY_OPERATOR;
import static com.ericsson.nms.security.nscs.constants.UserRoleValues.ROLE_SECURITY_MANAGEMENT;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.NODES_TO_ADD;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.PKI_DATASOURCE;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.USERS_TO_CREATE;

import java.io.File;
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
import com.ericsson.cifwk.taf.datasource.TestDataSource;
import com.ericsson.cifwk.taf.datasource.TestDataSourceFactory;
import com.ericsson.nms.security.nscs.predicate.PredicateUtil;
import com.ericsson.nms.security.pki.data.ConfigMngValue;
import com.ericsson.nms.security.pki.util.DefaultConfigMngProvider;
import com.ericsson.oss.testware.nodesecurity.data.Commands;
import com.google.common.base.Predicate;
import com.google.common.collect.Iterables;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;

/**
 * SetupAndTeardownScenarioLocalRbac contains necessary operations that must be executed before and after Local Rbac test suite.
 */
@SuppressWarnings({"PMD.LawOfDemeter", "PMD.ExcessiveImports"})
public class SetupAndTeardownScenarioLocalRbac extends SetupAndTeardownScenario {

    public static final String nodeTypes = DataHandler.getConfiguration().getProperty("localRbac.nodeTypes", "RNC,ERBS,RBS,MGW,MRS",
            String.class);

    public static final String COMMAND_DATASOURCE_ENABLE = "Command_Datasource_Enable";
    public static final String COMMAND_DATASOURCE_DISABLE = "Command_Datasource_Disable";
    public static final String LOCAL_RBAC_USERS_FILTERED = "Local_Rbac_Users_Filtered";
    public static final String LOCAL_RBAC_USERS_DATASOURCE = "Local_Rbac_Users_DataSource";
    public static final String EXPECTED_STATUS_ENABLE = "Expected_Status_Enable";
    public static final String EXPECTED_STATUS_DISABLE = "Expected_Status_Disable";
    public static final String EXPECTED_MESSAGE_LOCAL_RBAC_USERS = "Expected_Message_LocalRbac_Users";
    public static final String LAAD_DISTRIBUTE_WRONG_USER = "Laad_Distribute_Wrong_User";

    @Override
    public Predicate<DataRecord> correctNodeType() {
        getLogger().debug("\n SetupAndTeardownScenarioLocalRbac correctNodeType \n");
        return PredicateUtil.genericPredicate("nodeType", Arrays.asList(nodeTypes.split(",")));
    }

    public static List<String> positiveCustomRolesList() {
        return Arrays.asList(ROLE_NODESECURITY_ADMIN);
    }

    public static List<String> negativeCustomRolesList() {
        return Arrays.asList(ROLE_NODESECURITY_OPERATOR);
    }

    public static List<String> localRbacRolesList() {
        return Arrays.asList(ROLE_SECURITY_MANAGEMENT, ROLE_CM_NORMAL);
    }

    @Override
    public List<String> rbacCustomRolesList() {
        getLogger().debug("\n SetupAndTeardownScenarioLocalRbac rbacCustomRoles \n");
        final List<String> newList = new ArrayList<String>();
        newList.addAll(positiveCustomRolesList());
        newList.addAll(negativeCustomRolesList());
        newList.addAll(localRbacRolesList());
        return newList;
    }

    @Override
    public Iterable<DataRecord> filterUsers(final Iterable<DataRecord> userList) {
        return Iterables.filter(userList, isRfa250() ? PredicateUtil.nscsLocalRbac() : PredicateUtil.userRoleSuiteNamePredicate("roles", rbacCustomRolesList()));
    }

    @Override
    public Iterable<DataRecord> filterUsersForTbac() {
        return Iterables.filter(context.dataSource(USERS_TO_CREATE), PredicateUtil.nsuLocalRbac());
    }

    @Override
    protected boolean isTbacRequested() {
        return true;
    }

    protected void setupSpecificDataSource() {
        final String path = "data" + File.separator + "feature" + File.separator + "localRbac" + File.separator;
        final Iterable<DataRecord> localRbacUsersFilter;

        final TestDataSource<Commands> localRbacEnableNodeCommandsCsv = fromCsv(path + "LocalRbacEnableNodeCommands.csv", Commands.class);
        context.addDataSource(COMMAND_DATASOURCE_ENABLE, localRbacEnableNodeCommandsCsv);
        final TestDataSource<Commands> localRbacDisableNodeCommandsCsv = fromCsv(path + "LocalRbacDisableNodeCommands.csv", Commands.class);
        context.addDataSource(COMMAND_DATASOURCE_DISABLE, localRbacDisableNodeCommandsCsv);
        final TestDataSource<Commands> expectedStatusEnableCsv = fromCsv(path + "ExpectedStatusLocalRbacEnable.csv", Commands.class);
        context.addDataSource(EXPECTED_STATUS_ENABLE, expectedStatusEnableCsv);
        final TestDataSource<Commands> expectedStatusDisableCsv = fromCsv(path + "ExpectedStatusLocalRbacDisable.csv", Commands.class);
        context.addDataSource(EXPECTED_STATUS_DISABLE, expectedStatusDisableCsv);
        final TestDataSource<DataRecord> errorMessage = fromCsv(path + "ExpectedErrorMessage.csv");
        context.addDataSource(LAAD_DISTRIBUTE_WRONG_USER, errorMessage);

        final TestDataSource<DataRecord> expectedMessageLocalRbacUserCsv = fromCsv(path + "ExpectedMessageLocalRbacUser.csv");
        context.addDataSource(EXPECTED_MESSAGE_LOCAL_RBAC_USERS, expectedMessageLocalRbacUserCsv);

        localRbacUsersFilter = Iterables.filter(copy(fromTafDataProvider(USERS_TO_CREATE)), PredicateUtil.nsuLocalRbac());
        SetupAndTearDownUtil.removeAndCreateTestDataSource(LOCAL_RBAC_USERS_FILTERED, localRbacUsersFilter);

        final TestDataSource<DataRecord> mergedUserList = ScenarioUtility.mergeDataSources(LOCAL_RBAC_USERS_FILTERED, EXPECTED_MESSAGE_LOCAL_RBAC_USERS);
        SetupAndTearDownUtil.removeAndCreateTestDataSource(LOCAL_RBAC_USERS_DATASOURCE, mergedUserList);

        final Map<String, Object> cmdConfigMng = Maps.newHashMap();
        cmdConfigMng.put(DefaultConfigMngProvider.ALGO_NAME_KEY, DefaultConfigMngProvider.ALGO_NAME_VALUE_SHA1);
        cmdConfigMng.put(DefaultConfigMngProvider.ALGO_STATUS_KEY, DefaultConfigMngProvider.ALGO_STATUS_VALUE_ENABLE);
        final List<Map<String, Object>> result = Lists.newArrayList();
        result.add(cmdConfigMng);
        context.addDataSource(PKI_DATASOURCE, TestDataSourceFactory.createDataSource(result));
        context.addDataSource(PKI_DATASOURCE, context.dataSource(PKI_DATASOURCE, ConfigMngValue.class));
        TafDataSources.shareDataSource(PKI_DATASOURCE);
        ScenarioUtility.debugScope(getLogger(), NODES_TO_ADD);
        ScenarioUtility.debugScope(getLogger(), COMMAND_DATASOURCE_ENABLE);
        ScenarioUtility.debugScope(getLogger(), COMMAND_DATASOURCE_DISABLE);
        ScenarioUtility.debugScope(getLogger(), EXPECTED_STATUS_ENABLE);
        ScenarioUtility.debugScope(getLogger(), EXPECTED_STATUS_DISABLE);
        ScenarioUtility.debugScope(getLogger(), EXPECTED_MESSAGE_LOCAL_RBAC_USERS);
        ScenarioUtility.debugScope(getLogger(), LOCAL_RBAC_USERS_FILTERED);
        ScenarioUtility.debugScope(getLogger(), LOCAL_RBAC_USERS_DATASOURCE);
    }

    @BeforeSuite(alwaysRun = true, groups = { "Functional", "NSS", "RFA250", "ARNL", "ENM_EXTERNAL_TESTWARE" })
    @Parameters({ "agat" })
    public void onBeforeSuite(final ITestContext suiteContext, @Optional final String agat) {
        onBeforeSuiteMethod(suiteContext, agat);
    }

    @AfterSuite(alwaysRun = true, groups = { "Functional", "NSS", "RFA250", "ARNL", "ENM_EXTERNAL_TESTWARE" })
    public void onAfterSuite() {
        onAfterSuiteMethod();
    }
}
