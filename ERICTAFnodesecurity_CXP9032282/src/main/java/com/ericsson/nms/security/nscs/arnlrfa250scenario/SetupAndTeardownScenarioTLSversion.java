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

import static com.ericsson.cifwk.taf.datasource.TafDataSources.fromCsv;
import static com.ericsson.nms.security.nscs.constants.UserRoleValues.ROLE_NODESECURITY_ADMIN;
import static com.ericsson.nms.security.nscs.constants.UserRoleValues.ROLE_NODESECURITY_OPERATOR;
import static com.ericsson.nms.security.nscs.constants.UserRoleValues.ROLE_OAM;
import static com.ericsson.nms.security.nscs.constants.UserRoleValues.ROLE_SSH_KEY;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.NODES_TO_ADD;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.PKI_DATASOURCE;
import static com.ericsson.oss.testware.nodesecurity.constant.AgnosticConstants.TLS_VERSION_1_2;

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
import com.ericsson.oss.testware.nodesecurity.pibcommands.PibCommandConfigurator;
import com.google.common.base.Predicate;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import com.google.inject.Inject;

/**
 * SetupAndTeardownScenarioTLSversion contains necessary operations that must be executed before and after TLSv1.2 test suite.
 */
@SuppressWarnings({"PMD.LawOfDemeter", "PMD.ExcessiveImports"})
public class SetupAndTeardownScenarioTLSversion extends SetupAndTeardownScenario {

    public static final String nodeTypes = DataHandler.getConfiguration().getProperty("tlsVersion.nodeTypes", "ERBS",
            String.class);


    public static final String SL2_ON = "SL2_ON";
    public static final String SL2_OFF = "SL2_OFF";

    @Override
    public Predicate<DataRecord> netSimTest() {
        return PredicateUtil.netSimTestPredicate();
    }

    @Override
    public Predicate<DataRecord> correctNodeType() {
        getLogger().debug("\n SetupAndTeardownScenarioTLSversion correctNodeType \n");
        return PredicateUtil.genericPredicate("nodeType", Arrays.asList(nodeTypes.split(",")));
    }

    public static List<String> positiveCustomRolesList()  {
        return Arrays.asList(ROLE_NODESECURITY_ADMIN, ROLE_OAM);
    }

    public static List<String> negativeCustomRolesList()  {
        return Arrays.asList(ROLE_NODESECURITY_OPERATOR, ROLE_SSH_KEY);
    }

    @Inject
    private PibCommandConfigurator pibCommandConfigurator;

    @Override
    public List<String> rbacCustomRolesList() {
        getLogger().debug("\n SetupAndTeardownScenarioTlsv1.2 rbacCustomRoles \n");
        final List<String> newList = new ArrayList<String>();
        newList.addAll(positiveCustomRolesList());
        newList.addAll(negativeCustomRolesList());
        return newList;
    }

    protected void setupSpecificDataSource() {
        final String path = "data" + File.separator + "feature" + File.separator + "sl2" + File.separator;
        final TestDataSource<DataRecord> sl2 = fromCsv(path + "SL2info.csv");
        context.addDataSource(SL2_ON, sl2);
        final TestDataSource<DataRecord> sl1 = fromCsv(path + "SL1info.csv");
        context.addDataSource(SL2_OFF, sl1);

        final Map<String, Object> cmdConfigMng = Maps.newHashMap();
        cmdConfigMng.put(DefaultConfigMngProvider.ALGO_NAME_KEY, DefaultConfigMngProvider.ALGO_NAME_VALUE_SHA1);
        cmdConfigMng.put(DefaultConfigMngProvider.ALGO_STATUS_KEY, DefaultConfigMngProvider.ALGO_STATUS_VALUE_ENABLE);
        final List<Map<String, Object>> result = Lists.newArrayList();
        result.add(cmdConfigMng);
        context.addDataSource(PKI_DATASOURCE, TestDataSourceFactory.createDataSource(result));
        context.addDataSource(PKI_DATASOURCE, context.dataSource(PKI_DATASOURCE, ConfigMngValue.class));
        TafDataSources.shareDataSource(PKI_DATASOURCE);
        ScenarioUtility.debugScope(getLogger(), NODES_TO_ADD);
        ScenarioUtility.debugScope(getLogger(), SL2_ON);
        ScenarioUtility.debugScope(getLogger(), SL2_OFF);

    }

    @BeforeSuite(alwaysRun = true, groups = { "Functional", "NSS", "RFA250" })
    @Parameters({ "agat" })
    public void onBeforeSuite(final ITestContext suiteContext, @Optional final String agat) {
        configureTlsVersion(TLS_VERSION_1_2);
        onBeforeSuiteMethod(suiteContext, agat);
    }

    @AfterSuite(alwaysRun = true, groups = { "Functional", "NSS", "RFA250" })
    public void onAfterSuite() {
        onAfterSuiteMethod();
    }
}
