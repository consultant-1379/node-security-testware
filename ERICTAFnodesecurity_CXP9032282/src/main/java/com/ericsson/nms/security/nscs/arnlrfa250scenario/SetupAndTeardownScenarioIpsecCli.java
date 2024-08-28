/*
 * ------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2018
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
import static com.ericsson.nms.security.nscs.constants.UserRoleValues.ROLE_SSH_KEY;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.NODES_TO_ADD;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.PKI_DATASOURCE;

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
import com.google.common.base.Predicate;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;

/**
 * SetupAndTeardownScenarioIpsecCli contains necessary operations that must be executed before and after IpsecCli test suite.
 */
@SuppressWarnings({"PMD.LawOfDemeter"})
public class SetupAndTeardownScenarioIpsecCli extends SetupAndTeardownScenario {

    public static final String nodeTypes = DataHandler.getConfiguration().getProperty("ipsecCli.nodeTypes", "ERBS",
            String.class);

    public static final String IPSEC_ACTIVATE = "IPSEC_ACTIVATE";
    public static final String IPSEC_DEACTIVATE = "IPSEC_DEACTIVATE";
    public static final String IPSEC_ACTIVATE_WRONG_USER = "IPSEC_ACTIVATE_WRONG_USER";
    public static final String IPSEC_DEACTIVATE_WRONG_USER = "IPSEC_DEACTIVATE_WRONG_USER";

    public List<String> positiveCustomRolesList() {
        return Arrays.asList(ROLE_NODESECURITY_ADMIN);
    }

    public List<String> negativeCustomRolesList()  {
        return Arrays.asList(ROLE_NODESECURITY_OPERATOR, ROLE_SSH_KEY);
    }

    @Override
    public List<String> rbacCustomRolesList() {
        getLogger().debug("\n SetupAndTeardownScenarioIpsecCli rbacCustomRoles \n");
        final List<String> newList = new ArrayList<String>();
        newList.addAll(positiveCustomRolesList());
        newList.addAll(negativeCustomRolesList());
        return newList;
    }

    @Override
    public Predicate<DataRecord> correctNodeType() {
        getLogger().debug("\n SetupAndTeardownScenarioIpsecCli correctNodeType \n");
        return PredicateUtil.genericPredicate("nodeType", Arrays.asList(nodeTypes.split(",")));
    }

    protected void setupSpecificDataSource() {
        final String path = "data" + File.separator + "feature" + File.separator + "ipsecCli" + File.separator;
        final TestDataSource<DataRecord> ipsecActivate = fromCsv(path + "IpsecActivateinfo.csv");
        context.addDataSource(IPSEC_ACTIVATE, ipsecActivate);
        final TestDataSource<DataRecord> ipsecDeActivate = fromCsv(path + "IpsecDeActivateinfo.csv");
        context.addDataSource(IPSEC_DEACTIVATE, ipsecDeActivate);
        
        final TestDataSource<DataRecord> errorMessage = fromCsv(path + "ExpectedErrorMessage.csv");
        context.addDataSource(IPSEC_ACTIVATE_WRONG_USER, TafDataSources.merge(ipsecActivate, errorMessage));
        context.addDataSource(IPSEC_DEACTIVATE_WRONG_USER, TafDataSources.merge(ipsecDeActivate, errorMessage));

        final Map<String, Object> cmdConfigMng = Maps.newHashMap();
        cmdConfigMng.put(DefaultConfigMngProvider.ALGO_NAME_KEY, DefaultConfigMngProvider.ALGO_NAME_VALUE_SHA1);
        cmdConfigMng.put(DefaultConfigMngProvider.ALGO_STATUS_KEY, DefaultConfigMngProvider.ALGO_STATUS_VALUE_ENABLE);
        final List<Map<String, Object>> result = Lists.newArrayList();
        result.add(cmdConfigMng);
        context.addDataSource(PKI_DATASOURCE, TestDataSourceFactory.createDataSource(result));
        context.addDataSource(PKI_DATASOURCE, context.dataSource(PKI_DATASOURCE, ConfigMngValue.class));
        TafDataSources.shareDataSource(PKI_DATASOURCE);
        ScenarioUtility.debugScope(getLogger(), NODES_TO_ADD);
        ScenarioUtility.debugScope(getLogger(), IPSEC_ACTIVATE);
        ScenarioUtility.debugScope(getLogger(), IPSEC_DEACTIVATE);
        ScenarioUtility.debugScope(getLogger(), IPSEC_ACTIVATE_WRONG_USER);
        ScenarioUtility.debugScope(getLogger(), IPSEC_DEACTIVATE_WRONG_USER);
    }

    @BeforeSuite(alwaysRun = true, groups = { "Functional", "NSS", "RFA250" })
    @Parameters({ "agat" })
    public void onBeforeSuite(final ITestContext suiteContext, @Optional final String agat) {
        onBeforeSuiteMethod(suiteContext, agat);
    }

    @AfterSuite(alwaysRun = true, groups = { "Functional", "NSS", "RFA250" })
    public void onAfterSuite() {
        onAfterSuiteMethod();
    }

}
