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
 * SetupAndTeardownScenarioRealNodeRtSel contains necessary operations that must be executed before and after RtSel test suite.
 */
@SuppressWarnings({"PMD.LawOfDemeter"})
public class SetupAndTeardownScenarioRtSel extends SetupAndTeardownScenario {

    public static final String nodeTypes = DataHandler.getConfiguration().getProperty("rtSel.nodeTypes", "ERBS,MGW,RNC", String.class);

    public static final String RTSEL_ACTIVATE_WRONG_USER = "RTSEL_ACTIVATE_WRONG_USER";
    public static final String RTSEL_ACTIVATE_CORRECT_USER = "RTSEL_ACTIVATE_CORRECT_USER";
    public static final String RTSEL_DEACTIVATE_WRONG_USER = "RTSEL_DEACTIVATE_WRONG_USER";
    public static final String RTSEL_DEACTIVATE_CORRECT_USER = "RTSEL_DEACTIVATE_CORRECT_USER";
    public static final String RTSEL_DELETE_WRONG_USER = "RTSEL_DELETE_WRONG_USER";
    public static final String RTSEL_DELETE_CORRECT_USER = "RTSEL_DELETE_CORRECT_USER";


    @Override
    public Predicate<DataRecord> correctNodeType() {
        getLogger().debug("\n SetupAndTeardownScenarioRtSel correctNodeType \n");
        return PredicateUtil.genericPredicate("nodeType", Arrays.asList(nodeTypes.split(",")));
    }

    public static List<String> positiveCustomRolesList() {
        return Arrays.asList(ROLE_NODESECURITY_ADMIN);
    }

    public static List<String> negativeCustomRolesList() {
        return Arrays.asList(ROLE_NODESECURITY_OPERATOR);
    }

    @Override
    public List<String> rbacCustomRolesList() {
        getLogger().debug("\n SetupAndTeardownScenarioRtSel rbacCustomRoles \n");
        final List<String> newList = new ArrayList<String>();
        newList.addAll(positiveCustomRolesList());
        newList.addAll(negativeCustomRolesList());
        return newList;
    }

    protected void setupSpecificDataSource() {
        final String path = "data" + File.separator + "feature" + File.separator + "rtSel" + File.separator;
        TestDataSource<DataRecord> rtSel = fromCsv(path + "RtSelActivate.csv");
        context.addDataSource(RTSEL_ACTIVATE_CORRECT_USER, rtSel);
        TestDataSource<DataRecord> wrongErrorMessage = fromCsv(path + "ExpectedMessage.csv");
        context.addDataSource(RTSEL_ACTIVATE_WRONG_USER, TafDataSources.merge(rtSel, wrongErrorMessage));

        rtSel = fromCsv(path + "RtSelDeactivate.csv");
        context.addDataSource(RTSEL_DEACTIVATE_CORRECT_USER, rtSel);
        wrongErrorMessage = fromCsv(path + "ExpectedMessage.csv");
        context.addDataSource(RTSEL_DEACTIVATE_WRONG_USER, TafDataSources.merge(rtSel, wrongErrorMessage));

        rtSel = fromCsv(path + "RtSelDelete.csv");
        context.addDataSource(RTSEL_DELETE_CORRECT_USER, rtSel);
        wrongErrorMessage = fromCsv(path + "ExpectedMessage.csv");
        context.addDataSource(RTSEL_DELETE_WRONG_USER, TafDataSources.merge(rtSel, wrongErrorMessage));

        final Map<String, Object> cmdConfigMng = Maps.newHashMap();
        cmdConfigMng.put(DefaultConfigMngProvider.ALGO_NAME_KEY, DefaultConfigMngProvider.ALGO_NAME_VALUE_SHA1);
        cmdConfigMng.put(DefaultConfigMngProvider.ALGO_STATUS_KEY, DefaultConfigMngProvider.ALGO_STATUS_VALUE_ENABLE);
        final List<Map<String, Object>> result = Lists.newArrayList();
        result.add(cmdConfigMng);
        context.addDataSource(PKI_DATASOURCE, TestDataSourceFactory.createDataSource(result));
        context.addDataSource(PKI_DATASOURCE, context.dataSource(PKI_DATASOURCE, ConfigMngValue.class));
        TafDataSources.shareDataSource(PKI_DATASOURCE);

        ScenarioUtility.debugScope(getLogger(), RTSEL_ACTIVATE_CORRECT_USER);
        ScenarioUtility.debugScope(getLogger(), RTSEL_ACTIVATE_WRONG_USER);
        ScenarioUtility.debugScope(getLogger(), RTSEL_DEACTIVATE_CORRECT_USER);
        ScenarioUtility.debugScope(getLogger(), RTSEL_DEACTIVATE_WRONG_USER);
        ScenarioUtility.debugScope(getLogger(), RTSEL_DELETE_CORRECT_USER);
        ScenarioUtility.debugScope(getLogger(), RTSEL_DELETE_WRONG_USER);
    }

    @BeforeSuite(alwaysRun = true, groups = { "Functional", "NSS", "RFA250", "ARNL" })
    @Parameters({ "agat" })
    public void onBeforeSuite(final ITestContext suiteContext, @Optional final String agat) {
        onBeforeSuiteMethod(suiteContext, agat);
    }

    @AfterSuite(alwaysRun = true, groups = { "Functional", "NSS", "RFA250", "ARNL" })
    public void onAfterSuite() {
        onAfterSuiteMethod();
    }

}
