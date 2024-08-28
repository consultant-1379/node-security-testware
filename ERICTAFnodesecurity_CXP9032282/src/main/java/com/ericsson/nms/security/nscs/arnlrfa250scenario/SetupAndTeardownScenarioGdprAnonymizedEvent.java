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

import com.ericsson.cifwk.taf.data.DataHandler;
import com.ericsson.cifwk.taf.datasource.DataRecord;
import com.ericsson.cifwk.taf.datasource.TestDataSource;
import com.ericsson.nms.security.nscs.predicate.PredicateUtil;
import com.google.common.base.Predicate;
import org.testng.ITestContext;
import org.testng.annotations.AfterSuite;
import org.testng.annotations.BeforeSuite;
import org.testng.annotations.Optional;
import org.testng.annotations.Parameters;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static com.ericsson.cifwk.taf.datasource.TafDataSources.fromCsv;
import static com.ericsson.nms.security.nscs.constants.UserRoleValues.ROLE_NODESECURITY_ADMIN;

/**
 * SetupAndTeardownScenario GDPR_AnonymizedEvent contains necessary operations that must be executed before and after suite.
 */
@SuppressWarnings({"PMD.LawOfDemeter"})
public class SetupAndTeardownScenarioGdprAnonymizedEvent extends SetupAndTeardownScenario {

    public static final String nodeTypes = DataHandler.getConfiguration()
            .getProperty("gdprAnonymizedEvent.nodeTypes", "RNC", String.class);

    public static final String GDPR_ANONYMIZED_EVENT_DATA_SOURCE = "gdprAnonymizedEventDataSource";


    @Override
    protected boolean isFmSupervisionRequested() {
        return true;
    }

    @Override
    public Predicate<DataRecord> correctNodeType() {
        getLogger().debug("\n SetupAndTeardownScenarioGdprAnonymizedEvent correctNodeType \n");
        return PredicateUtil.genericPredicate("nodeType", Arrays.asList(nodeTypes.split(",")));
    }

    public static List<String> positiveCustomRolesList() {
        return Arrays.asList(ROLE_NODESECURITY_ADMIN);
    }

    @Override
    public List<String> rbacCustomRolesList() {
        getLogger().debug("\n SetupAndTeardownScenarioGdprAnonymizedEvent rbacCustomRoles \n");
        final List<String> newList = new ArrayList<String>();
        newList.addAll(positiveCustomRolesList());
        return newList;
    }

    @Override
    protected boolean isRbacRequested() {
        return false;
    }

    protected void setupSpecificDataSource() {
        final String gdprAnonymizedEvent = "data" + File.separator + "feature" + File.separator + "gdprAnonymizedEvent" + File.separator;
        final TestDataSource<DataRecord> gdpr = fromCsv(gdprAnonymizedEvent + "gdprAnonymizedEventConfig.csv");
        context.addDataSource(GDPR_ANONYMIZED_EVENT_DATA_SOURCE, gdpr);
        ScenarioUtility.dumpDataSource();
        ScenarioUtility.debugScope(getLogger(), GDPR_ANONYMIZED_EVENT_DATA_SOURCE);

    }

    @BeforeSuite(alwaysRun = true, groups = { "Functional", "NSS" })
    @Parameters({ "agat" })
    public void onBeforeSuite(final ITestContext suiteContext, @Optional final String agat) {
        onBeforeSuiteMethod(suiteContext, agat);
    }

    @AfterSuite(alwaysRun = true, groups = { "Functional", "NSS" })
    public void onAfterSuite() {
        onAfterSuiteMethod();
    }
}
