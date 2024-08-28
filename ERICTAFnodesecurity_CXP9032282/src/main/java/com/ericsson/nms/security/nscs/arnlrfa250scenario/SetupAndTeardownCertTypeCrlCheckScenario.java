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

import static com.ericsson.cifwk.taf.datasource.TafDataSources.fromTafDataProvider;

import org.testng.ITestContext;
import org.testng.annotations.AfterSuite;
import org.testng.annotations.BeforeSuite;
import org.testng.annotations.Optional;
import org.testng.annotations.Parameters;

import com.ericsson.cifwk.taf.datasource.DataRecord;
import com.ericsson.cifwk.taf.datasource.TestDataSource;
import com.ericsson.nms.security.nscs.predicate.PredicateUtil;
import com.google.common.collect.Iterables;

/**
 * SetupAndTeardownScenarioRealNode necessary operations that must be executed before and after every test suite.
 */
public class SetupAndTeardownCertTypeCrlCheckScenario extends SetupAndTeardownCertTypeScenario {

    public static final String ISSUE = "ISSUE";

    @Override
    protected void setupSpecificDataSource() {
        final TestDataSource<DataRecord> issue = fromTafDataProvider("crlcheck");
        final Iterable<DataRecord> issueFiltered =
                Iterables.filter(issue, PredicateUtil.suiteNamePredicate("suiteName", getSuiteName()));
        SetupAndTearDownUtil.removeAndCreateTestDataSource(ISSUE, issueFiltered);
        ScenarioUtility.debugScope(getLogger(), ISSUE);
    }

    @BeforeSuite(alwaysRun = true, groups = { "Functional", "NSS", "RFA250", "ARNL", "KGB", "ENM_EXTERNAL_TESTWARE", "AGAT_BUILD_ISO" })
    @Parameters({ "agat" })
    public void onBeforeSuite(final ITestContext suiteContext, @Optional final String agat) {
        onBeforeSuiteMethod(suiteContext, agat);
    }

    @AfterSuite(alwaysRun = true, groups = { "Functional", "NSS", "RFA250", "ARNL", "KGB", "ENM_EXTERNAL_TESTWARE", "AGAT_BUILD_ISO" })
    public void onAfterSuite() {
        onAfterSuiteMethod();
    }
}
