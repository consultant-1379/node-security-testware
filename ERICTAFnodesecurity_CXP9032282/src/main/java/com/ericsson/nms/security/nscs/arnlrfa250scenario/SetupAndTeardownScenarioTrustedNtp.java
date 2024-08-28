/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2019
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/

package com.ericsson.nms.security.nscs.arnlrfa250scenario;

import static com.ericsson.cifwk.taf.datasource.TafDataSources.fromCsv;
import static com.ericsson.nms.security.nscs.constants.UserRoleValues.*;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.NODES_TO_ADD;

import java.io.File;
import java.util.*;

import org.testng.ITestContext;
import org.testng.annotations.*;
import org.testng.annotations.Optional;

import com.ericsson.cifwk.taf.data.DataHandler;
import com.ericsson.cifwk.taf.datasource.DataRecord;
import com.ericsson.cifwk.taf.datasource.TestDataSource;
import com.ericsson.nms.security.nscs.predicate.PredicateUtil;
import com.google.common.base.Predicate;

/**
 * SetupAndTeardownScenarioTrustedNtp contains necessary operations that must be executed before and after test suite.
 */
@SuppressWarnings({ "PMD.LawOfDemeter" })
public class SetupAndTeardownScenarioTrustedNtp extends SetupAndTeardownScenario {

    public static final String nodeTypes = DataHandler.getConfiguration().getProperty("ntp.nodeTypes", "ERBS,RadioNode", String.class);

    public static final String NTP_POSITIVE_XML_FILE_BASED_TEST = "ntpPositiveXmlFileBasedTest";

    @Override
    public Predicate<DataRecord> netSimTest() {
        return PredicateUtil.netSimTestPredicate();
    }

    public static List<String> positiveCustomRolesList() {
        return Arrays.asList(ROLE_NODESECURITY_ADMIN);
    }

    public static List<String> negativeCustomRolesList() {
        return Arrays.asList(ROLE_NODESECURITY_OPERATOR, ROLE_SSH_KEY);
    }

    @Override
    protected boolean isFmSupervisionRequested() {
        return false;
    }

    @Override
    public List<String> rbacCustomRolesList() {
        getLogger().debug("\n SetupAndTeardownTrustedNtp rbacCustomRoles \n");
        final List<String> newList = new ArrayList<String>();
        newList.addAll(positiveCustomRolesList());
        newList.addAll(negativeCustomRolesList());
        return newList;
    }

    @Override
    public Predicate<DataRecord> correctNodeType() {
        getLogger().debug("NTP Setup and Teardown Scenario correct node type setup.");
        return PredicateUtil.genericPredicate("nodeType", Arrays.asList(nodeTypes.split(",")));
    }

    @BeforeSuite(alwaysRun = true, groups = { "Functional", "NSS", "KGB" })
    @Parameters({ "agat" })
    public void onBeforeSuite(final ITestContext suiteContext, @Optional final String agat) {
        onBeforeSuiteMethod(suiteContext, agat);
    }

    @AfterSuite(alwaysRun = true, groups = { "Functional", "NSS", "KGB" })
    public void onAfterSuite() {
        onAfterSuiteMethod();
    }

    @Override
    protected void setupSpecificDataSource() {
        final String path = "data" + File.separator + "feature" + File.separator + "ntp" + File.separator;

        final TestDataSource<DataRecord> xmlfileBased = fromCsv(path + "NtpXmlFileBase.csv");
        context.addDataSource(NTP_POSITIVE_XML_FILE_BASED_TEST, xmlfileBased);

        ScenarioUtility.debugScope(getLogger(), NODES_TO_ADD);
        ScenarioUtility.dumpDataSource();
        ScenarioUtility.debugScope(getLogger(), NTP_POSITIVE_XML_FILE_BASED_TEST);
    }
}
