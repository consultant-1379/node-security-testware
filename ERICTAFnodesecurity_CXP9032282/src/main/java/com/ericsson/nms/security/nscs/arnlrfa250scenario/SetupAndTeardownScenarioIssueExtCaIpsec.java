/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2012
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
import static com.ericsson.nms.security.nscs.constants.UserRoleValues.ROLE_NODESECURITY_ADMIN;
import static com.ericsson.nms.security.nscs.constants.UserRoleValues.ROLE_NODESECURITY_OPERATOR;
import static com.ericsson.nms.security.nscs.constants.UserRoleValues.ROLE_SSH_KEY;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.testng.ITestContext;
import org.testng.annotations.*;

import com.ericsson.cifwk.taf.datasource.DataRecord;
import com.ericsson.cifwk.taf.datasource.TestDataSource;
import com.ericsson.nms.security.nscs.predicate.PredicateUtil;
import com.google.common.base.Predicate;

@SuppressWarnings({"PMD.LawOfDemeter"})
public class SetupAndTeardownScenarioIssueExtCaIpsec extends SetupAndTeardownScenario {

    public static Predicate<DataRecord> extCaNodeList() {
        return PredicateUtil.genericPredicate("nodeType", Arrays.asList("RadioNode"));
    }

    public static final String ISSUE_EXTCA_SINGLENODE = "Single Node certificate issue for ExternalCA";
    public static final String ISSUE_EXTCA_MULTIPLENODE = "Multiple Node certificate issue for ExternalCA";
    public static final String ENTITY_CREATION = "entity creation";

    @Override
    public Predicate<DataRecord> netSimTest() {
        return PredicateUtil.netSimTestPredicate();
    }

    @Override
    public Predicate<DataRecord> correctNodeType() {
        getLogger().debug("\n SetupAndTeardownScenarioIssueExtCaIpsec correctNodeType \n");
        return extCaNodeList();
    }

    public static List<String> positiveCustomRolesList() {
        return Arrays.asList(ROLE_NODESECURITY_ADMIN);
    }

    public static List<String> negativeCustomRolesList()  {
        return Arrays.asList(ROLE_NODESECURITY_OPERATOR, ROLE_SSH_KEY);
    }

    @Override
    public List<String> rbacCustomRolesList() {
        getLogger().debug("\n SetupAndTeardownScenarioIssueExtCaIpsec rbacCustomRoles \n");
        final List<String> newList = new ArrayList<String>();
        newList.addAll(positiveCustomRolesList());
        newList.addAll(negativeCustomRolesList());
        return newList;
    }

    @BeforeSuite(alwaysRun = true, groups = { "Functional", "NSS", "RFA250", "KGB" })
    @Parameters({ "agat" })
    public void onBeforeSuite(final ITestContext suiteContext, @Optional final String agat) {
        onBeforeSuiteMethod(suiteContext, agat);
    }

    @AfterSuite(alwaysRun = true, groups = { "Functional", "NSS", "RFA250", "KGB" })
    public void onAfterSuite() {
        onAfterSuiteMethod();
    }

    protected void setupSpecificDataSource() {

         final String path = "data" + File.separator + "feature" + File.separator + "ExternalCaForIpsec" + File.separator;

         final TestDataSource<DataRecord> IssueSingleNode = fromCsv(path + "ExternalCaIssueSingleNode.csv");
         context.addDataSource(ISSUE_EXTCA_SINGLENODE, IssueSingleNode);
         final TestDataSource<DataRecord> IssueMultipleNode = fromCsv(path + "ExternalCaIssueMultipleNode.csv");
         context.addDataSource(ISSUE_EXTCA_MULTIPLENODE, IssueMultipleNode);

         final TestDataSource<DataRecord> EntityCreation = fromCsv(path + "EndEntityinfo.csv");
         context.addDataSource(ENTITY_CREATION, EntityCreation);
         ScenarioUtility.dumpDataSource();
         ScenarioUtility.debugScope(getLogger(), ISSUE_EXTCA_SINGLENODE);
    }
}
