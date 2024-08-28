/**
 * ------------------------------------------------------------------------------
 * ******************************************************************************
 * COPYRIGHT Ericsson 2017
 * <p>
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 * ******************************************************************************
 * ------------------------------------------------------------------------------
 */

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
import org.testng.annotations.AfterSuite;
import org.testng.annotations.BeforeSuite;
import org.testng.annotations.Optional;
import org.testng.annotations.Parameters;

import com.ericsson.cifwk.taf.data.DataHandler;
import com.ericsson.cifwk.taf.datasource.DataRecord;
import com.ericsson.cifwk.taf.datasource.TestDataSource;
import com.ericsson.nms.security.nscs.predicate.PredicateUtil;
import com.google.common.base.Predicate;

/**
 * SetupAndTeardownScenarioRealNodeHTTPS contains necessary operations that must be executed before and after HTTPS test suite.
 */
@SuppressWarnings({"PMD.LawOfDemeter"})
public class SetupAndTeardownScenarioHttps extends SetupAndTeardownScenario {

    public static final String nodeTypes = DataHandler.getConfiguration().getProperty("https.nodeTypes", "ERBS,RBS,MGW",
            String.class);

    public static final String HTTPS_POSITIVE_FILESBASE_TESTS = "HttpsPositiveFileBaseTests";
    public static final String HTTPS_POSITIVE_NODESBASE_TESTS = "HttpsPositiveNodesBaseTests";

    public static final String HTTPS_NEGATIVE_WRONGROLE_TESTS = "HttpsNegativeWrongRoleTests";
    public static final String HTTPS_NEGATIVE_UNSYNCHNODES_TESTS = "HttpsNegativeUnsynchNodeTests";
    public static final String HTTPS_NEGATIVE_NOTEXISTNODES_TESTS = "HttpsNegativeNotExistNodeTests";
    public static final String HTTPS_NEGATIVE_NOTSUPPORTEDNODES_TESTS = "HttpsNegativeNotSupportedNodeTests";

    public static final String NODES_TO_ADD_NOT_EXIST = "HttpsNotExistNodeTest";

    public static List<String> positiveCustomRolesList()  {
        return Arrays.asList(ROLE_NODESECURITY_ADMIN);
    }

    public static List<String> negativeCustomRolesList()  {
        return Arrays.asList(ROLE_NODESECURITY_OPERATOR, ROLE_SSH_KEY);
    }

    @Override
    public List<String> rbacCustomRolesList() {
        getLogger().debug("\n SetupAndTeardownScenarioHttps rbacCustomRoles \n");
        final List<String> newList = new ArrayList<String>();
        newList.addAll(positiveCustomRolesList());
        newList.addAll(negativeCustomRolesList());
        return newList;
    }

    @Override
    public Predicate<DataRecord> correctNodeType() {
        getLogger().debug("\n SetupAndTeardownScenarioHttps correctNodeType \n");
        return PredicateUtil.genericPredicate("nodeType", Arrays.asList(nodeTypes.split(",")));
    }

    /**
     * Meant to be overridden by child classes if more specific DataSources are needed.
     */
    @Override
    protected void setupSpecificDataSource() {

        final String path = "data" + File.separator + "feature" + File.separator + "https" + File.separator;

        final TestDataSource<DataRecord> fileName = fromCsv(path + "HttpsFileBase.csv");
        context.addDataSource(HTTPS_POSITIVE_FILESBASE_TESTS, fileName);
        final TestDataSource<DataRecord> nodeName = fromCsv(path + "HttpsNodeBase.csv");
        context.addDataSource(HTTPS_POSITIVE_NODESBASE_TESTS, nodeName);

        final TestDataSource<DataRecord> notExistNodename = fromCsv(path + "NotExistNodeName.csv");
        context.addDataSource(NODES_TO_ADD_NOT_EXIST, notExistNodename);

        final TestDataSource<DataRecord> errorMsgWrongRole = fromCsv(path + "ErrorMessageWrongRoleHttps.csv");
        context.addDataSource(HTTPS_NEGATIVE_WRONGROLE_TESTS, errorMsgWrongRole);
        final TestDataSource<DataRecord> errorMsgUnsynchNode = fromCsv(path + "ErrorMessageUnsynchNodeHttps.csv");
        context.addDataSource(HTTPS_NEGATIVE_UNSYNCHNODES_TESTS, errorMsgUnsynchNode);
        final TestDataSource<DataRecord> errorMsgNotExistNode = fromCsv(path + "ErrorMessageNotExistNodeHttps.csv");
        context.addDataSource(HTTPS_NEGATIVE_NOTEXISTNODES_TESTS, errorMsgNotExistNode);
        final TestDataSource<DataRecord> errorMsgUnsupportedNode = fromCsv(path + "ErrorMessageUnsupportedNodeHttps.csv");
        context.addDataSource(HTTPS_NEGATIVE_NOTSUPPORTEDNODES_TESTS, errorMsgUnsupportedNode);

        ScenarioUtility.dumpDataSource();
        ScenarioUtility.debugScope(getLogger(), HTTPS_POSITIVE_FILESBASE_TESTS);
        ScenarioUtility.debugScope(getLogger(), HTTPS_POSITIVE_NODESBASE_TESTS);
        ScenarioUtility.debugScope(getLogger(), HTTPS_NEGATIVE_WRONGROLE_TESTS);

        ScenarioUtility.debugScope(getLogger(), NODES_TO_ADD_NOT_EXIST);

        ScenarioUtility.debugScope(getLogger(), HTTPS_NEGATIVE_UNSYNCHNODES_TESTS);
        ScenarioUtility.debugScope(getLogger(), HTTPS_NEGATIVE_NOTEXISTNODES_TESTS);
        ScenarioUtility.debugScope(getLogger(), HTTPS_NEGATIVE_NOTSUPPORTEDNODES_TESTS);
    }

    @BeforeSuite(alwaysRun = true, groups = { "Functional", "NSS", "RFA250", "ARNL", "KGB" })
    @Parameters({ "agat" })
    public void onBeforeSuite(final ITestContext suiteContext, @Optional final String agat) {
        onBeforeSuiteMethod(suiteContext, agat);
    }

    @AfterSuite(alwaysRun = true, groups = { "Functional", "NSS", "RFA250", "ARNL", "KGB" })
    public void onAfterSuite() {
        onAfterSuiteMethod();
    }
}
