/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2017
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
import static com.ericsson.nms.security.nscs.constants.UserRoleValues.ROLE_FTPES;
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

@SuppressWarnings({"PMD.LawOfDemeter"})
public class SetupAndTeardownScenarioFtpes extends SetupAndTeardownScenario {

    public static final String nodeTypes = DataHandler.getConfiguration().getProperty("ftpes.nodeTypes", "RadioNode,Controller6610",
            String.class);

    public static final String FTPES_POSITIVE_FILE_BASED_TEST = "FtpesPositiveFileBasedTest";
    public static final String FTPES_POSITIVE_NODE_BASED_TEST = "FtpesPositiveNodeBasedTest";
    public static final String FTPES_NEGATIVE_UNSYNC_NODES_TEST = "ftpesNegativeUnsyncNodesTest";
    public static final String FTPES_NEGATIVE_NOT_EXISTING_NODES_TEST = "ftpesNegativeNotExistingNodesTest";
    public static final String FTPES_NEGATIVE_WRONG_ROLE_TEST = "ftpesNegativeWrongRoleTest";
    public static final String FTPES_NEGATIVE_UNSUPP_TYPE_TEST = "ftpesNegativeUnsuppTypeTest";
    public static final String NODES_TO_ADD_NOT_EXIST = "FtpesNotExistNodeTest";

    protected final String FTPES_CSV_FILES_PATH = "data" + File.separator + "feature" + File.separator + "ftpes" + File.separator;
    private final String ERROR_MESSAGES_PATH = "data" + File.separator + "feature" + File.separator + "errorMsg" + File.separator;

    static List<String> positiveCustomRoles() {
        return Arrays.asList(ROLE_NODESECURITY_ADMIN, ROLE_FTPES);
    }

    static List<String> negativeCustomRoles() {
        return Arrays.asList(ROLE_NODESECURITY_OPERATOR, ROLE_SSH_KEY);
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
    public List<String> rbacCustomRolesList() {
        getLogger().debug("FTPES Setup and Teardown Scenario custom roles setup.");
        final List<String> customRoles = new ArrayList<>(positiveCustomRoles());
        customRoles.addAll(negativeCustomRoles());
        return customRoles;
    }

    @Override
    public Predicate<DataRecord> correctNodeType() {
        getLogger().debug("FTPES Setup and Teardown Scenario correct node type setup.");
        return PredicateUtil.genericPredicate("nodeType", Arrays.asList(nodeTypes.split(",")));
    }

    @Override
    protected void setupSpecificDataSource() {
        final TestDataSource<DataRecord> fileBased = fromCsv(FTPES_CSV_FILES_PATH + "FtpesFileBase.csv");
        context.addDataSource(FTPES_POSITIVE_FILE_BASED_TEST, fileBased);
        final TestDataSource<DataRecord> nodeBased = fromCsv(FTPES_CSV_FILES_PATH + "FtpesNodeBase.csv");
        context.addDataSource(FTPES_POSITIVE_NODE_BASED_TEST, nodeBased);
        final TestDataSource<DataRecord> typeNotSuppErrorMsg = fromCsv(FTPES_CSV_FILES_PATH + "ErrorMessageUnsupportedNodeFtpes.csv");
        context.addDataSource(FTPES_NEGATIVE_UNSUPP_TYPE_TEST, typeNotSuppErrorMsg);
        final TestDataSource<DataRecord> unsyncErrorMsg = fromCsv(ERROR_MESSAGES_PATH + "ErrorMessageUnsynchNode.csv");
        context.addDataSource(FTPES_NEGATIVE_UNSYNC_NODES_TEST, unsyncErrorMsg);
        final TestDataSource<DataRecord> notExistErrorMsg = fromCsv(ERROR_MESSAGES_PATH + "ErrorMessageNotExistNode.csv");
        context.addDataSource(FTPES_NEGATIVE_NOT_EXISTING_NODES_TEST, notExistErrorMsg);
        final TestDataSource<DataRecord> wrongRoleErrorMsg = fromCsv(ERROR_MESSAGES_PATH + "ErrorMessageWrongRole.csv");
        context.addDataSource(FTPES_NEGATIVE_WRONG_ROLE_TEST, wrongRoleErrorMsg);

        final TestDataSource<DataRecord> notExistNodeName = fromCsv(FTPES_CSV_FILES_PATH + "NotExistNodeName.csv");
        context.addDataSource(NODES_TO_ADD_NOT_EXIST, notExistNodeName);

        ScenarioUtility.dumpDataSource();
        ScenarioUtility.debugScope(getLogger(), FTPES_POSITIVE_FILE_BASED_TEST);
        ScenarioUtility.debugScope(getLogger(), FTPES_POSITIVE_NODE_BASED_TEST);
        ScenarioUtility.debugScope(getLogger(), FTPES_NEGATIVE_UNSYNC_NODES_TEST);
        ScenarioUtility.debugScope(getLogger(), FTPES_NEGATIVE_NOT_EXISTING_NODES_TEST);
        ScenarioUtility.debugScope(getLogger(), NODES_TO_ADD_NOT_EXIST);
        ScenarioUtility.debugScope(getLogger(), FTPES_NEGATIVE_WRONG_ROLE_TEST);
        ScenarioUtility.debugScope(getLogger(), FTPES_NEGATIVE_UNSUPP_TYPE_TEST);
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