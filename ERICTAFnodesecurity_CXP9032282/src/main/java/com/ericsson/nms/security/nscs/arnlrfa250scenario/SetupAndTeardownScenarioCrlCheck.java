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
import com.ericsson.cifwk.taf.datasource.TafDataSources;
import com.ericsson.cifwk.taf.datasource.TestDataSource;
import com.ericsson.nms.security.nscs.predicate.PredicateUtil;
import com.google.common.base.Predicate;

/**
 * SetupAndTeardownScenarioRealNodeShm contains necessary operations that must be executed before and after SHM test suite.
 */
@SuppressWarnings({"PMD.LawOfDemeter"})
public class SetupAndTeardownScenarioCrlCheck extends SetupAndTeardownCertTypeCrlCheckScenario {

    public static final String nodeTypes = DataHandler.getConfiguration().getProperty("crlCheck.nodeTypes", "ERBS,RBS,RNC,MGW,RadioNode,5GRadioNode,"
                    + "VTFRadioNode,vPP,vRC,Router6675,Router6672,FRONTHAUL-6020,Controller6610,Shared-CNF,vDU",
            String.class);

    public static final String ISSUE_OAM = "ISSUE_OAM";
    public static final String ISSUE_IPSEC = "ISSUE_IPSEC";
    public static final String ISSUE_ALL = "ISSUE_ALL";
    public static final String ISSUE_OAM_EXPMSG = "ISSUE_OAM_EXPMSG";
    public static final String ISSUE_IPSEC_EXPMSG = "ISSUE_IPSEC_EXPMSG";
    public static final String ISSUE_ALL_EXPMSG = "ISSUE_ALL_EXPMSG";
    public static final String UNSUPPORTED_NODE_VERSION__EXPMSG = "UNSUPPORTED_NODE_VERSION__EXPMSG";

    public static List<String> positiveCustomRolesList()  {
        return Arrays.asList(ROLE_NODESECURITY_ADMIN);
    }

    public static List<String> negativeCustomRolesList()  {
        return Arrays.asList(ROLE_NODESECURITY_OPERATOR, ROLE_SSH_KEY);
    }

    @Override
    public List<String> rbacCustomRolesList() {
        getLogger().debug("\n SetupAndTeardownScenarioCrlCheck rbacCustomRoles \n");
        final List<String> newList = new ArrayList<String>();
        newList.addAll(positiveCustomRolesList());
        newList.addAll(negativeCustomRolesList());
        return newList;
    }

    @Override
    public Predicate<DataRecord> correctNodeType() {
        getLogger().debug("\n SetupAndTeardownScenarioCrlCheck correctNodeType \n");
        return PredicateUtil.genericPredicate("nodeType", Arrays.asList(nodeTypes.split(",")));
    }

    @Override
    protected void setupSpecificDataSource() {

        super.setupSpecificDataSource();
        
        final String pathIssueReIssue = "data" + File.separator + "feature" + File.separator + "issueReIssue" + File.separator;
        final TestDataSource<DataRecord> oam = fromCsv(pathIssueReIssue + "ISSUE_OAM.csv");
        context.addDataSource(ISSUE_OAM, oam);
        final TestDataSource<DataRecord> ipsec = fromCsv(pathIssueReIssue + "ISSUE_IPSEC.csv");
        context.addDataSource(ISSUE_IPSEC, ipsec);
        final String pathCrlCheck = "data" + File.separator + "feature" + File.separator + "crlcheck" + File.separator;
        final TestDataSource<DataRecord> all = fromCsv(pathCrlCheck + "ISSUE_ALL.csv");
        context.addDataSource(ISSUE_ALL, all);
        final TestDataSource<DataRecord> errorMessage = fromCsv(pathIssueReIssue + "ExpectedMessage.csv");
        context.addDataSource(ISSUE_OAM_EXPMSG, TafDataSources.merge(oam, errorMessage));
        context.addDataSource(ISSUE_IPSEC_EXPMSG, TafDataSources.merge(ipsec, errorMessage));
        context.addDataSource(ISSUE_ALL_EXPMSG, TafDataSources.merge(all, errorMessage));
        final TestDataSource<DataRecord> errorMessageUnsupportedNodeVersion = fromCsv(pathCrlCheck + "UNSUPPORTED_NODE_VERSION_EXPMSG.csv");
        context.addDataSource(UNSUPPORTED_NODE_VERSION__EXPMSG, errorMessageUnsupportedNodeVersion);

        ScenarioUtility.dumpDataSource();
        ScenarioUtility.debugScope(getLogger(), ISSUE_OAM);
        ScenarioUtility.debugScope(getLogger(), ISSUE_IPSEC);
        ScenarioUtility.debugScope(getLogger(), ISSUE_ALL);
        ScenarioUtility.debugScope(getLogger(), ISSUE_OAM_EXPMSG);
        ScenarioUtility.debugScope(getLogger(), ISSUE_IPSEC_EXPMSG);
        ScenarioUtility.debugScope(getLogger(), ISSUE_ALL_EXPMSG);
        ScenarioUtility.debugScope(getLogger(), UNSUPPORTED_NODE_VERSION__EXPMSG);
    }

    @BeforeSuite(alwaysRun = true, groups = { "Functional", "NSS", "RFA250", "ARNL",  "ENM_EXTERNAL_TESTWARE", "KGB", "AGAT_BUILD_ISO" })
    @Parameters({ "agat" })
    public void onBeforeSuite(final ITestContext suiteContext, @Optional final String agat) {
        onBeforeSuiteMethod(suiteContext, agat);
    }

    @AfterSuite(alwaysRun = true, groups = { "Functional", "NSS", "RFA250", "ARNL",  "ENM_EXTERNAL_TESTWARE", "KGB", "AGAT_BUILD_ISO" })
    public void onAfterSuite() {
        onAfterSuiteMethod();
    }
}
