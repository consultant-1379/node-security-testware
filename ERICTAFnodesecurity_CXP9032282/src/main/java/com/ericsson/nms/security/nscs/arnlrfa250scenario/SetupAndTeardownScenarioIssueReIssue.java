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
import static com.ericsson.nms.security.nscs.constants.UserRoleValues.ROLE_IPSEC;
import static com.ericsson.nms.security.nscs.constants.UserRoleValues.ROLE_NODESECURITY_ADMIN;
import static com.ericsson.nms.security.nscs.constants.UserRoleValues.ROLE_NODESECURITY_OPERATOR;
import static com.ericsson.nms.security.nscs.constants.UserRoleValues.ROLE_OAM;
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
public class SetupAndTeardownScenarioIssueReIssue extends SetupAndTeardownCertTypeScenario {

    public static final String nodeTypes = DataHandler.getConfiguration().getProperty("issueReissue.nodeTypes", "ERBS,RNC,RBS,MGW,MRS,RadioNode,BSC,VTFRadioNode,vRM,Router6675,5GRadioNode,vPP,vBSC,vRC,vTIF,NeLS,vSAPC,Router6672,FRONTHAUL-6020,Controller6610,SCU,ESC,Shared-CNF,vDU",
            String.class);

    public static final String ISSUE_EXPMSG = "ISSUE_EXPMSG";
    public static final String REISSUE_OAM = "REISSUE_OAM";
    public static final String REISSUE_IPSEC = "REISSUE_IPSEC";
    public static final String REISSUE_OAM_EXPMSG = "REISSUE_OAM_EXPMSG";
    public static final String REISSUE_IPSEC_EXPMSG = "REISSUE_IPSEC_EXPMSG";
    public static final String ISSUE_REISSUE_SYNTAX_NEGATIVE = "ISSUE_REISSUE_SYNTAX_NEGATIVE";

    @Override
    public Predicate<DataRecord> correctNodeType() {
        getLogger().debug("\n SetupAndTeardownScenarioIssueReIssue correctNodeType \n");
        return PredicateUtil.genericPredicate("nodeType", Arrays.asList(nodeTypes.split(",")));
    }

    public static List<String> positiveCustomRolesList() {
        return Arrays.asList(ROLE_NODESECURITY_ADMIN, ROLE_OAM, ROLE_IPSEC);
    }

    public static List<String> negativeCustomRolesList() {
        return Arrays.asList(ROLE_NODESECURITY_OPERATOR, ROLE_SSH_KEY);
    }

    @Override
    public List<String> rbacCustomRolesList() {
        getLogger().debug("\n SetupAndTeardownScenarioIssueReIssue rbacCustomRoles \n");
        final List<String> newList = new ArrayList<String>();
        newList.addAll(positiveCustomRolesList());
        newList.addAll(negativeCustomRolesList());
        return newList;
    }

    protected void setupSpecificDataSource() {

        super.setupSpecificDataSource();

        final String path = "data" + File.separator + "feature" + File.separator + "issueReIssue" + File.separator;
        final TestDataSource<DataRecord> errorMessage = fromCsv(path + "ExpectedMessage.csv");
        final TestDataSource<DataRecord> issue_expMsg = fromCsv(path + "ExpectedMessage.csv");
        context.addDataSource(ISSUE_EXPMSG, issue_expMsg);
        final TestDataSource<DataRecord> reissueoam = fromCsv(path + "REISSUE_OAM.csv");
        context.addDataSource(REISSUE_OAM, reissueoam);
        final TestDataSource<DataRecord> reissueipsec = fromCsv(path + "REISSUE_IPSEC.csv");
        context.addDataSource(REISSUE_IPSEC, reissueipsec);
        context.addDataSource(REISSUE_OAM_EXPMSG, TafDataSources.merge(reissueoam, errorMessage));
        context.addDataSource(REISSUE_IPSEC_EXPMSG, TafDataSources.merge(reissueipsec, errorMessage));

        final TestDataSource<DataRecord> issueSyntaxError = fromCsv(path + "SyntaxErrorCertificateIssueTests.csv");
        final TestDataSource<DataRecord> reIssueSyntaxError = fromCsv(path + "SyntaxErrorCertificateReissueTests.csv");
        context.addDataSource(ISSUE_REISSUE_SYNTAX_NEGATIVE, TafDataSources.combine(issueSyntaxError, reIssueSyntaxError));

        ScenarioUtility.dumpDataSource();
        ScenarioUtility.debugScope(getLogger(), ISSUE_EXPMSG);
        ScenarioUtility.debugScope(getLogger(), REISSUE_OAM);
        ScenarioUtility.debugScope(getLogger(), REISSUE_IPSEC);
        ScenarioUtility.debugScope(getLogger(), REISSUE_OAM_EXPMSG);
        ScenarioUtility.debugScope(getLogger(), REISSUE_IPSEC_EXPMSG);
        ScenarioUtility.debugScope(getLogger(), ISSUE_REISSUE_SYNTAX_NEGATIVE);
    }

    @BeforeSuite(alwaysRun = true, groups = { "Functional", "NSS", "RFA250", "ARNL", "ENM_EXTERNAL_TESTWARE", "AGAT_BUILD_ISO" })
    @Parameters({ "agat" })
    public void onBeforeSuite(final ITestContext suiteContext, @Optional final String agat) {
        onBeforeSuiteMethod(suiteContext, agat);
    }

    @AfterSuite(alwaysRun = true, groups = { "Functional", "NSS", "RFA250", "ARNL", "ENM_EXTERNAL_TESTWARE", "AGAT_BUILD_ISO" })
    public void onAfterSuite() {
        onAfterSuiteMethod();
    }
}
