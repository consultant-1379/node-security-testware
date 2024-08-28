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
import com.ericsson.cifwk.taf.datasource.TafDataSources;
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
import static com.ericsson.nms.security.nscs.constants.UserRoleValues.*;

/**
 * SetupAndTeardownScenarioRealNodeShm contains necessary operations that must be executed before and after SHM test suite.
 */
@SuppressWarnings({"PMD.LawOfDemeter"})
public class SetupAndTeardownScenarioCbpoiNode extends SetupAndTeardownCertTypeScenario {

    public static final String nodeTypes = DataHandler.getConfiguration().getProperty("trust.nodeTypes", "vDU,vCU-CP,vCU-UP,Shared-CNF", String.class);
    public static final String ISSUE_EXPMSG = "ISSUE_EXPMSG";
    public static final String REISSUE_OAM = "REISSUE_OAM";
    public static final String REISSUE_OAM_EXPMSG = "REISSUE_OAM_EXPMSG";
    public static final String TRUST_OAM = "TRUST_OAM";
    public static final String TRUST_OAM_EXPMSG = "TRUST_OAM_EXPMSG";
    public static final String LDAP_CONFIG_DATA_SOURCE = "LDAP_CONFIG_DATA_SOURCE";

    private static final String basePath = "data" + File.separator + "feature" + File.separator;

    public static final String PATH_ISSUE = basePath + "issueReIssue" + File.separator;
    public static final String PATH_TRUST = basePath + "trust" + File.separator;
    public static final String PATH_LDAP = basePath + "ldap" + File.separator;

    @Override
    public Predicate<DataRecord> correctNodeType() {
        getLogger().debug("\n SetupAndTeardownScenarioCbpoiNode correctNodeType \n");
        return PredicateUtil.genericPredicate("nodeType", Arrays.asList(nodeTypes.split(",")));
    }

    public List<String> positiveCustomRolesList() {
        return Arrays.asList(ROLE_NODESECURITY_ADMIN, ROLE_OAM);
    }

    public static List<String> positiveLdapRoleList() {
        return Arrays.asList(ROLE_LDAP);
    }

    @Override
    public List<String> rbacCustomRolesList() {
        getLogger().debug("\n SetupAndTeardownScenarioCbpoiNode rbacCustomRoles \n");
        final List<String> newList = new ArrayList<String>();
        newList.addAll(positiveCustomRolesList());
        newList.addAll(positiveLdapRoleList());
        return newList;
    }

    protected void setupSpecificDataSource() {
        super.setupSpecificDataSource();

        final TestDataSource<DataRecord> errorMessageIssue = fromCsv(PATH_ISSUE + "ExpectedMessage.csv");
        final TestDataSource<DataRecord> issue_expMsg = fromCsv(PATH_ISSUE + "ExpectedMessage.csv");
        context.addDataSource(ISSUE_EXPMSG, issue_expMsg);
        final TestDataSource<DataRecord> reissueoam = fromCsv(PATH_ISSUE + "REISSUE_OAM.csv");
        context.addDataSource(REISSUE_OAM, reissueoam);
        context.addDataSource(REISSUE_OAM_EXPMSG, TafDataSources.merge(reissueoam, errorMessageIssue));

        final TestDataSource<DataRecord> trustoam = fromCsv(PATH_TRUST + "TRUST_OAM.csv");
        context.addDataSource(TRUST_OAM, trustoam);
        final TestDataSource<DataRecord> errorMessage = fromCsv(PATH_TRUST + "ExpectedMessage.csv");
        context.addDataSource(TRUST_OAM_EXPMSG, TafDataSources.merge(trustoam, errorMessage));

        final TestDataSource<DataRecord> ldapConfig = fromCsv(PATH_LDAP + "LdapConfig.csv");
        context.addDataSource(LDAP_CONFIG_DATA_SOURCE, ldapConfig);

        ScenarioUtility.dumpDataSource();
        ScenarioUtility.debugScope(getLogger(), REISSUE_OAM);
        ScenarioUtility.debugScope(getLogger(), REISSUE_OAM_EXPMSG);
        ScenarioUtility.debugScope(getLogger(), TRUST_OAM);
        ScenarioUtility.debugScope(getLogger(), TRUST_OAM_EXPMSG);
        ScenarioUtility.debugScope(getLogger(), LDAP_CONFIG_DATA_SOURCE);
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
