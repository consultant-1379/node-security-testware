/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2020
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
 * SetupAndTeardownScenarioSso contains necessary operations that must be executed before and after SSO test suite.
 */
@SuppressWarnings({ "PMD.LawOfDemeter" })
public class SetupAndTeardownScenarioSso extends SetupAndTeardownScenario {

    public static final String nodeTypes =
 DataHandler.getConfiguration().getProperty("sso.nodeTypes",
                    "MINI-LINK-6352,Router6273,FRONTHAUL-6020,Controller6610", String.class);
    public static final String SSO_ENABLE_WRONG_USER = "SSO_ENABLE_WRONG_USER";
    public static final String SSO_ENABLE_CORRECT_USER = "SSO_ENABLE_CORRECT_USER";
    public static final String SSO_DISABLE_WRONG_USER = "SSO_DISABLE_WRONG_USER";
    public static final String SSO_DISABLE_CORRECT_USER = "SSO_DISABLE_CORRECT_USER";

    @Override
    public Predicate<DataRecord> correctNodeType() {
        getLogger().debug("\n SetupAndTeardownScenarioSso correctNodeType \n");
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
        getLogger().debug("\n SetupAndTeardownScenarioSso rbacCustomRoles \n");
        final List<String> newList = new ArrayList<String>();
        newList.addAll(positiveCustomRolesList());
        newList.addAll(negativeCustomRolesList());
        return newList;
    }

    @Override
    protected void setupSpecificDataSource() {
        final String path = "data" + File.separator + "feature" + File.separator + "sso" + File.separator;
        TestDataSource<DataRecord> sso = fromCsv(path + "SsoEnable.csv");
        context.addDataSource(SSO_ENABLE_CORRECT_USER, sso);
        TestDataSource<DataRecord> wrongErrorMessage = fromCsv(path + "ExpectedMessage.csv");
        context.addDataSource(SSO_ENABLE_WRONG_USER, TafDataSources.merge(sso, wrongErrorMessage));

        sso = fromCsv(path + "SsoDisable.csv");
        context.addDataSource(SSO_DISABLE_CORRECT_USER, sso);
        wrongErrorMessage = fromCsv(path + "ExpectedMessage.csv");
        context.addDataSource(SSO_DISABLE_WRONG_USER, TafDataSources.merge(sso, wrongErrorMessage));

        ScenarioUtility.debugScope(getLogger(), SSO_ENABLE_CORRECT_USER);
        ScenarioUtility.debugScope(getLogger(), SSO_ENABLE_WRONG_USER);
        ScenarioUtility.debugScope(getLogger(), SSO_DISABLE_CORRECT_USER);
        ScenarioUtility.debugScope(getLogger(), SSO_DISABLE_WRONG_USER);
    }

    @Override
    @BeforeSuite(alwaysRun = true, groups = { "Functional", "NSS", "RFA250" })
    @Parameters({ "agat" })
    public void onBeforeSuite(final ITestContext suiteContext, @Optional final String agat) {
        onBeforeSuiteMethod(suiteContext, agat);
    }

    @Override
    @AfterSuite(alwaysRun = true, groups = { "Functional", "NSS", "RFA250" })
    public void onAfterSuite() {
        onAfterSuiteMethod();
    }

}
