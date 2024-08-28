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
import static com.ericsson.nms.security.nscs.arnlrfa250scenario.ScenarioUtility.FINISHED_MESSAGE;
import static com.ericsson.nms.security.nscs.arnlrfa250scenario.ScenarioUtility.STARTING_MESSAGE;
import static com.ericsson.nms.security.nscs.constants.UserRoleValues.ROLE_NODESECURITY_ADMIN;
import static com.ericsson.nms.security.nscs.constants.UserRoleValues.ROLE_NODESECURITY_OPERATOR;
import static com.ericsson.nms.security.nscs.constants.UserRoleValues.ROLE_SSH_KEY;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.inject.Inject;

import org.testng.ITestContext;
import org.testng.ITestNGMethod;
import org.testng.annotations.AfterSuite;
import org.testng.annotations.BeforeSuite;
import org.testng.annotations.Optional;
import org.testng.annotations.Parameters;

import com.ericsson.cifwk.taf.data.DataHandler;
import com.ericsson.cifwk.taf.datasource.DataRecord;
import com.ericsson.cifwk.taf.datasource.TestDataSource;
import com.ericsson.nms.security.nscs.predicate.PredicateUtil;
import com.google.common.base.Predicate;
import com.google.common.collect.Iterables;

/**
 * SetupAndTeardownScenarioSshKey contains necessary operations that must be executed before and after SshKey test suite.
 */
@SuppressWarnings({"PMD.LawOfDemeter"})
public class SetupAndTeardownScenarioSshKey extends SetupAndTeardownScenario {

    public static final String nodeTypes = DataHandler.getConfiguration().getProperty("sshKey.nodeTypes", "vEPG-OI,SGSN-MME",  String.class);


    public static final String CRED_CREATE = "CredCreate";
    public static final String SSH_POSITIVE = "SSH_POSITIVE";
    public static final String SSH_NEGATIVE = "SSH_NEGATIVE";;


    @Inject
    public ScenarioUtility scenarioUtility;

    @Override
    public Predicate<DataRecord> correctNodeType() {
        getLogger().debug("\n SetupAndTeardownScenarioSshKey correctNodeType \n");
        return PredicateUtil.genericPredicate("nodeType", Arrays.asList(nodeTypes.split(",")));
    }

    public static List<String> positiveCustomRolesList()  {
        return Arrays.asList(ROLE_NODESECURITY_ADMIN);
    }

    public static List<String> negativeCustomRolesList()  {
        return Arrays.asList(ROLE_NODESECURITY_OPERATOR);
    }

    @Override
    public boolean isRbacRequested(){
        return false;
    }

    @Override
    public List<String> rbacCustomRolesList() {
        getLogger().debug("\n SetupAndTeardownScenarioSshKey rbacCustomRoles \n");
        final List<String> newList = new ArrayList<String>();
        newList.addAll(positiveCustomRolesList());
        newList.addAll(negativeCustomRolesList());
        return newList;
    }

    @Override
    protected boolean isFmSupervisionRequested() {
        return false;
    }

    @Override
    protected boolean isSynchNodeRequested() {
        return false;
    }

    protected void setupSpecificDataSource() {
        final String credPath = "data" + File.separator + "feature" + File.separator + "credential" + File.separator;
        final String sshPath = "data" + File.separator + "feature" + File.separator + "sshKey" + File.separator;

        final TestDataSource<DataRecord> credCreate = fromCsv(credPath + "CredCreate.csv");
        context.addDataSource(CRED_CREATE, credCreate);

        final TestDataSource<DataRecord> sshKeyPositive = fromCsv(sshPath + "SshKeyPositiveTestsAll.csv");
        context.addDataSource(SSH_POSITIVE, sshKeyPositive);

        context.addDataSource(SSH_NEGATIVE, fromCsv(sshPath + "SshKeyNegativeAll.csv"));

        getLogger().debug("\n SSH_POSITIVE \n" + Iterables.toString(context.dataSource(SSH_POSITIVE)).replace(", Data value: ", ",\nData value: "));
        getLogger().debug("\n SSH_NEGATIVE \n" + Iterables.toString(context.dataSource(SSH_NEGATIVE)).replace(", Data value: ", ",\nData value: "));
    }

    @BeforeSuite(alwaysRun = true, groups = { "Functional", "NSS", "RFA250", "ARNL" })
    @Parameters({ "agat" })
    public void onBeforeSuite(final ITestContext suiteContext, @Optional final String agat) {
        scenarioUtility.traceScope(STARTING_MESSAGE + "@BeforeSuite", 3);
        //        getLogger().debug("\nsuiteContext.toString(): [{}]\n", suiteContext.toString());
        final String suiteName = suiteContext.getSuite().getName();
        getLogger().debug("\nsuiteName [{}]\n", suiteName);
        final List<ITestNGMethod> allSuiteMethods = suiteContext.getSuite().getAllMethods();
        for (final ITestNGMethod suiteMethod : allSuiteMethods) {
            getLogger().debug("suiteMethod.getMethodName() [{}]", suiteMethod.getMethodName());
        }
        onBeforeSuiteMethod(suiteContext, agat);
        scenarioUtility.traceScope(FINISHED_MESSAGE + "@BeforeSuite", 3);
    }

    @AfterSuite(alwaysRun = true, groups = { "Functional", "NSS", "RFA250", "ARNL" })
    public void onAfterSuite() {
        scenarioUtility.traceScope(STARTING_MESSAGE + "@AfterSuite", 3);
        onAfterSuiteMethod();
        scenarioUtility.traceScope(FINISHED_MESSAGE + "@AfterSuite", 3);
    }
}
