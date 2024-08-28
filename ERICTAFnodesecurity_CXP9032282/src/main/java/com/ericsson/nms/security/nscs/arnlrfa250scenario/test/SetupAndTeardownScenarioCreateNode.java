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

package com.ericsson.nms.security.nscs.arnlrfa250scenario.test;

import static com.ericsson.cifwk.taf.scenario.TestScenarios.flow;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.scenario;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.NODES_TO_ADD;

import java.util.HashMap;
import java.util.Map;
import javax.inject.Inject;

import org.testng.ITestContext;
import org.testng.annotations.AfterSuite;
import org.testng.annotations.BeforeSuite;
import org.testng.annotations.Optional;
import org.testng.annotations.Parameters;

import com.ericsson.cifwk.taf.datasource.DataRecord;
import com.ericsson.cifwk.taf.datasource.DataRecordImpl;
import com.ericsson.cifwk.taf.datasource.TestDataSource;
import com.ericsson.cifwk.taf.scenario.api.TestScenarioBuilder;
import com.ericsson.nms.security.nscs.arnlrfa250scenario.SetupAndTeardownScenario;
import com.ericsson.nms.security.nscs.predicate.PredicateUtil;
import com.ericsson.oss.testware.security.authentication.flows.LoginLogoutRestFlows;
import com.ericsson.oss.testware.security.gim.flows.UserManagementTestFlows;
import com.google.common.base.Predicate;

/**
 * SetupAndTeardownScenarioCreateNode performs necessary operations that must be executed before and after every test suite.
 */
@SuppressWarnings({"PMD.LawOfDemeter"})
public class SetupAndTeardownScenarioCreateNode extends SetupAndTeardownScenario {

    @Inject
    UserManagementTestFlows userManagementTestFlows;
    @Inject
    LoginLogoutRestFlows loginLogoutRestFlows;
    @Override
    protected boolean isRbacRequested() {
        return false;
    }

    @Override
    protected boolean isTbacRequested() {
        return false;
    }

    @Override
    public Predicate<DataRecord> netSimTest() {
        return PredicateUtil.passTrue();
    }

    /**
     * Meant to be overridden by child classes if more specific DataSources are needed.
     */
    @Override
    protected void setupSpecificDataSource() {
    }

    @Override
    protected TestScenarioBuilder beforeSuiteScenarioBuilder() {
        final int vUser = getNumberOfNodes();
        final TestScenarioBuilder scenarioBuilder = scenario("Before Suite Scenario")
                .addFlow(utilityFlows.startNetsimNodes(netSimTest()).withVusers(vUser))
                .addFlow(flow("Login Default User").addSubFlow(loginLogoutRestFlows.loginDefaultUser()).withVusers(vUser))
                .addFlow(utilityFlows.createNodes(netSimTest(), vUser))
                .addFlow(utilityFlows.syncNodes(isSynchNodeRequested(), netSimTest(), vUser))
                .addFlow(utilityFlows.subscriptionEnableTest(isFmSupervisionRequested(), vUser))
                .addFlow(flow("Logout Default User").addSubFlow(loginLogoutRestFlows.logout()).withVusers(vUser))
                .alwaysRun();
        return scenarioBuilder;
    }

    @Override
    protected void scenarioSetupAfterBeforeSuite() {
        final TestDataSource<DataRecord> nodesListReadFromDataProvider = context.dataSource(NODES_TO_ADD);
        context.removeDataSource(NODES_TO_ADD);
        for (final DataRecord node : nodesListReadFromDataProvider) {
            final Map<String, Object> param = new HashMap<>(node.getAllFields());
            param.remove("nodeOperatorType");
            context.dataSource(NODES_TO_ADD).addRecord().setFields(new DataRecordImpl(param));
        }
    }


    @BeforeSuite(alwaysRun = true)
    @Parameters({ "agat" })
    public void onBeforeSuite(final ITestContext suiteContext, @Optional final String agat) {
        onBeforeSuiteMethod(suiteContext, agat);
    }

    @AfterSuite(alwaysRun = true)
    public void onAfterSuite() {
        onAfterSuiteMethod();
    }

}
