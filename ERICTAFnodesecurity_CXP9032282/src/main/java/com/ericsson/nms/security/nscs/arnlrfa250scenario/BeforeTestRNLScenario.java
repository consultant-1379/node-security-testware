/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2016
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/

package com.ericsson.nms.security.nscs.arnlrfa250scenario;

import com.ericsson.cifwk.taf.annotations.TestSuite;
import com.ericsson.cifwk.taf.data.DataHandler;
import com.ericsson.cifwk.taf.datasource.DataRecord;
import com.ericsson.cifwk.taf.scenario.TestScenario;
import com.ericsson.cifwk.taf.scenario.api.ScenarioExceptionHandler;
import com.ericsson.nms.security.nscs.datasource.DataSourceException;
import com.ericsson.nms.security.nscs.predicate.PredicateUtil;
import com.ericsson.oss.testware.nodesecurity.flows.CredentialsFlows;
import com.ericsson.oss.testware.nodesecurity.flows.UtilFlows;
import com.google.common.base.Predicate;
import org.testng.ITestContext;
import org.testng.annotations.*;

import javax.inject.Inject;
import java.lang.reflect.Method;
import java.util.concurrent.TimeUnit;

import static com.ericsson.cifwk.taf.datasource.TafDataSources.copy;
import static com.ericsson.cifwk.taf.datasource.TafDataSources.fromTafDataProvider;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.*;
import static com.ericsson.nms.security.nscs.predicate.PredicateUtil.userRoleSuiteNamePredicate;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.*;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.NODES_TO_ADD;
import static com.google.common.collect.Iterables.filter;

@SuppressWarnings({"PMD.LawOfDemeter", "PMD.ExcessiveImports"})
public class BeforeTestRNLScenario extends ScenarioUtility {

    @Inject
    private SetupAndTeardownBeforeTestRNLScenario setupAndTeardownBeforeTestRNLScenario;

    @Inject
    private UtilFlows utilFlows;


    @BeforeSuite (groups = { "ARNL", "ENM_EXTERNAL_TESTWARE" })
    @Parameters({ "agat" })
    public void beforeSuite(final ITestContext suiteContext, @Optional final String agat) {
        SetupAndTeardownScenario.setAgat(agat);
        setupAndTeardownBeforeTestRNLScenario.onBeforeSuite(suiteContext, SetupAndTeardownScenario.getAgat());
        final Predicate<DataRecord> predicatePositive = userRoleSuiteNamePredicate("roles",
                SetupAndTeardownScenarioCredential.positiveCustomRolesList());
        final Predicate<DataRecord> predicateNegative = userRoleSuiteNamePredicate("roles",
                SetupAndTeardownScenarioCredential.negativeCustomRolesList());
        super.beforeClass(predicatePositive, predicateNegative);
        final TestScenario beforeClassScenario = scenario("Before Suite RNL Test Scenario - Get Node(s) Network Element MOs")
                .addFlow(utilityFlows.login(PredicateUtil.nsuAdm(), vUser))
                .addFlow(utilityFlows.checkSyncNodeStatusOnce(vUser))
                .addFlow(utilFlows.getNetworkElementMOs(vUser)).withExceptionHandler(ScenarioExceptionHandler.LOGONLY)
                .build();
        startScenario(beforeClassScenario);
        setupAndTeardownBeforeTestRNLScenario.onAfterSuiteMethod();
    }
}
