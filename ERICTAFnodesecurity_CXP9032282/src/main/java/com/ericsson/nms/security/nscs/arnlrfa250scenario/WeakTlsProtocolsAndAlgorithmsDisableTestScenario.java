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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import com.ericsson.cifwk.taf.annotations.TestSuite;
import com.ericsson.cifwk.taf.datasource.DataRecord;
import com.ericsson.cifwk.taf.scenario.TestScenario;
import com.ericsson.cifwk.taf.scenario.TestScenarioRunner;
import com.ericsson.oss.testware.nodesecurity.flows.PibParametersReadUpdateFlow;
import com.google.common.base.Predicate;

import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import javax.inject.Inject;

import static com.ericsson.cifwk.taf.scenario.TestScenarios.dataDrivenScenario;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.dataSource;
import static com.ericsson.nms.security.nscs.predicate.PredicateUtil.userRoleSuiteNamePredicate;
import static com.ericsson.oss.testware.nodesecurity.constant.AgnosticConstants.READPIB;
import static com.ericsson.oss.testware.nodesecurity.constant.AgnosticConstants.UPDATEPIB;
import static com.ericsson.oss.testware.nodesecurity.pibcommands.PibCommandConfigurator.ALGORITHM_PIB;
import static com.ericsson.oss.testware.nodesecurity.pibcommands.PibCommandConfigurator.TLS_AES_128;
import static com.ericsson.oss.testware.nodesecurity.pibcommands.PibCommandConfigurator.TLS_DHE;
import static com.ericsson.oss.testware.nodesecurity.pibcommands.PibCommandConfigurator.TLS_DSS;
import static com.ericsson.oss.testware.nodesecurity.pibcommands.PibCommandConfigurator.TLS_PIB;
import static com.ericsson.oss.testware.nodesecurity.pibcommands.PibCommandConfigurator.TLS_SHA;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.ADDED_NODES;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.AVAILABLE_USERS;

@SuppressWarnings({"PMD.LawOfDemeter"})
public class WeakTlsProtocolsAndAlgorithmsDisableTestScenario extends ScenarioUtility {

    @Inject
    private PibParametersReadUpdateFlow pibParameterReadUpdateFlow;

    public static final String ENABLED_TLS_PROTOCOLS_ECIM = "enabledTLSProtocolsECIM";
    public static final String ENABLED_TLS_PROTOCOLS_LDAP = "enabledTLSProtocolsExtLDAP";

    public static final List<String> algorithmsvalueList = new ArrayList<String>();
    public static final List<String> comEcimPibParam = new ArrayList<String>();
    public static final List<String> extLdapPibParam = new ArrayList<String>();

    @BeforeClass(groups = { "Functional", "NSS" })
    public void beforeClass() {
        final Predicate<DataRecord> predicatePositive =  userRoleSuiteNamePredicate("roles",
                SetupAndTeardownScenarioWeakTlsProtocolsAndAlgorithmsDisable.positiveCustomRolesList());
        final Predicate<DataRecord> predicateNegative = userRoleSuiteNamePredicate("roles",
                SetupAndTeardownScenarioWeakTlsProtocolsAndAlgorithmsDisable.negativeCustomRolesList());
        super.beforeClass(predicatePositive, predicateNegative);
    }

    @Test(enabled = true, priority = 1, groups = { "Functional", "NSS" })
    @TestSuite
    public void disableWeakTlsProtocolsAndAlgorithms() {
        doParallelNodesBase(INPUT_DATASOURCE, "NSCS_DISABLE_WEAK_TLS_PROTOCOLS_AND_ALGORITHMS_COMECIM",
                context.dataSource(ADDED_NODES), userListPositive);
        ScenarioUtility.debugScope(LOGGER, INPUT_DATASOURCE);
        comEcimPibParam.add(ENABLED_TLS_PROTOCOLS_ECIM);
        extLdapPibParam.add(ENABLED_TLS_PROTOCOLS_LDAP);
        algorithmsvalueList.addAll(Arrays.asList(TLS_AES_128,TLS_DSS,TLS_DHE,TLS_SHA));
        final TestScenario scenario = dataDrivenScenario("Disable Weak Tls Protocols And Update Algorithms Test Scenario")
                .addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(utilityFlows.verifySyncNodes())
                .addFlow(pibParameterReadUpdateFlow.pibCommandFlow("readTlsPibCommandFlow", READPIB, TLS_PIB, comEcimPibParam))
                .addFlow(pibParameterReadUpdateFlow.pibCommandFlow("readTlsPibCommandFlow", READPIB, TLS_PIB, extLdapPibParam))
                .addFlow(pibParameterReadUpdateFlow.pibCommandFlow("readAlgorithmPibCommandFlow", READPIB, ALGORITHM_PIB, algorithmsvalueList))
                .addFlow(pibParameterReadUpdateFlow.pibCommandFlow("updateTlsPibCommandFlow", UPDATEPIB, TLS_PIB, comEcimPibParam))
                .addFlow(pibParameterReadUpdateFlow.pibCommandFlow("updateTlsPibCommandFlow", UPDATEPIB, TLS_PIB, extLdapPibParam))
                .addFlow(utilityFlows.actionSyncNodeOnNodes(vUser))
                .addFlow(pibParameterReadUpdateFlow.pibCommandFlow("updateAlgorithmPibCommandFlow", UPDATEPIB, ALGORITHM_PIB, algorithmsvalueList))
                .addFlow(utilityFlows.actionSyncNodeOnNodes(vUser))
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(AVAILABLE_USERS).bindTo(ADDED_NODES))
                .doParallel(vUser).build();
        final TestScenarioRunner runner = SetupAndTearDownUtil.getScenarioRunner();
        runner.start(scenario);
    }
}
