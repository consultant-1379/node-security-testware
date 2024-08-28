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
import static com.ericsson.oss.testware.nodesecurity.pibcommands.PibCommandConfigurator.SSH_AES;
import static com.ericsson.oss.testware.nodesecurity.pibcommands.PibCommandConfigurator.SSH_ECDH;
import static com.ericsson.oss.testware.nodesecurity.pibcommands.PibCommandConfigurator.SSH_HMAC;
import static com.ericsson.oss.testware.nodesecurity.pibcommands.PibCommandConfigurator.SSH_PIB;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.ADDED_NODES;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.AVAILABLE_USERS;



@SuppressWarnings({"PMD.LawOfDemeter"})
public class WeakCiphersRemovalTestScenario extends ScenarioUtility {



    @Inject
    private PibParametersReadUpdateFlow pibParameterReadUpdateFlow;



    public static final String ENABLED_SSH_PROTOCOLS_PIB = "enabledSSHProtocolsPib";
    public static final String ENABLED_SSH_PROTOCOLS_OUTDOORPIB = "enabledSSHProtocolsOutdoorPib";



    public static final List<String> algorithmsvalueList = new ArrayList<String>();
    public static final List<String> PibParam = new ArrayList<String>();
    public static final List<String> OutdoorPibParam = new ArrayList<String>();



    @BeforeClass(groups = { "Functional", "NSS" })
    public void beforeClass() {
        final Predicate<DataRecord> predicatePositive =  userRoleSuiteNamePredicate("roles",
                        SetupAndTeardownWeakCiphersDisable.positiveCustomRolesList());
        final Predicate<DataRecord> predicateNegative = userRoleSuiteNamePredicate("roles",
                        SetupAndTeardownWeakCiphersDisable.negativeCustomRolesList());
        super.beforeClass(predicatePositive, predicateNegative);
    }



    @Test(enabled = true, priority = 1, groups = { "Functional", "NSS" })
    @TestSuite
    public void disableWeakCiphers() {
        doParallelNodesBase(INPUT_DATASOURCE, "NSCS_DISABLE_WEAK_CIPHERS",
                context.dataSource(ADDED_NODES), userListPositive);
        ScenarioUtility.debugScope(LOGGER, INPUT_DATASOURCE);
        PibParam.add(ENABLED_SSH_PROTOCOLS_PIB);
        OutdoorPibParam.add(ENABLED_SSH_PROTOCOLS_OUTDOORPIB);
        algorithmsvalueList.addAll(Arrays.asList(SSH_AES,SSH_ECDH,SSH_HMAC));
        final TestScenario scenario = dataDrivenScenario("Disable Weak Ciphers")
                .addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(utilityFlows.verifySyncNodes())
                .addFlow(pibParameterReadUpdateFlow.pibCommandFlow("readSshPibCommandFlow", READPIB, SSH_PIB, PibParam))
                .addFlow(pibParameterReadUpdateFlow.pibCommandFlow("readSshPibCommandFlow", READPIB, SSH_PIB, OutdoorPibParam))
                .addFlow(pibParameterReadUpdateFlow.pibCommandFlow("readAlgorithmPibCommandFlow", READPIB, ALGORITHM_PIB, algorithmsvalueList))
                .addFlow(pibParameterReadUpdateFlow.pibCommandFlow("updatesshPibCommandFlow", UPDATEPIB, SSH_PIB, PibParam))
                .addFlow(pibParameterReadUpdateFlow.pibCommandFlow("updatesshPibCommandFlow", UPDATEPIB, SSH_PIB, OutdoorPibParam))
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