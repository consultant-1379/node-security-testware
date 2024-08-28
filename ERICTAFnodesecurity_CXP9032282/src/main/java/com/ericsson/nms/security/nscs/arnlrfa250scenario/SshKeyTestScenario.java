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

import static com.ericsson.cifwk.taf.scenario.TestScenarios.dataDrivenScenario;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.dataSource;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.flow;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.scenario;
import static com.ericsson.nms.security.nscs.predicate.PredicateUtil.userRoleSuiteNamePredicate;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.ADDED_NODES;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.AVAILABLE_USERS;

import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;
import javax.inject.Inject;

import com.ericsson.cifwk.taf.data.DataHandler;
import com.ericsson.cifwk.taf.scenario.api.ScenarioExceptionHandler;
import com.ericsson.oss.testware.nodeintegration.flows.NodeIntegrationFlows;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.ericsson.cifwk.taf.TestContext;
import com.ericsson.cifwk.taf.annotations.TestSuite;
import com.ericsson.cifwk.taf.datasource.DataRecord;
import com.ericsson.cifwk.taf.scenario.TestScenario;
import com.ericsson.cifwk.taf.scenario.TestScenarioRunner;
import com.ericsson.nms.security.nscs.predicate.PredicateUtil;
import com.ericsson.oss.testware.nodesecurity.flows.CredentialsFlows;
import com.ericsson.oss.testware.nodesecurity.flows.SshKeyFlows;
import com.google.common.base.Predicate;
import com.google.common.collect.Iterables;

/**
 * SshKey Scenario.
 */
@SuppressWarnings({"PMD.LawOfDemeter"})
public class SshKeyTestScenario extends ScenarioUtility {

    private static final Logger LOGGER = LoggerFactory.getLogger(SshKeyTestScenario.class);
    private static final String wait = "Wait";
    private static final String nodeTypeFilterValue = "nodeType =='vEPG-OI'";

    @Inject
    private TestContext context;
    @Inject
    private SshKeyFlows sshKeyFlows;
    @Inject
    private CredentialsFlows credentialsFlows;
    @Inject
    private NodeIntegrationFlows nodeIntegrationFlows;



    @BeforeClass(groups = { "Functional", "NSS", "RFA250" })
    public void beforeClass() {
        traceScope(STARTING_MESSAGE + "@BeforeClass", 2);
        final Predicate<DataRecord> predicatePositive =  userRoleSuiteNamePredicate("roles",
                SetupAndTeardownScenarioSshKey.positiveCustomRolesList());
        final Predicate<DataRecord> predicateNegative = userRoleSuiteNamePredicate("roles",
                SetupAndTeardownScenarioSshKey.negativeCustomRolesList());
        super.beforeClass(predicatePositive, predicateNegative);

        LOGGER.info("\n   BEFORE CLASS SSHKEY TEST - START \n");
        dumpDataSource();
        LOGGER.info("\n   BEFORE CLASS SSHKEY TEST - END \n");
        final TestScenario beforeClassScenario = scenario("Before Class SshKey Scenario")
                .addFlow(utilityFlows.login(PredicateUtil.nsuAdm(), vUser))
                .addFlow(credentialsFlows.getSecurityInfoBasic(vUser))
                .addFlow(nodeIntegrationFlows.enableCMSupervision().withDataSources(dataSource(ADDED_NODES).withFilter(nodeTypeFilterValue).allowEmpty()))
                .addFlow(nodeIntegrationFlows.verifySynchNodeBuilder().withDataSources(dataSource(ADDED_NODES).withFilter(nodeTypeFilterValue).allowEmpty()))
                .addFlow(sshKeyFlows.getUserAuthentication().withDataSources(dataSource(ADDED_NODES).withFilter(nodeTypeFilterValue).allowEmpty()))
                .addFlow(utilityFlows.logout(PredicateUtil.nsuAdm(), vUser)).alwaysRun()
                .build();
        startScenario(beforeClassScenario);
        traceScope(FINISHED_MESSAGE + "@BeforeClass", 2);
    }

    @Test(enabled = true, priority = 1, groups = { "Functional", "NSS", "RFA250" })
    @TestSuite
    public void sshKeyCreatePositive() {
        traceScope(STARTING_MESSAGE + "sshKeyCreatePositive()", 2);
        traceScope(STARTING_MESSAGE + "doParallelNodesBase()", 1);
        doParallelNodesBase(INPUT_DATASOURCE, "NSCS_SSHKEY_CREATE_WITH_DIFFERENT_ALGOTYPE",
                Iterables.filter(context.dataSource(SetupAndTeardownScenarioSshKey.SSH_POSITIVE ),
                        PredicateUtil.userRolePredicate("testType", Arrays.asList("create"))),
                context.dataSource(ADDED_NODES),
                Iterables.filter(context.dataSource(AVAILABLE_USERS), PredicateUtil.nscsAdm()));
        traceScope(FINISHED_MESSAGE + "doParallelNodesBase()", 1);
        traceScope(STARTING_MESSAGE + "Ssh key create scenario", 1);
        final TestScenario scenario = dataDrivenScenario("Ssh key create scenario")
                .addFlow(loginLogoutRestFlows.loginBuilder())
                //Pre-Condition
                .addFlow(credentialsFlows.credentialsDeleteFlow())
                .addFlow(flow(wait).pause(1, TimeUnit.SECONDS))
                .addFlow(credentialsFlows.credentialsCreateBasic())
                .addFlow(flow(wait).pause(1, TimeUnit.SECONDS))
                //Pre-Condition End
                .addFlow(sshKeyFlows.sshKeyCreateAndVerify(false))
                //Post-Condition (only on Real Node)
                .addFlow(SetupAndTeardownScenario.isRealNode() ? sshKeyFlows.sshKeyRestoreBasic() : flow("")).alwaysRun()
                //.addFlow(sshKeyFlows.sshKeyRestoreBasic()).alwaysRun()
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(AVAILABLE_USERS).bindTo(ADDED_NODES))
                .doParallel(1).build();
        startScenario(scenario);
        traceScope(FINISHED_MESSAGE + "Ssh key create scenario", 1);
        traceScope(FINISHED_MESSAGE + "sshKeyCreatePositive()", 2);
    }

    @Test(enabled = true, priority = 2, groups = { "Functional", "NSS", "RFA250" })
    @TestSuite
    public void sshKeyUpdatePositive() {
        traceScope(STARTING_MESSAGE + "sshKeyUpdatePositive()", 2);
        traceScope(STARTING_MESSAGE + "doParallelNodesBase()", 1);
        doParallelNodesBase(INPUT_DATASOURCE, "NSCS_SSHKEY_UPDATE_WITH_DIFFERENT_ALGOTYPE",
                Iterables.filter(context.dataSource(SetupAndTeardownScenarioSshKey.SSH_POSITIVE ),
                        PredicateUtil.userRolePredicate("testType", Arrays.asList("update"))),
                context.dataSource(ADDED_NODES),
                Iterables.filter(context.dataSource(AVAILABLE_USERS), PredicateUtil.nscsAdm()));
        traceScope(FINISHED_MESSAGE + "doParallelNodesBase()", 1);
        traceScope(STARTING_MESSAGE + "Ssh key update scenario", 1);
        final TestScenario scenario = dataDrivenScenario("Ssh key update scenario")
                .addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(sshKeyFlows.sshKeyUpdateAndVerify(false))
                //Post-Condition (only on Real Node)
                .addFlow(SetupAndTeardownScenario.isRealNode() ? sshKeyFlows.sshKeyRestoreBasic() : flow("")).alwaysRun()
                //.addFlow(sshKeyFlows.sshKeyRestoreBasic()).alwaysRun()
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(AVAILABLE_USERS).bindTo(ADDED_NODES))
                .doParallel(1).build();
        startScenario(scenario);
        traceScope(FINISHED_MESSAGE + "Ssh key update scenario", 1);
        traceScope(FINISHED_MESSAGE + "sshKeyUpdatePositive()", 2);
    }

    @Test(enabled = true, priority = 3, groups = { "Functional", "NSS", "RFA250" })
    @TestSuite
    public void sshKeyDeletePositive() {
        traceScope(STARTING_MESSAGE + "sshKeyDeletePositive()", 2);
        traceScope(STARTING_MESSAGE + "doParallelNodesBase()", 1);
        doParallelNodesBase(INPUT_DATASOURCE, "NSCS_SSHKEY_DELETE",
                Iterables.filter(context.dataSource(SetupAndTeardownScenarioSshKey.SSH_POSITIVE),
                        PredicateUtil.userRolePredicate("testType", Arrays.asList("delete"))),
                context.dataSource(ADDED_NODES), Iterables.filter(context.dataSource(AVAILABLE_USERS), PredicateUtil.nscsAdm()));
        traceScope(FINISHED_MESSAGE + "doParallelNodesBase()", 1);
        traceScope(STARTING_MESSAGE + "Ssh key delete scenario", 1);
        final TestScenario scenario = dataDrivenScenario("Ssh key delete scenario")
                .addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(sshKeyFlows.sshKeyDeleteAndVerify(false))
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(AVAILABLE_USERS).bindTo(ADDED_NODES))
                .doParallel(1).build();
        startScenario(scenario);
        traceScope(FINISHED_MESSAGE + "Ssh key delete scenario", 1);
        traceScope(FINISHED_MESSAGE + "sshKeyDeletePositive()", 2);
    }

    @Test(enabled = true, priority = 4, groups = { "Functional", "NSS" })
    @TestSuite
    public void sshKeyCreateNegative() {
        traceScope(STARTING_MESSAGE + "sshKeyCreateNegative()", 2);
        traceScope(STARTING_MESSAGE + "doParallelNodesBase()", 1);
        doParallelNodesBase(INPUT_DATASOURCE, "NSCS_SSHKEY_CREATE_WRONG_USER",
                Iterables.filter(context.dataSource(SetupAndTeardownScenarioSshKey.SSH_NEGATIVE),
                        PredicateUtil.userRolePredicate("testType", Arrays.asList("create"))),
                context.dataSource(ADDED_NODES), userListNegative);
        traceScope(FINISHED_MESSAGE + "doParallelNodesBase()", 1);
        traceScope(STARTING_MESSAGE + "Ssh key create wrong user scenario", 1);
        final TestScenario scenario = dataDrivenScenario("Ssh key create wrong user scenario")
                .addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(sshKeyFlows.sshKeyCreateAndVerify(true))
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(AVAILABLE_USERS).bindTo(ADDED_NODES))
                .doParallel(vUser).build();
        startScenario(scenario);
        traceScope(FINISHED_MESSAGE + "Ssh key create wrong user scenario", 1);
        traceScope(FINISHED_MESSAGE + "sshKeyCreateNegative()", 2);
    }

    @Test(enabled = true, priority = 5, groups = { "Functional", "NSS" })
    @TestSuite
    public void sshKeyUpdateNegative() {
        traceScope(STARTING_MESSAGE + "sshKeyUpdateNegative()", 2);
        traceScope(STARTING_MESSAGE + "doParallelNodesBase()", 1);
        doParallelNodesBase(INPUT_DATASOURCE, "NSCS_SSHKEY_UPDATE_WRONG_USER",
                Iterables.filter(context.dataSource(SetupAndTeardownScenarioSshKey.SSH_NEGATIVE),
                        PredicateUtil.userRolePredicate("testType", Arrays.asList("update"))),
                context.dataSource(ADDED_NODES), userListNegative);
        traceScope(FINISHED_MESSAGE + "doParallelNodesBase()", 1);
        traceScope(STARTING_MESSAGE + "Ssh key update wrong user scenario", 1);
        final TestScenario scenario = dataDrivenScenario("Ssh key update wrong user scenario")
                .addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(sshKeyFlows.sshKeyUpdateAndVerify(true))
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(AVAILABLE_USERS).bindTo(ADDED_NODES))
                .doParallel(vUser).build();
        startScenario(scenario);
        traceScope(FINISHED_MESSAGE + "Ssh key update wrong user scenario", 1);
        traceScope(FINISHED_MESSAGE + "sshKeyUpdateNegative()", 2);
    }

    @Test(enabled = true, priority = 6, groups = { "Functional", "NSS" })
    @TestSuite
    public void sshKeyDeleteNegative() {
        traceScope(STARTING_MESSAGE + "sshKeyDeleteNegative()", 2);
        traceScope(STARTING_MESSAGE + "doParallelNodesBase()", 1);
        doParallelNodesBase(INPUT_DATASOURCE, "NSCS_SSHKEY_DELETE_WRONG_USER",
                Iterables.filter(context.dataSource(SetupAndTeardownScenarioSshKey.SSH_NEGATIVE),
                        PredicateUtil.userRolePredicate("testType", Arrays.asList("delete"))),
                context.dataSource(ADDED_NODES), userListNegative);
        traceScope(FINISHED_MESSAGE + "doParallelNodesBase()", 1);
        traceScope(STARTING_MESSAGE + "Ssh key delete wrong user scenario", 1);
        final TestScenario scenario = dataDrivenScenario("Ssh key delete wrong user scenario")
                .addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(sshKeyFlows.sshKeyDeleteAndVerify(true))
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(AVAILABLE_USERS).bindTo(ADDED_NODES))
                .doParallel(vUser).build();
        startScenario(scenario);
        traceScope(FINISHED_MESSAGE + "Ssh key delete wrong user scenario", 1);
        traceScope(FINISHED_MESSAGE + "sshKeyDeleteNegative()", 2);
    }
}
