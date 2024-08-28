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

import static com.ericsson.cifwk.taf.datasource.TafDataSources.fromCsv;
import static com.ericsson.cifwk.taf.datasource.TafDataSources.merge;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.dataDrivenScenario;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.dataSource;
import static com.ericsson.cifwk.taf.scenario.TestScenarios.scenario;
import static com.ericsson.nms.security.nscs.arnlrfa250scenario.SetupAndTeardownScenarioLdap.*;
import static com.ericsson.nms.security.nscs.predicate.PredicateUtil.userRoleSuiteNamePredicate;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.ADDED_NODES;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.AVAILABLE_USERS;
import static com.ericsson.oss.testware.nodesecurity.constant.AgnosticConstants.WAIT_TO_POPULATE_ELASTIC_SEARCH;
import static com.ericsson.oss.testware.nodesecurity.steps.LdapTestSteps.StoreBindDnMode.*;
import static com.ericsson.oss.testware.nodesecurity.steps.LdapTestSteps.ValueParam.LDAP_BIND_DN;

import javax.inject.Inject;

import com.ericsson.cifwk.taf.annotations.TestId;
import com.ericsson.cifwk.taf.datasource.TestDataSource;
import com.ericsson.cifwk.taf.scenario.api.ScenarioExceptionHandler;
import com.ericsson.oss.testware.nodesecurity.flows.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testng.ITestContext;
import org.testng.annotations.*;

import com.ericsson.cifwk.taf.TestContext;
import com.ericsson.cifwk.taf.annotations.TestSuite;
import com.ericsson.cifwk.taf.datasource.DataRecord;
import com.ericsson.cifwk.taf.scenario.TestScenario;
import com.ericsson.nms.security.nscs.flow.UtilityFlows;
import com.ericsson.nms.security.nscs.predicate.PredicateUtil;
import com.ericsson.oss.testware.nodesecurity.steps.LdapTestSteps;
import com.ericsson.oss.testware.security.authentication.flows.LoginLogoutRestFlows;
import com.google.common.base.Predicate;

import java.lang.reflect.Method;

@SuppressWarnings({"PMD.LawOfDemeter"})
public class LdapTestScenario extends ScenarioUtility {

    private static final Logger LOGGER = LoggerFactory.getLogger(LdapTestScenario.class);

    @Inject
    private TestContext context;

    @Inject
    private UtilityFlows utilityFlows;

    @Inject
    private LdapFlows ldapFlows;

    @Inject
    private CertificateIssueFlows certificateIssueFlows;

    @Inject
    private LoginLogoutRestFlows loginlogoutFlow;

    @Inject
    private PibFlows pibFlow;

    @Inject
    private ProxyAccountFlows proxyAccountFlows;

    private static final String SINGLE_NODE_DATA_SOURCE = "singleNodeDataSource";

    @BeforeClass(groups = {"Functional", "NSS", "RFA250"})
    public void beforeClass() {
        final Predicate<DataRecord> predicatePositive = userRoleSuiteNamePredicate("roles",
                SetupAndTeardownScenarioLdap.positiveCustomRolesList());
        final Predicate<DataRecord> predicateNegative = userRoleSuiteNamePredicate("roles",
                SetupAndTeardownScenarioLdap.negativeCustomRolesList());
        final Predicate<DataRecord> predicatePositiveLdap = userRoleSuiteNamePredicate("roles",
                SetupAndTeardownScenarioLdap.positiveLdapRoleList());
        super.beforeClass(predicatePositiveLdap, predicatePositive, predicateNegative);
        LOGGER.info("\n   BEFORE CLASS LDAP TEST - START \n");
        dumpDataSource();
        final TestScenario beforeClassScenario = scenario("Before Class Ldap Scenario")
                .addFlow(utilityFlows.login(PredicateUtil.nsuAdm(), vUser))
                .addFlow(certificateIssueFlows.certificateIssueVerify(SetupAndTeardownScenarioLdap.ISSUE_OAM, false)
                        .withDataSources(dataSource(ADDED_NODES)).withVusers(vUser))
                .addFlow(utilityFlows.verifySyncNodes(vUser))
                .addFlow(utilityFlows.logout(PredicateUtil.nsuAdm(), vUser)).alwaysRun()
                .build();
        startScenario(beforeClassScenario);
        LOGGER.info("\n   BEFORE CLASS LDAP TEST - END \n");
    }

    @BeforeMethod(groups = { "Functional", "NSS" })
    public void beforeMethod(final Method method) {
        if (method.getName().equals("LdapRenewNoProxyConfigured")) {
            LOGGER.info("\n\nBEFORE Method - clearing BindDn attribute on node Ldap object - START");
            final TestScenario clearBinDnAttributeName = scenario("clear BindDn attribute name on MO node Ldap")
                    .addFlow(utilityFlows.login(PredicateUtil.nsuLdap(), vUser))
                    .addFlow(ldapFlows.restoreLdapAdministrativeStateBuilder((SetupAndTeardownScenarioLdap.LDAP_RESTORE_ADMIN_STATE_DATA_SOURCE))
                            .withDataSources(dataSource(ADDED_NODES)).withVusers(vUser))
                    .addFlow(ldapFlows.retrieveProxyAccountBindDnFromLdapMO(ADD_TO_LIST)
                            .withDataSources(dataSource(ADDED_NODES)).withVusers(vUser))// retrieve bindDn attribute by node Ldap MO and add to BindDNList in order to delete it in teardown
                    .addFlow(ldapFlows.setLdapMoAttribute(SetupAndTeardownScenarioLdap.LDAP_CONFIG_DATA_SOURCE, LDAP_BIND_DN)
                            .withDataSources(dataSource(ADDED_NODES)).withVusers(vUser))//clear BindDN attribute on node Ldap MO
                    .addFlow(ldapFlows.retrieveProxyAccountBindDnFromLdapMO(true, GET)
                            .withDataSources(dataSource(ADDED_NODES)).withVusers(vUser))// get BindDN attribute on node Ldap MO (<null> is expected)
                    .addFlow(utilityFlows.verifySyncNodes(vUser))
                    .addFlow(utilityFlows.logout(PredicateUtil.nsuLdap(), vUser))
                    .alwaysRun()
                    .build();
            startScenario(clearBinDnAttributeName);
            LOGGER.info("\nBEFORE Method - clearing BindDn attribute on node Ldap object - END");
        }
    }

    @Test(enabled = true, priority = 1 ,groups = { "Functional", "NSS" })
    @TestSuite
    public void LdapRenewNoProxyConfigured() {
        doParallelNodesBase(INPUT_DATASOURCE, "TORF-613998_Ldap_Renew_no_configured_proxy",
                context.dataSource(SetupAndTeardownScenarioLdap.LDAP_CONFIG_DATA_SOURCE),
                context.dataSource(ADDED_NODES), userListPositiveLdap);
        final TestScenario scenario = dataDrivenScenario("Ldap Renew on a node without a configured proxy")
                .addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(utilityFlows.verifySyncNodes())
                .addFlow(ldapFlows.retrieveProxyAccountBindDnFromLdapMO(STORE_WITH_NODE_REF))
                .addFlow(ldapFlows.ldapRenewFlow())
                .addFlow(ldapFlows.checkLdapRenew(SetupAndTeardownScenarioLdap.LDAP_CONFIG_DATA_SOURCE))
                .addFlow(loginLogoutRestFlows.logoutBuilder())
                .addFlow(pibFlow.delay(30, WAIT_TO_POPULATE_ELASTIC_SEARCH))
                .addFlow(loginlogoutFlow.loginDefaultUser())
                .addFlow(ldapFlows.retrieveEventsFromSystemRecorder(LDAP_RENEW_PROXY_NOT_CONFIGURED_DATA_SOURCE))
                .addFlow(loginlogoutFlow.logout())
                .alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(AVAILABLE_USERS).bindTo(ADDED_NODES)
                        .bindTo(LdapTestSteps.DataSource.LDAP_DATASOURCE))
                .doParallel(vUser).build();
        startScenario(scenario);
    }

    @Test(enabled = true, priority = 2 ,groups = { "Functional", "NSS" })
    @TestSuite
    public void LdapRenewProxyAlreadyConfigured() {
        doParallelNodesBase(INPUT_DATASOURCE, "TORF-613998_Ldap_Renew_proxy_already_configured",
                context.dataSource(SetupAndTeardownScenarioLdap.LDAP_CONFIG_DATA_SOURCE),
                context.dataSource(ADDED_NODES), userListPositiveLdap);
        final TestScenario scenario = dataDrivenScenario("Ldap Renew on a node with already configured proxy")
                .addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(utilityFlows.verifySyncNodes())
                .addFlow(ldapFlows.retrieveProxyAccountBindDnFromLdapMO(STORE_WITH_NODE_REF))// retrieve BindDn attribute and Store with nodeRef(nodeName)
                .addFlow(ldapFlows.ldapRenewFlow())
                .addFlow(ldapFlows.checkLdapRenew(SetupAndTeardownScenarioLdap.LDAP_CONFIG_DATA_SOURCE))
                .addFlow(loginLogoutRestFlows.logoutBuilder())
                .addFlow(pibFlow.delay(30, WAIT_TO_POPULATE_ELASTIC_SEARCH))
                .addFlow(loginlogoutFlow.loginDefaultUser())
                .addFlow(ldapFlows.retrieveEventsFromSystemRecorder(LDAP_RENEW_PROXY_ALREADY_CONFIGURED__DATA_SOURCE))
                .addFlow(loginlogoutFlow.logout())
                .alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(AVAILABLE_USERS).bindTo(ADDED_NODES)
                        .bindTo(LdapTestSteps.DataSource.LDAP_DATASOURCE))
                .doParallel(vUser).build();
        startScenario(scenario);
    }

    @Test(enabled = true, priority = 3 ,groups =  { "Functional", "NSS" })
    @TestSuite
    public void LdapConfigPositiveTest() {
        doParallelNodesBase(INPUT_DATASOURCE, "NSCS_LDAP_CONFIGURE_FILE_CorrectUserRole",
                context.dataSource(SetupAndTeardownScenarioLdap.LDAP_CONFIG_DATA_SOURCE),
                context.dataSource(ADDED_NODES), userListPositiveLdap);
        final TestScenario scenario = dataDrivenScenario("LDAP Config - Positive Scenario")
                .addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(utilityFlows.verifySyncNodes())
                .addFlow(ldapFlows.retrieveProxyAccountBindDnFromLdapMO(ADD_TO_LIST))// add bindDn to BindDNList in order to delete it in teardown
                .addFlow(ldapFlows.setLdapConfigFlowBasic())
                .addFlow(ldapFlows.setLdapVerificationFlowBasic())
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE)
                        .bindTo(AVAILABLE_USERS)
                        .bindTo(ADDED_NODES)
                        .bindTo(LdapTestSteps.DataSource.LDAP_DATASOURCE))
                .doParallel(vUser).build();
        startScenario(scenario);
    }

    @AfterMethod(groups = { "Functional", "NSS" })
    public void afterMethod(final Method method) {
        if (method.getName().equals("LdapConfigPositiveTest")) {
            final TestScenario restoreLdapAdminState = scenario("After Method - Restore Ldap AdministrativeState to LOCKED")
                    .addFlow(utilityFlows.login(PredicateUtil.nsuLdap(), vUser))
                    .addFlow(ldapFlows.restoreLdapAdministrativeStateBuilder((SetupAndTeardownScenarioLdap.LDAP_RESTORE_ADMIN_STATE_DATA_SOURCE))
                            .withDataSources(dataSource(ADDED_NODES))
                            .withVusers(vUser))
                    .addFlow(utilityFlows.logout(PredicateUtil.nsuLdap(), vUser))
                    .alwaysRun()
                    .build();
            startScenario(restoreLdapAdminState);
        }
    }

    @Test(enabled = true,  priority = 4 ,groups = { "Functional", "NSS" })
    @TestSuite
    public void LdapRenewNegative() {
        singlenode(SINGLE_NODE_DATA_SOURCE, context.dataSource(ADDED_NODES));
        doParallelNodesBase(INPUT_DATASOURCE, "TORF-613998_ENM_User_cannot_RENEW_LDAP_without_proper_role",
                context.dataSource(SetupAndTeardownScenarioLdap.LDAP_RENEW_NEGATIVE_DATA_SOURCE),
                context.dataSource(SINGLE_NODE_DATA_SOURCE), userListNegative);
        final TestScenario scenario = dataDrivenScenario("ENM user without proper role cannot perform Ldap Renew command")
                .addFlow(utilityFlows.login(PredicateUtil.nsuOper()))
                .addFlow(ldapFlows.ldapRenewNegativeFlow(SetupAndTeardownScenarioLdap.LDAP_RENEW_NEGATIVE_DATA_SOURCE))
                .addFlow(loginlogoutFlow.logout())
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE)
                        .bindTo(AVAILABLE_USERS)
                        .bindTo(SINGLE_NODE_DATA_SOURCE)
                        .bindTo(SetupAndTeardownScenarioLdap.LDAP_RENEW_NEGATIVE_DATA_SOURCE))
                .doParallel(vUser).build();
        startScenario(scenario);
    }

    @Test(enabled = true,  priority = 5 ,groups = { "Functional", "NSS" })
    @TestId(id = "NSCS_LDAP_CONFIGURE_MANUAL_CorrectUserRole", title = "configure ldap with option '--manual'")
    public void LdapConfigPositiveTestManual() {
        singlenode(SINGLE_NODE_DATA_SOURCE, context.dataSource(ADDED_NODES));
        final TestScenario scenario = scenario("NSCS_LDAP_CONFIGURE_using --manual")
                .addFlow(utilityFlows.login(PredicateUtil.nsuLdap()))
                .addFlow(ldapFlows.configureLdapManualAndVerifyProxy(SINGLE_NODE_DATA_SOURCE, ADD_TO_LIST)) // configure ldap --manual and add bindDN to bindDnList
                .addFlow(loginlogoutFlow.logout())
                .build();
        startScenario(scenario);
    }

    @AfterClass(groups = { "Functional", "NSS" })
    public void afterClass() {
        LOGGER.info("\n\nAfter Class Scenario - CleanUp Proxy Accounts created");
        cleanUpProxyAccount();
    }
}
