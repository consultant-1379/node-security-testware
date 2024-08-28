/**
 * ------------------------------------------------------------------------------
 * ******************************************************************************
 * COPYRIGHT Ericsson 2021
 * <p>
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 * ******************************************************************************
 * ------------------------------------------------------------------------------
 */

package com.ericsson.nms.security.nscs.arnlrfa250scenario;

import com.ericsson.cifwk.taf.annotations.TestSuite;
import com.ericsson.cifwk.taf.datasource.DataRecord;
import com.ericsson.cifwk.taf.scenario.TestScenario;
import com.ericsson.nms.security.nscs.predicate.PredicateUtil;

import com.ericsson.oss.testware.nodesecurity.flows.LdapRestFlows;

import com.ericsson.oss.testware.security.authentication.flows.LoginLogoutRestFlows;
import com.google.common.base.Predicate;
import com.google.common.collect.Iterables;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import javax.inject.Inject;

import java.lang.reflect.Method;


import static com.ericsson.cifwk.taf.scenario.TestScenarios.*;
import static com.ericsson.nms.security.nscs.arnlrfa250scenario.IscfAndCredApiScenarioUtility.executeScenario;
import static com.ericsson.nms.security.nscs.arnlrfa250scenario.SetupAndTeardownScenarioLdap_REST.*;
import static com.ericsson.nms.security.nscs.predicate.PredicateUtil.*;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.ADDED_NODES;

@SuppressWarnings({"PMD.LawOfDemeter"})
public class LdapREST_TestScenario extends ScenarioUtility {

    private static final Logger LOGGER = LoggerFactory.getLogger(LdapREST_TestScenario.class);
    private static final String SINGLE_NODE_DATA_SOURCE = "singleNodeDataSource";
    private static final String POST_PATH_PARAM_NODE_NAME_SCENARIO = " POST having path parameter: <nodeName>";
    private static final String POST_PATH_PARAM_NODE_NAME_NETWORKELEMENT_SCENARIO = "POST having path parameter: NetworkElement=<nodeName>";
    private static final String POST_PATH_PARAM_NODE_NAME_IP_FAMILY_SCENARIO = "POST having path parameter <nodename> and query param ipFamily";

    private static final String POST_INVALID_NODE_RESOURCE_SCENARIO = "POST having invalid <nodeName>";
    private static final String DELETE_INVALID_NODE_RESOURCE_SCENARIO = "DELETE having invalid <nodeName>";
    private static final String POST_NODE_NO_NES = "POST with node having NetworkElementSecurity undefined";
    private static final String DELETE_NODE_NO_NES = "DELETE with node having NetworkElementSecurity undefined";
    private static final String DELETE_SCENARIO = "DELETE rest";
    private static final String RBAC_POST_DELETE_SCENARIO = "Verify RBAC violation";

    private static final String RBAC_FLOW = "RBAC verification flow";
    private static final String LDAP_REST_POSITIVE_FLOW = "Ldap REST Positive flow";
    private static final String INVALID_RESOURCES_FLOW = "Invalid Resources flow";

    @Inject
    LdapRestFlows ldapRestFlows;

    @Inject
    protected LoginLogoutRestFlows loginlogoutFlow;

    @BeforeClass(groups = { "Functional", "NSS" })
    public void beforeClass() {
        LOGGER.info("\n-----<< Starting BEFORE CLASS Ldap REST >>-----\n");
        final Predicate<DataRecord> predicatePositive =  userRoleSuiteNamePredicate("roles", positiveCustomRolesList());
        final Predicate<DataRecord> predicateNegative = userRoleSuiteNamePredicate("roles", negativeCustomRolesList());
        super.beforeClass(predicatePositive, predicateNegative);
        LOGGER.info("\n----<< BEFORE CLASS Ldap REST - END >>----- \n");
    }

    @Test(enabled = true, priority = 1, groups = {"Functional", "NSS" })
    @TestSuite
    public void ldapRestPostWithParamNodeName() {
        // POST rest invoked having path parameter nodeName=<nodename>
        buildInputDataSource("1", "Ldap_REST_POST_invoked_having_path_param_nodeName", ADDED_NODES, userListPositive);
        runLdapRestScenario(POST_PATH_PARAM_NODE_NAME_SCENARIO, nsuLdapRest(), LDAP_REST_POSITIVE_FLOW, true);
    }


    @Test(enabled = true, priority = 2, groups = {"Functional", "NSS" })
    @TestSuite
    public void ldapRestPostWithParamNetworkElement() {
        // POST rest invoked having path parameter nodeName = <NetworkElement=nodename>
        buildInputDataSource("2", "Ldap_REST_POST_invoked_having_path_param_nodeName_NetworkElement=<nodeName>", ADDED_NODES, userListPositive);
        runLdapRestScenario(POST_PATH_PARAM_NODE_NAME_NETWORKELEMENT_SCENARIO, nsuLdapRest(), LDAP_REST_POSITIVE_FLOW, true);
    }

    @Test(enabled = true, priority = 3, groups = {"Functional", "NSS" })
    @TestSuite
    public void ldapRestPostWithIpFamily6() {
        // POST rest invoked having path parameter nodeName=<nodename> and query param ipFamily=INET6
        context.removeDataSource(SINGLE_NODE_DATA_SOURCE);
        fetchSpecificNodeFromCsv(SINGLE_NODE_DATA_SOURCE, context.dataSource(ADDED_NODES), isCbpoiNodeIpv4);
        buildInputDataSource("3", "Ldap_REST_POST_invoked_having_path_parameter_nodeName=<nodename>_and_query_param_ipFamily=INET6",
                SINGLE_NODE_DATA_SOURCE, userListPositive);
        runLdapRestScenario(POST_PATH_PARAM_NODE_NAME_IP_FAMILY_SCENARIO, nsuLdapRest(), LDAP_REST_POSITIVE_FLOW, true);
    }

    @Test(enabled = true, priority = 4, groups = {"Functional", "NSS" })
    @TestSuite
    public void ldapRestPostWithIpFamily4() {
        // POST rest invoked having path parameter nodeName=<nodename> and query param ipFamily=INET
        context.removeDataSource(SINGLE_NODE_DATA_SOURCE);
        fetchSpecificNodeFromCsv(SINGLE_NODE_DATA_SOURCE, context.dataSource(ADDED_NODES), isCbpoiNodeIpv6);
        buildInputDataSource("4", "Ldap_REST_POST_invoked_having_path_parameter_nodeName=<nodename>_and_query_param_ipFamily=INET",
                SINGLE_NODE_DATA_SOURCE, userListPositive);
        runLdapRestScenario(POST_PATH_PARAM_NODE_NAME_IP_FAMILY_SCENARIO, nsuLdapRest(), LDAP_REST_POSITIVE_FLOW, true);
    }

    @Test(enabled = true, priority = 5, groups = {"Functional", "NSS" })
    @TestSuite
    public void ldapRestDELETE() {
        // DELETE rest invoked having path parameter nodeName=<nodename>
        context.removeDataSource(SINGLE_NODE_DATA_SOURCE);
        fetchSpecificNodeFromCsv(SINGLE_NODE_DATA_SOURCE, context.dataSource(ADDED_NODES), isCbpoiNodeIpv4);
        buildInputDataSource("5", "Ldap_REST_DELETE", SINGLE_NODE_DATA_SOURCE, userListPositive);
        runLdapRestScenario(DELETE_SCENARIO,  nsuLdapRest(), LDAP_REST_POSITIVE_FLOW, true);
    }

    @Test(enabled = true, priority = 6, groups = {"Functional", "NSS" })
    @TestSuite
    public void ldapRestDeleteWithParamNetworkElement() {
        // DELETE rest invoked having path parameter nodeName=<nodename>
        context.removeDataSource(SINGLE_NODE_DATA_SOURCE);
        fetchSpecificNodeFromCsv(SINGLE_NODE_DATA_SOURCE, context.dataSource(ADDED_NODES), isCbpoiNodeIpv6);
        buildInputDataSource("6", "Ldap_REST_DELETE", SINGLE_NODE_DATA_SOURCE, userListPositive);
        runLdapRestScenario(DELETE_SCENARIO,  nsuLdapRest(), LDAP_REST_POSITIVE_FLOW, true);
    }

    ////////////////////////////////////////////////////////////////////////////////////////
    //                                   Negative Tests                                   //
    ////////////////////////////////////////////////////////////////////////////////////////
    //
    // RBAC
    //
    @Test(enabled = true, priority = 7, groups = {"Functional", "NSS" })
    @TestSuite
    public void userWithoutProperRoleCannotPerformPostAndDeleteRestCall() {
        context.removeDataSource(SINGLE_NODE_DATA_SOURCE);
        fetchSpecificNodeFromCsv(SINGLE_NODE_DATA_SOURCE, context.dataSource(ADDED_NODES), isCbpoiNodeIpv4);
        buildInputDataSource("7","Ldap_REST_call_RBAC_violation", SINGLE_NODE_DATA_SOURCE, userListNegative);
        runLdapRestScenario(RBAC_POST_DELETE_SCENARIO, nsuOper(), RBAC_FLOW, false);
    }

    //
    // Invalid Node Resource
    //

    @Test(enabled = true, priority = 8, groups = {"Functional", "NSS" })
    @TestSuite
    public void ldapRestPostInvalidNodeResource() {
        // REST POST invalid Node Resource
        buildInputDataSource("8" ,"Ldap_REST_POST_call_on_a_NOT_EXISTING_node", NOT_EXISTENT_NODE, userListPositive);
        ScenarioUtility.debugScope(LOGGER, INPUT_DATASOURCE);
        runLdapRestScenario(POST_INVALID_NODE_RESOURCE_SCENARIO, nsuLdapRest(), INVALID_RESOURCES_FLOW, false);
    }

    @Test(enabled = true, priority = 9, groups = {"Functional", "NSS" })
    @TestSuite
    public void ldapRestDeleteInvalidNodeResource() {
        // REST DELETE invalid Node Resource
        buildInputDataSource("9" ,"Ldap_REST_DELETE_call_on_a_NOT_EXISTING_node", NOT_EXISTENT_NODE, userListPositive);
        ScenarioUtility.debugScope(LOGGER, INPUT_DATASOURCE);
        runLdapRestScenario(DELETE_INVALID_NODE_RESOURCE_SCENARIO, nsuLdapRest(), INVALID_RESOURCES_FLOW, false);
    }

    //
    // Node without NetworkElementSecurity MO defined (NES)
    // Before method : Remove Network Element Security MO for the specified node
    //
    @BeforeMethod(groups = {"Functional", "NSS" })
    public void beforeMethod_ldapRestNodeHavingNetworkElementSecurityMoUndefined(final Method method) {
        if (method.getName().contains("ldapRestPostNodeHavingNetworkElementSecurityMoUndefined")) {
            LOGGER.info(" -----< Starting Before method \"ldapRestNodeHavingNetworkElementSecurityMoUndefined|\" "
                    + "- Removing Network Element Security MO for the specified node >-----");
            context.removeDataSource(SINGLE_NODE_DATA_SOURCE);
            fetchSpecificNodeFromCsv(SINGLE_NODE_DATA_SOURCE, context.dataSource(ADDED_NODES), isCbpoiNodeIpv4);
            final TestScenario beforeMethod = scenario("Before method ldapRestNodeHavingNetworkElementSecurityMoUndefined ")
                    .addFlow(utilityFlows.login(nsuOper()))
                    .addFlow(ldapRestFlows.removeNodeCredentials().withDataSources(dataSource(SINGLE_NODE_DATA_SOURCE).bindTo(ADDED_NODES)))
                    .addFlow(utilityFlows.logout(nsuOper())).alwaysRun()
                    .build();
            executeScenario(beforeMethod);
            LOGGER.info("\n----<< BEFORE Method - END >>----- \n");
        }
    }

    //
    // Node with Network Element Security MO Undefined
    //
    @Test(enabled = true, priority = 10, groups = {"Functional", "NSS" })
    @TestSuite
    public void ldapRestPostNodeHavingNetworkElementSecurityMoUndefined() {
        // POST
        buildInputDataSource("10" ,"Ldap_REST_POST_call_on_a_node_without_Network_Element_Security_defined",
                SINGLE_NODE_DATA_SOURCE, userListPositive);
        ScenarioUtility.debugScope(LOGGER, INPUT_DATASOURCE);
        runLdapRestScenario(POST_NODE_NO_NES, nsuLdapRest(), INVALID_RESOURCES_FLOW, false);

    }

    @Test(enabled = true, priority = 11, groups = {"Functional", "NSS" })
    @TestSuite
    public void ldapRestDeleteNodeHavingNetworkElementSecurityMoUndefined() {
        // POST
        buildInputDataSource("11" ,"Ldap_REST_DELETE_call_on_a_node_without_Network_Element_Security_defined",
                SINGLE_NODE_DATA_SOURCE, userListPositive);
        ScenarioUtility.debugScope(LOGGER, INPUT_DATASOURCE);
        runLdapRestScenario(DELETE_NODE_NO_NES, nsuLdapRest(), INVALID_RESOURCES_FLOW, false);
    }



    @AfterClass(groups = { "Functional", "NSS" })
    public void afterClass() {
        LOGGER.info("\n\nAfter Class Scenario - CleanUp Proxy Accounts created");
        cleanUpProxyAccount();
    }

    /**
     * This method builds in a unique DataSource (INPUT_DATASOURCE) all the input data.
     *
     * @Param
     *      testfilterpredicate
     *          String predicate to filter the related index row (context) from LDAP_REST_TEST_DATASOURCE
     * @Param
     *      testId
     *          string test ID identifier
     * @Param
     *      NodeDataSource
     *          the input Node datasource
     * @Param
     *      userList
     *          Iterable<DataRecord>
     */
    private void buildInputDataSource(final String testfilterpredicate,
                                      final String testId,
                                      final String NodeDataSource,
                                      final Iterable<DataRecord> userList) {
        final Iterable<DataRecord> testFilteredByPredicate = Iterables.filter(context.dataSource(LDAP_REST_TEST_DATASOURCE),
                PredicateUtil.contextFilter(testfilterpredicate));
        doParallelNodesBase(INPUT_DATASOURCE, testId, testFilteredByPredicate, context.dataSource(NodeDataSource), userList);
        ScenarioUtility.debugScope(LOGGER, INPUT_DATASOURCE);
    }

    private void runLdapRestScenario(final String scenarioName,
                                     final Predicate userPredicate,
                                     final String flowName,
                                     final boolean verifyResponse) {
        final TestScenario scenario = dataDrivenScenario(scenarioName)
                .addFlow(utilityFlows.login(userPredicate))
                .addFlow(verifyResponse ? ldapRestFlows.ldapRestPositiveFlow(flowName) : ldapRestFlows.ldapRestNegativeFlow(flowName))
                .addFlow(utilityFlows.logout(userPredicate)).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(ADDED_NODES))
                .build();
        executeScenario(scenario);
    }
}
