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
import com.ericsson.oss.testware.nodesecurity.flows.GenerateEnrollmentInfoFlows;
import com.ericsson.oss.testware.nodesecurity.flows.GenerateEnrollmentInfoRestFlows;
import com.ericsson.oss.testware.nodesecurity.flows.PkiCommandFlow;
import com.ericsson.oss.testware.security.authentication.flows.LoginLogoutRestFlows;
import com.google.common.base.Predicate;
import com.google.common.collect.Iterables;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import javax.inject.Inject;

import static com.ericsson.cifwk.taf.scenario.TestScenarios.*;
import static com.ericsson.nms.security.nscs.arnlrfa250scenario.IscfAndCredApiScenarioUtility.executeScenario;
import static com.ericsson.nms.security.nscs.arnlrfa250scenario.SetupAndTeardownGenerateEnrollmentInfoScenario.DEFAULT_OTP_PARAMETERS_VALUE;
import static com.ericsson.nms.security.nscs.arnlrfa250scenario.SetupAndTeardownGenerateEnrollmentInfo_REST.*;
import static com.ericsson.nms.security.nscs.arnlrfa250scenario.SetupAndTeardownScenarioLdap_REST.LDAP_REST_TEST_DATASOURCE;
import static com.ericsson.nms.security.nscs.predicate.PredicateUtil.*;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.*;

@SuppressWarnings({"PMD.LawOfDemeter", "PMD.ExcessiveImports"})
public class GenEnrollInfoREST_TestScenario extends ScenarioUtility {

    private static final Logger LOGGER = LoggerFactory.getLogger(GenEnrollInfoREST_TestScenario.class);
    private static final String SINGLE_NODE_DATA_SOURCE = "singleNodeDataSource";
    private static final String GENERATE_ENROLLMENT_INFO_POST_DEFAULT_PARAM = "POST Domain OAM test Scenario with default params";
    private static final String GENERATE_ENROLLMENT_INFO_POST_QUERY_AND_BODY_PARAMS = "POST Domain OAM test Scenario with query param and body";
    private static final String GENERATE_ENROLLMENT_INFO_DELETE_DOMAIN = "DELETE Domain test Scenario";
    private static final String GENERATE_ENROLLMENT_INFO_RBAC = "Verify RBAC violation";
    private static final String GENERATE_ENROLLMENT_INFO_NOT_EXISTENT_NODE = "Generate Enrollment Info REST - invalid Node resource";
    private static final String GENERATE_ENROLLMENT_INFO_INVALID_PARAMS = "Generate Enrollment Info REST - invalid Node params";

    private static final String RBAC_FLOW = "RBAC verification flow";
    private static final String POST_REST_FLOW = "POST REST Domain flow";
    private static final String POST_DELETE_FLOW = "DELETE REST Domain flow";
    private static final String INVALID_RESOURCES_FLOW = "Invalid Resources flow";

    @Inject
    GenerateEnrollmentInfoFlows generateEnrollmentInfoFlows;

    @Inject
    GenerateEnrollmentInfoRestFlows generateEnrollmentInfoRestFlows;

    @Inject
    protected LoginLogoutRestFlows loginlogoutFlow;

    @BeforeClass(groups = { "Functional", "NSS" })
    public void beforeClass() {
        LOGGER.info("\n-----<< Starting BEFORE CLASS Generate Enrollment Info REST - Delete PKI EE >>-----\n");
        final Predicate<DataRecord> predicatePositive =  userRoleSuiteNamePredicate("roles", positiveCustomRolesList());
        final Predicate<DataRecord> predicateNegative = userRoleSuiteNamePredicate("roles", negativeCustomRolesList());
        super.beforeClass(predicatePositive, predicateNegative);
        final TestScenario beforeClass = scenario("Get default OTP parameters values")
                .addFlow(loginLogoutRestFlows.loginDefaultUser())
                .addFlow(generateEnrollmentInfoFlows.deleteOamEndEntityBuilder(DELETE_END_ENTITY).withDataSources(dataSource(ADDED_NODES)))
                .addFlow(generateEnrollmentInfoFlows.getdefaultotpvaluesbuilder(DEFAULT_OTP_PARAMETERS_NAME, nodeTypes))
                .addFlow(loginLogoutRestFlows.logout())
                .alwaysRun()
                .build();
        startScenario(beforeClass);
        LOGGER.info("\n----<< BEFORE CLASS Generate Enrollment Info REST - END >>----- \n");
    }

    /**
     * Shared-CNF Node configured with ConnectivityInformation in IPv4
     * POST - path parameters nodeName and domain Name (OAM) - no body
     */
    @Test(enabled = true, priority = 1, groups = {"Functional", "NSS" })
    @TestSuite
    public void generateEnrollmentInfoRestPost_NoPathParam_NoBody() {
        context.removeDataSource(SINGLE_NODE_DATA_SOURCE);
        fetchSpecificNodeFromCsv(SINGLE_NODE_DATA_SOURCE, context.dataSource(ADDED_NODES), isCbpoiNodeIpv4);
        buildInputDataSource("1", "Generate_Enrollment_Information_POST_REST_call_only_path_param",
                SINGLE_NODE_DATA_SOURCE, userListPositive);
        runGenerateEnrollmentInfoScenarioPOST(GENERATE_ENROLLMENT_INFO_POST_DEFAULT_PARAM, POST_REST_FLOW);
    }

    /**
     * Shared-CNF Node configured with ConnectivityInformation in IPv4
     * POST - path parameters nodeName and domain Name (OAM) - query params [INET6]  and body defined
     */
    @Test(enabled = true, priority = 2, groups = {"Functional", "NSS" })
    @TestSuite
    public void generateEnrollmentInfoRestPost_PathParamINET6_Body_SharedCnf_IpV4() {
        context.removeDataSource(SINGLE_NODE_DATA_SOURCE);
        fetchSpecificNodeFromCsv(SINGLE_NODE_DATA_SOURCE, context.dataSource(ADDED_NODES), isCbpoiNodeIpv4);
        buildInputDataSource("2", "Generate_Enrollment_Information_POST_REST_call_path_param_with_query_param_and_body_defined",
                SINGLE_NODE_DATA_SOURCE, userListPositive);
        runGenerateEnrollmentInfoScenarioPOST(GENERATE_ENROLLMENT_INFO_POST_QUERY_AND_BODY_PARAMS, POST_REST_FLOW);
    }

    /**
     * Shared-CNF Node configured with ConnectivityInformation in IPv6
     * POST - path parameters nodeName and domain Name (OAM) - query params [INET]  and body defined
     */
    @Test(enabled = true, priority = 3, groups = {"Functional", "NSS"})
    @TestSuite
    public void generateEnrollmentInfoRestPost_PathParamINET_Body_SharedCnfIpV6() {
        context.removeDataSource(SINGLE_NODE_DATA_SOURCE);
        fetchSpecificNodeFromCsv(SINGLE_NODE_DATA_SOURCE, context.dataSource(ADDED_NODES), isCbpoiNodeIpv6);
        buildInputDataSource("3", "Generate_Enrollment_Information_POST_REST_call_path_param_with_query_param_and_body_defined",
                SINGLE_NODE_DATA_SOURCE, userListPositive);
        runGenerateEnrollmentInfoScenarioPOST(GENERATE_ENROLLMENT_INFO_POST_QUERY_AND_BODY_PARAMS, POST_REST_FLOW);
    }

    /**
     * RadioNode configured with ConnectivityInformation in IPv4
     * POST - path parameters nodeName and domain Name (OAM) - query params [INET6]  and body defined
     */
    @Test(enabled = true, priority = 4, groups = {"Functional", "NSS"})
    @TestSuite
    public void generateEnrollmentInfoRestPost_PathParamINET6_Body_RadioNodeIpV4() {
        context.removeDataSource(SINGLE_NODE_DATA_SOURCE);
        fetchSpecificNodeFromCsv(SINGLE_NODE_DATA_SOURCE, context.dataSource(ADDED_NODES), isComEcimNode);
        buildInputDataSource("4", "Generate_Enrollment_Information_POST_REST_call_path_param_with_query_param_and_body_defined",
                SINGLE_NODE_DATA_SOURCE, userListPositive);
        runGenerateEnrollmentInfoScenarioPOST(GENERATE_ENROLLMENT_INFO_POST_QUERY_AND_BODY_PARAMS, POST_REST_FLOW);
    }

    @Test(enabled = true, priority = 5, groups = {"Functional", "NSS" })
    @TestSuite
    public void generateEnrollmentInfoRestDELETE() {
        buildInputDataSource("5", "Generate_Enrollment_Information_DELETE_REST_call", ADDED_NODES, userListPositive);
        final TestScenario scenario = dataDrivenScenario(GENERATE_ENROLLMENT_INFO_DELETE_DOMAIN)
                .addFlow(utilityFlows.loginFunctionalUser("1"))
                .addFlow(generateEnrollmentInfoRestFlows.generateEnrollmentInfo_REST_DELETE(POST_DELETE_FLOW))
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(ADDED_NODES))
                .build();
        executeScenario(scenario);
    }

    /**
     * RBAC
     * Negative tests performed with functional Test user without proper role assigned
     * method rest : POST / DELETE
     */
    @Test(enabled = true, priority = 6, groups = {"Functional", "NSS" })
    @TestSuite
    public void userCannotPerformPostAndDeleteRestCall() {
        context.removeDataSource(SINGLE_NODE_DATA_SOURCE);
        fetchSpecificNodeFromCsv(SINGLE_NODE_DATA_SOURCE, context.dataSource(ADDED_NODES), isCbpoiNodeIpv4);
        buildInputDataSource("6", "Generate_Enrollment_Information_POST_and_DELETE_REST_call_RBAC_violation",
                SINGLE_NODE_DATA_SOURCE, userListNegative);
        runGenerateEnrollmentInfoRestScenario_Negative(nsuOper(), GENERATE_ENROLLMENT_INFO_RBAC, RBAC_FLOW);
    }

    /** Negative tests providing invalid resources or wrong parameters
     * POST - NOT existent node
     */
    @Test(enabled = true, priority = 7, groups = {"Functional", "NSS" })
    @TestSuite
    public void generateEnrollmentInfoNegativeTest_POST_Not_Existing_Node() {
        buildInputDataSource("7", "Generate_Enrollment_Information_POST_REST_call_negative_cases",
                NOT_EXISTENT_NODE, userListPositive);
        runGenerateEnrollmentInfoRestScenario_Negative(nsuGenEnrollmentInfoRest(), GENERATE_ENROLLMENT_INFO_NOT_EXISTENT_NODE,
                INVALID_RESOURCES_FLOW);
    }

    /**
     * DELETE - NOT existent node
     */
    @Test(enabled = true, priority = 8, groups = {"Functional", "NSS" })
    @TestSuite
    public void generateEnrollmentInfoNegativeTest_Delete_Not_Existing_Node() {
        buildInputDataSource("8", "Generate_Enrollment_Information_POST_REST_call_negative_cases",
                NOT_EXISTENT_NODE, userListPositive);
        runGenerateEnrollmentInfoRestScenario_Negative(nsuGenEnrollmentInfoRest(), GENERATE_ENROLLMENT_INFO_NOT_EXISTENT_NODE,
                INVALID_RESOURCES_FLOW);
    }

    /**
     * POST - invalid Argument in path param [IPSEC]
     */
    @Test(enabled = true, priority = 9, groups = {"Functional", "NSS" })
    @TestSuite
    public void generateEnrollmentInfoNegativeTest_POST_InvalidPathParam() {
        context.removeDataSource(SINGLE_NODE_DATA_SOURCE);
        fetchSpecificNodeFromCsv(SINGLE_NODE_DATA_SOURCE, context.dataSource(ADDED_NODES), isCbpoiNodeIpv4);
        buildInputDataSource("9", "Generate_Enrollment_Information_POST_REST_call_negative_cases",
                SINGLE_NODE_DATA_SOURCE, userListPositive);
        runGenerateEnrollmentInfoRestScenario_Negative(nsuGenEnrollmentInfoRest(), GENERATE_ENROLLMENT_INFO_INVALID_PARAMS,
                INVALID_RESOURCES_FLOW);
    }

    /**
     * DELETE - invalid Argument in path param [IPSEC]
     */
    @Test(enabled = true, priority = 10, groups = {"Functional", "NSS" })
    @TestSuite
    public void generateEnrollmentInfoNegativeTest_DELETE_InvalidPathParam() {
        context.removeDataSource(SINGLE_NODE_DATA_SOURCE);
        fetchSpecificNodeFromCsv(SINGLE_NODE_DATA_SOURCE, context.dataSource(ADDED_NODES), isCbpoiNodeIpv4);
        buildInputDataSource("10", "Generate_Enrollment_Information_DELETE_REST_call_negative_cases",
                SINGLE_NODE_DATA_SOURCE, userListPositive);
        runGenerateEnrollmentInfoRestScenario_Negative(nsuGenEnrollmentInfoRest(), GENERATE_ENROLLMENT_INFO_INVALID_PARAMS,
                INVALID_RESOURCES_FLOW);
    }

    private void runGenerateEnrollmentInfoRestScenario_Negative(final Predicate userFilterPredicate,
                                                                final String scenarioName,
                                                                final String flowName) {
        final TestScenario scenario = dataDrivenScenario(scenarioName)
                .addFlow(utilityFlows.login(userFilterPredicate))
                .addFlow(generateEnrollmentInfoRestFlows.generateEnrollmentInfo_REST_Negative(flowName))
                .addFlow(utilityFlows.logout(userFilterPredicate)).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(ADDED_NODES))
                .build();
        executeScenario(scenario);
    }

    private void runGenerateEnrollmentInfoScenarioPOST(final String scenarioName,
                                                       final String flowName) {
        final TestScenario scenario = dataDrivenScenario(scenarioName)
                .addFlow(utilityFlows.login(nsuGenEnrollmentInfoRest()))
                .addFlow(generateEnrollmentInfoRestFlows.generateEnrollmentInfo_REST_POST(flowName, DEFAULT_ENROLLMENT_MODE_VALUE))
                .addFlow(generateEnrollmentInfoFlows.getAndVerifyOamEndEntity(DEFAULT_OTP_PARAMETERS_VALUE))
                .addFlow(utilityFlows.logout(nsuGenEnrollmentInfoRest())).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(ADDED_NODES))
                .build();
        executeScenario(scenario);
    }

    /**
     * This method builds in a unique DataSource (INPUT DATA SOURCE) all the input data.
     *
     * @Param
     *      testfilterpredicate
     *          String predicate to filter the related index row (context) from GENERATE_ENROLLMENT_INFO_TEST_DATASOURCE
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
        final Iterable<DataRecord> testFilteredByPredicate = Iterables.filter(context.dataSource(GENERATE_ENROLLMENT_INFO_TEST_DATASOURCE),
                PredicateUtil.contextFilter(testfilterpredicate));
        doParallelNodesBase(INPUT_DATASOURCE, testId, testFilteredByPredicate, context.dataSource(NodeDataSource), userList);
        ScenarioUtility.debugScope(LOGGER, INPUT_DATASOURCE);
    }
}


