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
import com.ericsson.cifwk.taf.scenario.TestScenarioRunner;
import com.ericsson.nms.security.nscs.predicate.PredicateUtil;
import com.ericsson.oss.testware.nodesecurity.flows.GenerateEnrollmentInfoFlows;
import com.ericsson.oss.testware.nodesecurity.flows.PkiCommandFlow;

import com.ericsson.oss.testware.security.authentication.flows.LoginLogoutRestFlows;
import com.google.common.base.Predicate;
import com.google.common.collect.Iterables;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import javax.inject.Inject;
import java.lang.reflect.Method;

import static com.ericsson.cifwk.taf.scenario.TestScenarios.*;
import static com.ericsson.nms.security.nscs.arnlrfa250scenario.IscfAndCredApiScenarioUtility.executeScenario;
import static com.ericsson.nms.security.nscs.arnlrfa250scenario.SetupAndTeardownGenerateEnrollmentInfoScenario.*;
import static com.ericsson.nms.security.nscs.arnlrfa250scenario.SetupAndTeardownGenerateEnrollmentInfoScenario.GENERATE_ENROLLMENT_INFO_WRONG_OTP_PARAMS;
import static com.ericsson.nms.security.nscs.predicate.PredicateUtil.*;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.*;

import static com.ericsson.oss.testware.nodesecurity.steps.PkiCommandsTestSteps.EXTCA_INPUTS;

@SuppressWarnings({"PMD.LawOfDemeter", "PMD.ExcessiveImports"})
public class GenEnrollInfoTestScenario extends ScenarioUtility {

    private static final Logger LOGGER = LoggerFactory.getLogger(GenEnrollInfoTestScenario.class);
    private static final String SINGLE_NODE_DATA_SOURCE = "singleNodeDataSource";
    private static final String GENERATE_ENROLLMENT_INFO_SCENARIO_WITH_EXTCA = "Generate Enrollment Info Test Scenario with ExtCa";
    private static final String GENERATE_ENROLLMENT_INFO_SCENARIO_NO_EXTCA = "Generate Enrollment Info Test Scenario without ExtCa excluding/including parameters in xml";
    private static final String SUPPORT_DATASOURCE = "SupportInputDataSource";

    @Inject
    GenerateEnrollmentInfoFlows generateEnrollmentInfoFlows;

    @Inject
    PkiCommandFlow pkiCommandFlow;

    @Inject
    protected LoginLogoutRestFlows loginlogoutFlow;

    @BeforeClass(groups = { "Functional", "NSS" })
    public void beforeClass() {
        LOGGER.info("\n-----<< Starting BEFORE CLASS Generate Enrollment Info - Delete PKI EE and import External CA to ENM >>-----\n");
        final Predicate<DataRecord> predicatePositive =  userRoleSuiteNamePredicate("roles",
                SetupAndTeardownGenerateEnrollmentInfoScenario.positiveCustomRolesList());
        final Predicate<DataRecord> predicateNegative = userRoleSuiteNamePredicate("roles",
                SetupAndTeardownGenerateEnrollmentInfoScenario.negativeCustomRolesList());
        super.beforeClass(predicatePositive, predicateNegative);
        final TestScenario beforeClass = scenario("Get default OTP parameters value and remove pki EE")
                .addFlow(loginLogoutRestFlows.loginDefaultUser())
                .addFlow(generateEnrollmentInfoFlows.deleteOamEndEntityBuilder(DELETE_END_ENTITY).withDataSources(dataSource(ADDED_NODES)))
                .addFlow(generateEnrollmentInfoFlows.getdefaultotpvaluesbuilder(DEFAULT_OTP_PARAMETERS_NAME, nodeTypes))
                .addFlow(pkiCommandFlow.prepareExtCaInputs(EXTCA_DETAILS))
                .addFlow(pkiCommandFlow.importAndPublishExtCa("IMPORT AND PUBLISH EXTCA", EXTCA_DETAILS, EXTCA_INPUTS))
                .addFlow(pkiCommandFlow.createTrustAndEntityProfiles(CREATE_TRUST_PROFILE, CREATE_ENTITY_PROFILE, EXTCA_INPUTS))
                .addFlow(loginLogoutRestFlows.logout())
                .alwaysRun()
                .build();
        startScenario(beforeClass);
        LOGGER.info("\n----<< BEFORE CLASS Generate Enrollment Info - END >>----- \n");
    }

    @Test(enabled = true, priority = 1, groups = {"Functional", "NSS" })
    @TestSuite
    public void generateEnrollmentInfoWithExternalCA() {
        fetchSpecificNodeFromCsv(SINGLE_NODE_DATA_SOURCE, context.dataSource(ADDED_NODES), isCbpoiNodeIpv4);
        doParallelNodesBase(INPUT_DATASOURCE, "Generate_Enrollment_Information_with_ExtCA",
                context.dataSource(GENERATE_ENROLLMENT_INFO_WITH_EXTCA), context.dataSource(SINGLE_NODE_DATA_SOURCE), userListPositive);
        mergeDataSourcesTwo(SUPPORT_DATASOURCE, EXTCA_INPUTS, DEFAULT_ENROLLMENT_MODE_VALUE);
        runScenarioGenerateEnrolmentInfo_with_ExtCA(GENERATE_ENROLLMENT_INFO_SCENARIO_WITH_EXTCA + " - Shared-Cnf node");
        context.removeDataSource(SINGLE_NODE_DATA_SOURCE);
        context.removeDataSource(INPUT_DATASOURCE);
        fetchSpecificNodeFromCsv(SINGLE_NODE_DATA_SOURCE, context.dataSource(ADDED_NODES), isComEcimNode);
        doParallelNodesBase(INPUT_DATASOURCE, "Generate_Enrollment_Information_with_ExtCA",
                context.dataSource(GENERATE_ENROLLMENT_INFO_WITH_EXTCA), context.dataSource(SINGLE_NODE_DATA_SOURCE), userListPositive);
        runScenarioGenerateEnrolmentInfo_with_ExtCA(GENERATE_ENROLLMENT_INFO_SCENARIO_WITH_EXTCA + " - ECIM Radio node");
    }

    @AfterMethod(groups = { "Functional", "NSS" }, alwaysRun = true)
    public void afterMethod(Method method) {
        if (method.getName().startsWith("generateEnrollmentInfoWithExternalCA")) {
            LOGGER.info("\n\n-----<< After Scenario [generateEnrollmentInfoWithExternalCA] - Deleting External CA Data from ENM - Starting >>-----");
            final TestScenario afterMethodScenario = scenario("Delete ExtCA Data")
                    .addFlow(loginlogoutFlow.loginDefaultUser())
                    .addFlow(generateEnrollmentInfoFlows.deleteOamEndEntityBuilder(DELETE_END_ENTITY).withDataSources(dataSource(ADDED_NODES)))
                    .addFlow(pkiCommandFlow.deleteExtCaDataBuilder(EXTCA_INPUTS))
                    .addFlow(loginlogoutFlow.logout()).alwaysRun().build();
            final TestScenarioRunner runner = SetupAndTearDownUtil.getScenarioRunner();
            runner.start(afterMethodScenario);
            LOGGER.info("\n-----<< After Scenario [generateEnrollmentInfoWithExternalCA] - Deleting External CA Data from ENM  - Finished >>-----\n\n");
        }
    }

    @Test(enabled = true, priority = 2, groups = { "Functional", "NSS" })
    @TestSuite
    public void generateEnrollmentInfoWithOtpParams() {
        context.removeDataSource(SINGLE_NODE_DATA_SOURCE);
        fetchSpecificNodeFromCsv(SINGLE_NODE_DATA_SOURCE, context.dataSource(ADDED_NODES), isCbpoiNodeIpv4);
        Iterable<DataRecord> testFilteredByPredicate;
        testFilteredByPredicate = Iterables.filter(context.dataSource(GENERATE_ENROLLMENT_INFO_WITH_OTP_PARAMS), PredicateUtil.contextFilter("1"));
        doParallelNodesBase(INPUT_DATASOURCE, "Generate_Enrollment_Information_without_ExtCA_providing_OTP_parameters",
                testFilteredByPredicate, context.dataSource(SINGLE_NODE_DATA_SOURCE), userListPositive);
        ScenarioUtility.debugScope(LOGGER, INPUT_DATASOURCE);
        runScenarioGenerateEnrolmentInfo_No_ExtCA(GENERATE_ENROLLMENT_INFO_SCENARIO_NO_EXTCA);
        context.removeDataSource(SINGLE_NODE_DATA_SOURCE);
        context.removeDataSource(INPUT_DATASOURCE);
        fetchSpecificNodeFromCsv(SINGLE_NODE_DATA_SOURCE, context.dataSource(ADDED_NODES), isCbpoiNodeIpv6);
        testFilteredByPredicate = Iterables.filter(context.dataSource(GENERATE_ENROLLMENT_INFO_WITH_OTP_PARAMS), PredicateUtil.contextFilter("2"));
        doParallelNodesBase(INPUT_DATASOURCE, "Generate_Enrollment_Information_without_ExtCA_providing_OTP_parameters",
                testFilteredByPredicate, context.dataSource(SINGLE_NODE_DATA_SOURCE), userListPositive);
        ScenarioUtility.debugScope(LOGGER, INPUT_DATASOURCE);
        runScenarioGenerateEnrolmentInfo_No_ExtCA(GENERATE_ENROLLMENT_INFO_SCENARIO_NO_EXTCA);
    }

    @Test(enabled = true, priority = 3, groups = { "Functional", "NSS" })
    @TestSuite
    public void generateEnrollmentInfoNegative() {
        fetchSpecificNodeFromCsv(SINGLE_NODE_DATA_SOURCE, context.dataSource(ADDED_NODES), isCbpoiNodeIpv4);
        doParallelNodesBase(INPUT_DATASOURCE, "Generate_Enrollment_Information_Negative_Test_wrong_parameters",
                context.dataSource(GENERATE_ENROLLMENT_INFO_WRONG_OTP_PARAMS), context.dataSource(SINGLE_NODE_DATA_SOURCE), userListPositive);
        ScenarioUtility.debugScope(LOGGER, INPUT_DATASOURCE);
        final TestScenario scenario = dataDrivenScenario("Generate Enrollment Info Negative Test Scenario - wrong OTP parameters")
                .addFlow(loginLogoutRestFlows.loginBuilder())
                .addFlow(generateEnrollmentInfoFlows.generateEnrollmentInfoNegativeFlowBasic())
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(AVAILABLE_USERS).bindTo(ADDED_NODES).bindTo(NODES_TO_ADD))
                .doParallel(vUser).build();
        final TestScenarioRunner runner = SetupAndTearDownUtil.getScenarioRunner();
        runner.start(scenario);
    }

    private void runScenarioGenerateEnrolmentInfo_No_ExtCA(final String scenarioName) {
        final TestScenario scenario = dataDrivenScenario(scenarioName)
                .addFlow(utilityFlows.loginFunctionalUser("1"))
                .addFlow(generateEnrollmentInfoFlows.generateEnrollmentInfoFlow("Generate Enrollment Info without ExtCa Flow", SUPPORT_DATASOURCE))
                .addFlow(generateEnrollmentInfoFlows.getAndVerifyOamEndEntity(DEFAULT_OTP_PARAMETERS_VALUE))
                .addFlow(loginLogoutRestFlows.logoutBuilder()).alwaysRun()
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(ADDED_NODES))
                .build();
        executeScenario(scenario);
    }

    private void runScenarioGenerateEnrolmentInfo_with_ExtCA(final String scenarioName) {
        final TestScenario scenario = dataDrivenScenario(scenarioName)
                .addFlow(utilityFlows.loginFunctionalUser("1"))
                .addFlow(generateEnrollmentInfoFlows.generateEnrollmentInfoFlow("Generate Enrollment Info with ExtCa Flow", SUPPORT_DATASOURCE))
                .addFlow(generateEnrollmentInfoFlows.getAndVerifyOamEndEntity(DEFAULT_OTP_PARAMETERS_VALUE))
                .addFlow(loginlogoutFlow.logout())
                .withScenarioDataSources(dataSource(INPUT_DATASOURCE).bindTo(ADDED_NODES))
                .build();
        executeScenario(scenario);
    }
}
