package com.ericsson.nms.security.nscs.arnlrfa250scenario;

import com.ericsson.cifwk.taf.TafTestBase;
import com.ericsson.cifwk.taf.TestContext;
import com.ericsson.cifwk.taf.datasource.DataRecord;
import com.ericsson.cifwk.taf.datasource.TestDataSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testng.annotations.AfterSuite;
import org.testng.annotations.BeforeSuite;

import javax.inject.Inject;
import java.io.File;
import java.util.Arrays;
import java.util.List;

import static com.ericsson.cifwk.taf.datasource.TafDataSources.fromCsv;
import static com.ericsson.cifwk.taf.datasource.TafDataSources.shared;
import static com.ericsson.nms.security.nscs.constants.UserRoleValues.*;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.*;

@SuppressWarnings({"PMD.LawOfDemeter", "PMD.ExcessiveImports", "PMD.AvoidCatchingGenericException"})
public class SetupAndTeardownGenerateEnrollmentInfo_REST extends TafTestBase {

    public static final String GENERATE_ENROLLMENT_INFO_TEST_DATASOURCE ="GenerateEnrollmentInfoRestDataSource";
    public static final String DEFAULT_OTP_PARAMETERS_NAME = "DefaultOtpParametersNameDataSource";
    public static final String DEFAULT_ENROLLMENT_MODE_VALUE = "DefaultEnrollmentModeValueDataSource";
    public static final String DELETE_END_ENTITY = "DeleteEndEntityDataSource";
    public static final String NOT_EXISTENT_NODE = "notExistentNodeDataSource";
    public static final String nodeTypes = "RadioNode,Shared-CNF";
    private static final Logger LOGGER = LoggerFactory.getLogger(SetupAndTeardownGenerateEnrollmentInfo_REST.class);
    private static final String BASE_PATH = "data" + File.separator + "feature" + File.separator;
    private static final String DATA_PATH_CURRENT = BASE_PATH + "generateEnrollmentInfoREST" + File.separator;
    private static final String DATA_PATH_EXTERNAL = BASE_PATH + "generateEnrollmentInfo" + File.separator;

    @Inject
    private TestContext context;

    @Inject
    private IscfAndCredApiScenarioUtility scenarioUtility;

    @BeforeSuite(alwaysRun = true)
    public void onBeforeSuite() {
        try {
            beforeSuite();
        } catch (final Exception e) {
            LOGGER.error(e.getMessage(), e);
        }
    }

    public static List<String> positiveCustomRolesList()  {
        return Arrays.asList(ROLE_GENERATE_ENROLLMENT_INFO_REST);
    }
    public static List<String> negativeCustomRolesList()  {
        return Arrays.asList(ROLE_NODESECURITY_OPERATOR);
    }


    @AfterSuite(alwaysRun = true)
    public void onAfterSuite() {
        scenarioUtility.tearDownScenario("Generate Enrollment Info REST - tearDownScenario", true);
    }

    private void beforeSuite() {
        LOGGER.info("\n\n -----<< Generate Enrollment Info REST - Setup Scenario - Starting >>-----");

        context.addDataSource(USERS_TO_CREATE, fromCsv(DATA_PATH_CURRENT + "usersToCreate.csv"));
        context.addDataSource(USERS_TO_DELETE, fromCsv(DATA_PATH_CURRENT + "usersToCreate.csv"));
        context.addDataSource(ROLE_TO_CREATE ,fromCsv(DATA_PATH_CURRENT + "Role_To_Create.csv"));
        context.addDataSource(ROLE_TO_DELETE ,fromCsv(DATA_PATH_CURRENT + "Role_To_Create.csv"));
        context.addDataSource(NODES_TO_ADD, shared(fromCsv(DATA_PATH_CURRENT + "GenerateEnrollmentInfoREST_NodeToAdd.csv")));

        final TestDataSource<DataRecord> generateEnrollmentInfoTest = fromCsv(DATA_PATH_CURRENT + "GenerateEnrollmentInfo_REST_Test.csv");
        context.addDataSource(GENERATE_ENROLLMENT_INFO_TEST_DATASOURCE, generateEnrollmentInfoTest);

        final TestDataSource<DataRecord> defaultOtpParameterNames = fromCsv(DATA_PATH_EXTERNAL + "OTP_defaultData.csv");
        context.addDataSource(DEFAULT_OTP_PARAMETERS_NAME, defaultOtpParameterNames);

        final TestDataSource<DataRecord> deleteEntityProfile = fromCsv(DATA_PATH_EXTERNAL + "DeleteEndEntityExpectedMessagges.csv");
        context.addDataSource(DELETE_END_ENTITY, deleteEntityProfile);

        final TestDataSource<DataRecord> notExistentNode = fromCsv(DATA_PATH_CURRENT + "NotExistentNode.csv");
        context.addDataSource(NOT_EXISTENT_NODE, notExistentNode);

        ScenarioUtility.debugScope(LOGGER, USERS_TO_CREATE);
        ScenarioUtility.debugScope(LOGGER, USERS_TO_DELETE);
        ScenarioUtility.debugScope(LOGGER, ROLE_TO_CREATE);
        ScenarioUtility.debugScope(LOGGER, ROLE_TO_DELETE);
        ScenarioUtility.debugScope(LOGGER, NODES_TO_ADD);
        ScenarioUtility.debugScope(LOGGER, GENERATE_ENROLLMENT_INFO_TEST_DATASOURCE);
        ScenarioUtility.debugScope(LOGGER, DEFAULT_OTP_PARAMETERS_NAME);
        ScenarioUtility.debugScope(LOGGER, DELETE_END_ENTITY);

        scenarioUtility.setupNodes("Setup Scenario Generate EnrollmentInfo REST - create nodes", true);
        scenarioUtility.setupRoles("Setup Scenario Generate EnrollmentInfo REST - create Roles");
        scenarioUtility.setupUsers("Setup Scenario Generate EnrollmentInfo REST - create ENM users");
        LOGGER.info("\n -----<< Generate Enrollment Info REST Setup Scenario - End >>-----\n\n");
    }
}