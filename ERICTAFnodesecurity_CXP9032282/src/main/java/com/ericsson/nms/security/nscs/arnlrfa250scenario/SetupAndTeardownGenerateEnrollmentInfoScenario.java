package com.ericsson.nms.security.nscs.arnlrfa250scenario;

import com.ericsson.cifwk.taf.TafTestBase;
import com.ericsson.cifwk.taf.TestContext;
import com.ericsson.cifwk.taf.data.DataHandler;
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
import static com.ericsson.nms.security.nscs.constants.UserRoleValues.ROLE_NODESECURITY_ADMIN;
import static com.ericsson.nms.security.nscs.constants.UserRoleValues.ROLE_NODESECURITY_OPERATOR;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.*;

@SuppressWarnings({"PMD.LawOfDemeter", "PMD.ExcessiveImports", "PMD.AvoidCatchingGenericException"})
public class SetupAndTeardownGenerateEnrollmentInfoScenario extends TafTestBase {

    public static final String GENERATE_ENROLLMENT_INFO_WITHOUT_EXTCA = "GenerateEnrollmentInfoWithOutExtCaDataSource";
    public static final String GENERATE_ENROLLMENT_INFO_WITH_OTP_PARAMS ="GenerateEnrollmentInfoWithOtpParamsDataSource";
    public static final String GENERATE_ENROLLMENT_INFO_WRONG_OTP_PARAMS = "GenerateEnrollmentInfoWithWrongOtpParamsDataSource";
    public static final String GENERATE_ENROLLMENT_INFO_WITH_EXTCA = "GenerateEnrollmentInfoWithExtCaDataSource";
    public static final String DEFAULT_OTP_PARAMETERS_NAME = "DefaultOtpParametersNameDataSource";
    public static final String DEFAULT_OTP_PARAMETERS_VALUE = "DefaultOtpParametersValueDataSource";
    public static final String DEFAULT_ENROLLMENT_MODE_VALUE = "DefaultEnrollmentModeValueDataSource";
    public static final String EXTCA_DETAILS = "ExtCaDetailsDataSource";
    public static final String CREATE_TRUST_PROFILE = "CreateTrustProfileDataSource";
    public static final String CREATE_ENTITY_PROFILE = "CreateEntityProfileDataSource";
    public static final String DELETE_END_ENTITY = "DeleteEndEntityDataSource";
    public static final String nodeTypes = "RadioNode,Shared-CNF";
    private static final Logger LOGGER = LoggerFactory.getLogger(SetupAndTeardownGenerateEnrollmentInfoScenario.class);
    private static final String DATA_PATH = "data" + File.separator + "feature" + File.separator +"generateEnrollmentInfo" + File.separator;

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
        return Arrays.asList(ROLE_NODESECURITY_ADMIN);
    }

    public static List<String> negativeCustomRolesList()  {
        return Arrays.asList(ROLE_NODESECURITY_OPERATOR);
    }


        @AfterSuite(alwaysRun = true)
    public void onAfterSuite() {
        scenarioUtility.tearDownScenario("Generate Enrollment Info tearDownScenario", false);
    }

    private void beforeSuite() {
        LOGGER.info("\n\n -----<< Generate Enrollment Info Setup Scenario - Starting >>-----");

        context.addDataSource(USERS_TO_CREATE, fromCsv(DATA_PATH + "GenerateEnrollmentInfo_usersToCreate.csv"));
        context.addDataSource(USERS_TO_DELETE, fromCsv(DATA_PATH + "GenerateEnrollmentInfo_usersToCreate.csv"));
        context.addDataSource(NODES_TO_ADD, shared(fromCsv(DATA_PATH + "GenerateEnrollmentInfo_NodeToAdd.csv")));

        final TestDataSource<DataRecord> generateEnrollmentInfoWithExternalCA = fromCsv(DATA_PATH + "GenerateEnrollmentInfoWithExtCa.csv");
        context.addDataSource(GENERATE_ENROLLMENT_INFO_WITH_EXTCA, generateEnrollmentInfoWithExternalCA);

        final TestDataSource<DataRecord> generateEnrollmentInfoWithOtpParams = fromCsv(DATA_PATH + "GenerateEnrollmentInfo_with_OTP.csv");
        context.addDataSource(GENERATE_ENROLLMENT_INFO_WITH_OTP_PARAMS, generateEnrollmentInfoWithOtpParams);

        final TestDataSource<DataRecord> generateEnrollmentInfoWrongOtpParams = fromCsv(DATA_PATH + "GenerateEnrollmentInfo_with_OTP_wrong_params.csv");
        context.addDataSource(GENERATE_ENROLLMENT_INFO_WRONG_OTP_PARAMS, generateEnrollmentInfoWrongOtpParams);

        final TestDataSource<DataRecord> defaultOtpParameterNames = fromCsv(DATA_PATH + "OTP_defaultData.csv");
        context.addDataSource(DEFAULT_OTP_PARAMETERS_NAME, defaultOtpParameterNames);

        final TestDataSource<DataRecord> extCaDetails = fromCsv(DATA_PATH + "ExtCaDetails.csv");
        context.addDataSource(EXTCA_DETAILS, extCaDetails);

        final TestDataSource<DataRecord> createTrustProfile = fromCsv(DATA_PATH + "CreateTrustProfileExtCa.csv");
        context.addDataSource(CREATE_TRUST_PROFILE, createTrustProfile);

        final TestDataSource<DataRecord> createEntityProfile = fromCsv(DATA_PATH + "CreateEntityProfileExtCa.csv");
        context.addDataSource(CREATE_ENTITY_PROFILE, createEntityProfile);

        final TestDataSource<DataRecord> deleteEntityProfile = fromCsv(DATA_PATH + "DeleteEndEntityExpectedMessagges.csv");
        context.addDataSource(DELETE_END_ENTITY, deleteEntityProfile);

        ScenarioUtility.debugScope(LOGGER, USERS_TO_CREATE);
        ScenarioUtility.debugScope(LOGGER, USERS_TO_DELETE);
        ScenarioUtility.debugScope(LOGGER, NODES_TO_ADD);
        ScenarioUtility.debugScope(LOGGER, GENERATE_ENROLLMENT_INFO_WITHOUT_EXTCA);
        ScenarioUtility.debugScope(LOGGER, GENERATE_ENROLLMENT_INFO_WITH_EXTCA);
        ScenarioUtility.debugScope(LOGGER, EXTCA_DETAILS);
        ScenarioUtility.debugScope(LOGGER, CREATE_TRUST_PROFILE);
        ScenarioUtility.debugScope(LOGGER, CREATE_ENTITY_PROFILE);


        scenarioUtility.setupNodes("Setup Scenario Generate EnrollmentInfo - create nodes", false);
        scenarioUtility.setupUsers("Setup Scenario Generate EnrollmentInfo - create ENM users");
        LOGGER.info("\n -----<< Generate EnrollmentInfo Setup Scenario - End >>-----\n\n");
    }
}