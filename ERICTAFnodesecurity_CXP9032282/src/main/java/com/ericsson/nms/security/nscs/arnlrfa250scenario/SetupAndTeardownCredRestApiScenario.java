
package com.ericsson.nms.security.nscs.arnlrfa250scenario;

import static com.ericsson.cifwk.taf.datasource.TafDataSources.fromCsv;
import static com.ericsson.cifwk.taf.datasource.TafDataSources.shared;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.NODES_TO_ADD;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.ROLE_TO_CLEAN_UP;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.ROLE_TO_CREATE;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.USERS_TO_CREATE;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.USERS_TO_DELETE;
import static com.ericsson.oss.testware.nodesecurity.steps.CredentialServiceNbiTestStep.CRED_NBI_DATASOURCE;
import static com.ericsson.oss.testware.nodesecurity.steps.CredentialServiceRestApiTestStep.CRED_API_REST_DATASOURCE;

import java.io.File;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.inject.Inject;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testng.annotations.AfterSuite;
import org.testng.annotations.BeforeSuite;
import org.testng.annotations.Parameters;

import com.ericsson.cifwk.taf.TafTestBase;
import com.ericsson.cifwk.taf.TestContext;
import com.ericsson.cifwk.taf.datasource.DataRecord;
import com.ericsson.cifwk.taf.datasource.TafDataSources;
import com.ericsson.cifwk.taf.datasource.TestDataSource;
import com.ericsson.cifwk.taf.datasource.TestDataSourceFactory;
import com.ericsson.nms.security.nscs.utils.UtilContext;
import com.ericsson.nms.security.nscs.utils.Utils;

@SuppressWarnings({ "PMD.LawOfDemeter", "PMD.ExcessiveImports", "PMD.AvoidCatchingGenericException" })
public class SetupAndTeardownCredRestApiScenario extends TafTestBase {

    private static final Logger LOGGER = LoggerFactory.getLogger(SetupAndTeardownCredRestApiScenario.class);
    private static final String SOURCE_PATH = "data" + File.separator + "feature" + File.separator + "credentialsAPI" + File.separator;

    @Inject
    private TestContext context;

    @Inject
    private IscfAndCredApiScenarioUtility iscfAndCredApiScenarioUtility;


    @Parameters({ "nscsprofiles" })
    @BeforeSuite(alwaysRun = true)
    public void onBeforeSuite(final String suiteNscsProfiles) {
        try {
            beforeSuite(suiteNscsProfiles);
        } catch (final Exception e) {
            LOGGER.error(e.getMessage(), e);
        }
    }

    @AfterSuite(alwaysRun = true)
    public void onAfterSuite() {
        iscfAndCredApiScenarioUtility.tearDownScenario("Credentials REST Api - TearDownScenario", false );
    }

    private void beforeSuite(final String suiteNscsProfiles) {
        LOGGER.info("\n\n **** Credentials REST Api Setup Scenario - Starting ****\n");
        UtilContext.makeUtilContext().setProfile(suiteNscsProfiles);
        final String profile = UtilContext.makeUtilContext().readSuiteProfile();
        LOGGER.info("Loading profile [{}] and sourcePath [{}] ", profile, SOURCE_PATH);
        context.addDataSource(ROLE_TO_CREATE, TafDataSources.fromCsv(SOURCE_PATH + "rbac/RoleDefinition.csv"));
        context.addDataSource(ROLE_TO_CLEAN_UP, TafDataSources.fromCsv(SOURCE_PATH + "rbac/RoleDefinition.csv"));
        context.addDataSource(USERS_TO_CREATE, fromCsv(SOURCE_PATH + "usersToCreateCredentialsApi.csv"));
        context.addDataSource(USERS_TO_DELETE, fromCsv(SOURCE_PATH + "usersToCreateCredentialsApi.csv"));
        context.addDataSource(NODES_TO_ADD, shared(fromCsv(SOURCE_PATH + "CredApi_NodeToAdd.csv")));
        ScenarioUtility.debugScope(LOGGER, USERS_TO_CREATE);
        ScenarioUtility.debugScope(LOGGER, USERS_TO_DELETE);
        ScenarioUtility.debugScope(LOGGER, NODES_TO_ADD);
        context.addDataSource(CRED_API_REST_DATASOURCE, prepareSpecificDataSourceFromCsvFile("CredentialServiceApiPositiveTests.csv", "PositiveExpectedResponse.csv"));
        context.addDataSource(CRED_NBI_DATASOURCE,
                fromCsv("CredentialServiceNbiPositiveTests.csv"));
        ScenarioUtility.debugScope(LOGGER, CRED_API_REST_DATASOURCE);
        iscfAndCredApiScenarioUtility.setupRoles("Credentials REST Setup Scenario - create ENM custome roles");
        iscfAndCredApiScenarioUtility.setupNodes("Credentials REST Setup Scenario - create nodes", false);
        iscfAndCredApiScenarioUtility.setupUsers("Credentials REST Setup Scenario - create ENM users");
        LOGGER.info("\n **** Credentials REST Setup Scenario - End ****\n");
    }

    private TestDataSource<DataRecord> prepareSpecificDataSourceFromCsvFile(final String specificCsvFile, final String otherCsvFile) {
        final String iteratorDS = "iteratorDataSource";
        final String otherDS = "otherDataSource";
        context.addDataSource(iteratorDS, fromCsv(SOURCE_PATH + specificCsvFile));
        context.addDataSource(otherDS, fromCsv(SOURCE_PATH + otherCsvFile));
        final List<Map<String, Object>> rows = Utils.copyDataSource(context.dataSource(iteratorDS), iteratorDS);
        final List<Map<String, Object>> rows1 = Utils.copyDataSource(context.dataSource(otherDS), otherDS);
        final List<Map<String, Object>> data = new ArrayList<>();
        for (final Map<String, Object> row : rows) {
            final Map<String, Object> map = new HashMap<>();
            map.putAll(row);
            map.putAll(rows1.get(0));
            data.add(map);
        }
        return TestDataSourceFactory.createDataSource(data);
    }

    public void seUptWrongUserRoleDataSources() {
        removeCredApiDataSource();
        context.addDataSource(CRED_API_REST_DATASOURCE, prepareSpecificDataSourceFromCsvFile("CredentialServiceApiPositiveTests.csv", "WrongUserRoleExpectedResponse.csv"));
        ScenarioUtility.debugScope(LOGGER, CRED_API_REST_DATASOURCE);
    }

    private void removeCredApiDataSource() {
        context.removeDataSource(CRED_API_REST_DATASOURCE);
    }

    public void seUptWrongUserRoleNbiDataSources() {
        removeCredNbiDataSource();
        context.addDataSource(CRED_NBI_DATASOURCE,
                prepareSpecificDataSourceFromCsvFile("CredentialServiceApiPositiveTests.csv", "WrongUserRoleNbiExpectedResponse.csv"));
        ScenarioUtility.debugScope(LOGGER, CRED_NBI_DATASOURCE);
    }

    private void removeCredNbiDataSource() {
        context.removeDataSource(CRED_NBI_DATASOURCE);
    }

    public void setUpNegativeTestsDataSources() {
        removeCredNbiDataSource();
        context.addDataSource(CRED_NBI_DATASOURCE, fromCsv("CredentialServiceNbiNegativeTests.csv"));
        ScenarioUtility.debugScope(LOGGER, CRED_NBI_DATASOURCE);
    }

}
