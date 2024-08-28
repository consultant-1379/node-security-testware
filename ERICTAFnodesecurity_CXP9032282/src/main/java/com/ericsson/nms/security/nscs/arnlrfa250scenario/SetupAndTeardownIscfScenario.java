package com.ericsson.nms.security.nscs.arnlrfa250scenario;

import com.ericsson.cifwk.taf.TafTestBase;
import com.ericsson.cifwk.taf.TestContext;
import com.ericsson.cifwk.taf.datasource.DataRecord;
import com.ericsson.cifwk.taf.datasource.TafDataSources;
import com.ericsson.cifwk.taf.datasource.TestDataSource;
import com.ericsson.cifwk.taf.datasource.TestDataSourceFactory;
import com.ericsson.nms.security.nscs.utils.UtilContext;
import com.ericsson.nms.security.nscs.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testng.annotations.AfterSuite;
import org.testng.annotations.BeforeSuite;
import org.testng.annotations.Parameters;

import javax.inject.Inject;
import java.io.File;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.ericsson.cifwk.taf.datasource.TafDataSources.fromCsv;
import static com.ericsson.cifwk.taf.datasource.TafDataSources.shared;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.NODES_TO_ADD;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.USERS_TO_CREATE;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.USERS_TO_DELETE;
import static com.ericsson.oss.testware.nodesecurity.steps.IscfRestTestStep.END_ENTITY_DATASOURCES;
import static com.ericsson.oss.testware.nodesecurity.steps.IscfRestTestStep.ISCF_COMBO_CPP_DATASOURCES;
import static com.ericsson.oss.testware.nodesecurity.steps.IscfRestTestStep.ISCF_IPSEC_CPP_DATASOURCES;
import static com.ericsson.oss.testware.nodesecurity.steps.IscfRestTestStep.ISCF_OAM_CPP_DATASOURCES;
import static com.ericsson.oss.testware.nodesecurity.steps.IscfRestTestStep.ISCF_SEC_DATA_ECIM_DATASOURCES;

@SuppressWarnings({"PMD.LawOfDemeter", "PMD.ExcessiveImports", "PMD.AvoidCatchingGenericException"})
public class SetupAndTeardownIscfScenario extends TafTestBase {

    private static final Logger LOGGER = LoggerFactory.getLogger(SetupAndTeardownIscfScenario.class);

    private static final String ISCF_SOURCE_PATH = "data" + File.separator + "feature" + File.separator +"iscf" + File.separator;
    private static final String ISCF_IPSEC_CPP_CSV = "Iscf_Ipsec_CPP.csv";
    private static final String ISCF_OAM_CPP_CSV = "Iscf_OAM_CPP.csv";
    private static final String ISCF_COMBO_CPP_CSV = "Iscf_Combo_CPP.csv";
    private static final String ISCF_SEC_DATA_ECIM_CSV = "Iscf_Sec_Data_ECIM.csv";
    private static final String ISCF_POSITIVE_TEST_EXPECTED_RESPONSE_CSV = "Iscf_PositiveTest_expectedResponse.csv";
    private static final String ISCF_SBJECT_ALT_NAME_CSV = "Iscf_subjectAltName_format_value.csv";

    private static final TestDataSource<DataRecord> iscfIpsecCpp = fromCsv(ISCF_SOURCE_PATH + ISCF_IPSEC_CPP_CSV);
    private static final TestDataSource<DataRecord> iscfComboCpp = fromCsv(ISCF_SOURCE_PATH + ISCF_COMBO_CPP_CSV);
    private static final TestDataSource<DataRecord> iscfSecDataEcim = fromCsv(ISCF_SOURCE_PATH + ISCF_SEC_DATA_ECIM_CSV);
    private static final TestDataSource<DataRecord> iscfOamCpp = fromCsv(ISCF_SOURCE_PATH + ISCF_OAM_CPP_CSV);

    @Inject
    private TestContext context;

    @Inject
    private IscfAndCredApiScenarioUtility iscfAndCredApiScenarioUtility;

    @Parameters({ "nscsprofiles" })
    @BeforeSuite(alwaysRun = true)
    public void onBeforeSuiteIscf(final String suiteNscsProfiles) {
        try {
            beforeSuiteIscf(suiteNscsProfiles);
        } catch (final Exception e) {
            LOGGER.error(e.getMessage(), e);
        }
    }

    @AfterSuite(alwaysRun = true)
    public void onAfterSuiteIscf() {
        iscfAndCredApiScenarioUtility.tearDownScenario("Iscf tearDownScenario", false);
    }

    private void beforeSuiteIscf(final String suiteNscsProfiles) {
        LOGGER.info("\n\n **** Iscf Setup Scenario - Starting ****\n");
        
        context.addDataSource(USERS_TO_CREATE, fromCsv(ISCF_SOURCE_PATH + "usersToCreateIscf.csv"));
        context.addDataSource(USERS_TO_DELETE, fromCsv(ISCF_SOURCE_PATH + "usersToCreateIscf.csv"));
        context.addDataSource(NODES_TO_ADD, shared(fromCsv(ISCF_SOURCE_PATH + "Iscf_NodeToAdd.csv")));

        ScenarioUtility.debugScope(LOGGER, USERS_TO_CREATE);
        ScenarioUtility.debugScope(LOGGER, USERS_TO_DELETE);
        ScenarioUtility.debugScope(LOGGER, NODES_TO_ADD);

        final TestDataSource<DataRecord> iscfPositiveResponse = fromCsv(ISCF_POSITIVE_TEST_EXPECTED_RESPONSE_CSV);

        context.addDataSource(ISCF_OAM_CPP_DATASOURCES, TafDataSources.merge(iscfPositiveResponse ,iscfOamCpp));
        context.addDataSource(ISCF_IPSEC_CPP_DATASOURCES, iscfPrepareSpecificDataSourceFromCsvFile(ISCF_IPSEC_CPP_CSV));
        context.addDataSource(ISCF_COMBO_CPP_DATASOURCES, iscfPrepareSpecificDataSourceFromCsvFile(ISCF_COMBO_CPP_CSV));
        context.addDataSource(ISCF_SEC_DATA_ECIM_DATASOURCES, iscfPrepareSpecificDataSourceFromCsvFile(ISCF_SEC_DATA_ECIM_CSV));
        dumpIscfDataSource();
        iscfAndCredApiScenarioUtility.setupNodes("Setup Scenario Iscf - create nodes", false);
        iscfAndCredApiScenarioUtility.setupUsers("Setup Scenario Iscf - create ENM users");
        LOGGER.info("\n **** Iscf Setup Scenario - End ****\n");
    }

    private TestDataSource<DataRecord> iscfPrepareSpecificDataSourceFromCsvFile(final String IscfSpecificCsvFile) {
        final String iteratorDS = "iteratorDataSource";
        final String specificIscfDS = "specificIscfDataSource";
        final String expectedMessageDS = "expectedMessageDataSource";

        context.addDataSource(iteratorDS, fromCsv(ISCF_SOURCE_PATH + ISCF_SBJECT_ALT_NAME_CSV));
        context.addDataSource(specificIscfDS, fromCsv(ISCF_SOURCE_PATH + IscfSpecificCsvFile));
        context.addDataSource(expectedMessageDS, fromCsv(ISCF_SOURCE_PATH + ISCF_POSITIVE_TEST_EXPECTED_RESPONSE_CSV));
        final List<Map<String, Object>> rows = Utils.copyDataSource(context.dataSource(iteratorDS), iteratorDS);
        final List<Map<String, Object>> rows1 = Utils.copyDataSource(context.dataSource(specificIscfDS), specificIscfDS);
        final List<Map<String, Object>> rows2 = Utils.copyDataSource(context.dataSource(expectedMessageDS), expectedMessageDS);
        final List<Map<String, Object>> data = new ArrayList<>();
        for (final Map<String, Object> row : rows) {
            final Map<String, Object> map = new HashMap<>();
            map.putAll(row);
            map.putAll(rows1.get(0));
            map.putAll(rows2.get(0));
            data.add(map);
        }
        return TestDataSourceFactory.createDataSource(data);
    }

    public void setUpNegativeTestsDataSources() {
        removeIscfDataSource();
        context.addDataSource(ISCF_OAM_CPP_DATASOURCES, fromCsv(ISCF_SOURCE_PATH + "Iscf_Negative_OAM_CPP.csv"));
        context.addDataSource(ISCF_IPSEC_CPP_DATASOURCES, fromCsv(ISCF_SOURCE_PATH + "Iscf_Negative_IPSEC_CPP.csv"));
        context.addDataSource(ISCF_COMBO_CPP_DATASOURCES, fromCsv(ISCF_SOURCE_PATH + "Iscf_Negative_Combo_CPP.csv"));
        context.addDataSource(ISCF_SEC_DATA_ECIM_DATASOURCES, fromCsv(ISCF_SOURCE_PATH + "Iscf_Sec_Data_ECIM_Negative.csv"));
        dumpIscfDataSource();
    }

    public void seUptWrongUserRoleDataSources() {
        removeIscfDataSource();
        final TestDataSource<DataRecord> iscfWrongUserRoleResponse = fromCsv(ISCF_SOURCE_PATH + "Iscf_Wrong_User_Role.csv");
        context.addDataSource(ISCF_OAM_CPP_DATASOURCES, TafDataSources.merge(iscfWrongUserRoleResponse, iscfOamCpp));
        context.addDataSource(ISCF_IPSEC_CPP_DATASOURCES, TafDataSources.merge(iscfWrongUserRoleResponse, iscfIpsecCpp));
        context.addDataSource(ISCF_COMBO_CPP_DATASOURCES, TafDataSources.merge(iscfWrongUserRoleResponse, iscfComboCpp));
        context.addDataSource(ISCF_SEC_DATA_ECIM_DATASOURCES, TafDataSources.merge(iscfWrongUserRoleResponse, iscfSecDataEcim));
        context.addDataSource(END_ENTITY_DATASOURCES, TafDataSources.merge(iscfWrongUserRoleResponse, iscfOamCpp));
        dumpIscfDataSource();
    }

    private void dumpIscfDataSource() {
        ScenarioUtility.debugScope(LOGGER, ISCF_OAM_CPP_DATASOURCES);
        ScenarioUtility.debugScope(LOGGER, ISCF_IPSEC_CPP_DATASOURCES);
        ScenarioUtility.debugScope(LOGGER, ISCF_COMBO_CPP_DATASOURCES);
        ScenarioUtility.debugScope(LOGGER, ISCF_SEC_DATA_ECIM_DATASOURCES);
    }

    private void removeIscfDataSource() {
        context.removeDataSource(ISCF_OAM_CPP_DATASOURCES);
        context.removeDataSource(ISCF_IPSEC_CPP_DATASOURCES);
        context.removeDataSource(ISCF_COMBO_CPP_DATASOURCES);
        context.removeDataSource(ISCF_SEC_DATA_ECIM_DATASOURCES);
    }
}
