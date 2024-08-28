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
public class SetupAndTeardownScenarioLdap_REST extends TafTestBase {

    public static final String LDAP_REST_TEST_DATASOURCE ="LdapRestTestDataSource";
    public static final String NOT_EXISTENT_NODE = "notExistentNodeDataSource";
    public static final String nodeTypes = "RadioNode,Shared-CNF";
    private static final Logger LOGGER = LoggerFactory.getLogger(SetupAndTeardownScenarioLdap_REST.class);
    private static final String PATH = "data" + File.separator + "feature" + File.separator + "ldapREST" + File.separator;

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
        return Arrays.asList(ROLE_LDAP_REST);
    }
    public static List<String> negativeCustomRolesList()  {
        return Arrays.asList(ROLE_NODESECURITY_OPERATOR);
    }


    @AfterSuite(alwaysRun = true)
    public void onAfterSuite() {
        scenarioUtility.tearDownScenario("Ldap REST - tearDown Scenario", true);
    }

    private void beforeSuite() {
        LOGGER.info("\n\n -----<< Ldap REST - Setup Scenario - Starting >>-----");

        context.addDataSource(USERS_TO_CREATE, fromCsv(PATH + "usersToCreate.csv"));
        context.addDataSource(USERS_TO_DELETE, fromCsv(PATH + "usersToCreate.csv"));
        context.addDataSource(ROLE_TO_CREATE ,fromCsv(PATH + "Role_To_Create.csv"));
        context.addDataSource(ROLE_TO_DELETE ,fromCsv(PATH + "Role_To_Create.csv"));
        context.addDataSource(NODES_TO_ADD, shared(fromCsv(PATH + "LdapREST_NodeToAdd.csv")));

        final TestDataSource<DataRecord> generateEnrollmentInfoTest = fromCsv(PATH + "Ldap_REST_Test.csv");
        context.addDataSource(LDAP_REST_TEST_DATASOURCE, generateEnrollmentInfoTest);

        final TestDataSource<DataRecord> notExistentNode = fromCsv(PATH + "NotExistentNode.csv");
        context.addDataSource(NOT_EXISTENT_NODE, notExistentNode);

        ScenarioUtility.debugScope(LOGGER, USERS_TO_CREATE);
        ScenarioUtility.debugScope(LOGGER, USERS_TO_DELETE);
        ScenarioUtility.debugScope(LOGGER, ROLE_TO_CREATE);
        ScenarioUtility.debugScope(LOGGER, ROLE_TO_DELETE);
        ScenarioUtility.debugScope(LOGGER, NODES_TO_ADD);
        ScenarioUtility.debugScope(LOGGER, LDAP_REST_TEST_DATASOURCE);

        scenarioUtility.setupNodes("Setup Scenario Ldap REST - create nodes", true);
        scenarioUtility.setupRoles("Setup Scenario Ldap REST - create Roles");
        scenarioUtility.setupUsers("Setup Scenario Ldap REST - create ENM users");
        LOGGER.info("\n -----<< Ldap REST Setup Scenario - End >>-----\n\n");
    }
}