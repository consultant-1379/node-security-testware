/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ericsson.nms.security.nscs.scenario;

import static com.ericsson.nms.security.nscs.constants.CsvDataSourceConstants.USERS_TESTS_CSV;
import static com.ericsson.nms.security.nscs.constants.UserRoleValues.ROLE_CREDENTIAL;
import static com.ericsson.nms.security.nscs.constants.UserRoleValues.ROLE_FIELD_TECHNICIAN;
import static com.ericsson.nms.security.nscs.constants.UserRoleValues.ROLE_GET_CREDENTIALS;
import static com.ericsson.nms.security.nscs.constants.UserRoleValues.ROLE_GET_SNMP_CREDENTIALS;
import static com.ericsson.nms.security.nscs.constants.UserRoleValues.ROLE_IPSEC;
import static com.ericsson.nms.security.nscs.constants.UserRoleValues.ROLE_NODESECURITY_ADMIN;
import static com.ericsson.nms.security.nscs.constants.UserRoleValues.ROLE_OAM;
import static com.ericsson.nms.security.nscs.constants.UserRoleValues.ROLE_OPERATOR;
import static com.ericsson.nms.security.nscs.constants.UserRoleValues.ROLE_SECURITY_ADMIN;
import static com.ericsson.nms.security.nscs.constants.UserRoleValues.ROLE_SSH_KEY;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.AVAILABLE_USERS;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.ROLE_TO_CREATE;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.ROLE_TO_DELETE;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.USERS_TO_CREATE;
import static com.ericsson.oss.testware.enmbase.data.CommonDataSources.USERS_TO_DELETE;

import java.util.Arrays;

import javax.inject.Inject;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testng.annotations.AfterSuite;
import org.testng.annotations.BeforeSuite;
import org.testng.annotations.Parameters;

import com.ericsson.cifwk.taf.TafTestBase;
import com.ericsson.cifwk.taf.TestContext;
import com.ericsson.nms.security.nscs.constants.SecurityConstants;
import com.ericsson.nms.security.nscs.utils.UtilContext;

/**
 * Setup nodes for Role Base scenarios.
 */
@SuppressWarnings({"PMD.LawOfDemeter"})
public class RbacSetupTearDownScenario extends TafTestBase {

    private static final Logger log = LoggerFactory.getLogger(RbacSetupTearDownScenario.class);

    @Inject
    private BaseScenario baseScenario;

    @Inject
    private TestContext context;

    /**
     * Setup the nodes.
     *
     * @param dataprovidername dataprovider from datadriven.properties file.
     */
    @Parameters({"dataprovidername", "nscsprofiles"})
    @BeforeSuite(alwaysRun = true, groups = {"NSS"})
    public void onBeforeSuite(final String dataprovidername, final String suiteNscsProfiles) {
        UtilContext.makeUtilContext().setProfile(suiteNscsProfiles);
        baseScenario.beforeSuiteForRbac(dataprovidername);
        baseScenario.loadCustomRolesToCreate(
                Arrays.asList(ROLE_CREDENTIAL, ROLE_SSH_KEY, ROLE_OAM, ROLE_IPSEC, ROLE_GET_CREDENTIALS, ROLE_GET_SNMP_CREDENTIALS));
        baseScenario.loadDefaultUsersToCreate(
                Arrays.asList(ROLE_NODESECURITY_ADMIN, ROLE_CREDENTIAL, ROLE_SSH_KEY,
                        ROLE_OAM, ROLE_IPSEC, ROLE_GET_CREDENTIALS, ROLE_GET_SNMP_CREDENTIALS,
                        ROLE_OPERATOR, ROLE_SECURITY_ADMIN, ROLE_FIELD_TECHNICIAN),
                USERS_TESTS_CSV);
        baseScenario.cleanSetupEnvironment();
        baseScenario.createUserRoleScenario();
    }

    /**
     * Tear down the nodes.
     */
    @AfterSuite(alwaysRun = true)
    public void onAfterSuite() {
        log.info("********  tearDownEnvironment [{}] ********", "NodeSecurity_Rbac");
        if (!SecurityConstants.PROFILE_SETUP.equals(UtilContext.makeUtilContext().readSuiteProfile())) {
            emptyUsersToCreate();
            emptyRoleToCreate();
            baseScenario.createTeardown();
        }
    }

    private void emptyUsersToCreate() {
        log.info("removing datasources USERS_TO_CREATE and USERS_TO_DELETE");
        context.removeDataSource(USERS_TO_CREATE);
        context.removeDataSource(USERS_TO_DELETE);
        context.removeDataSource(AVAILABLE_USERS);
    }

    private void emptyRoleToCreate() {
        log.info("removing datasources ROLE_TO_CREATE and ROLE_TO_DELETE");
        context.removeDataSource(ROLE_TO_CREATE);
        context.removeDataSource(ROLE_TO_DELETE);
    }
}
